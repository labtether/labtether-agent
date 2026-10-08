package agentcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const selfUpdateExitCode = 10

const (
	envNativeWrapperParentPID          = "LABTETHER_PARENT_PID"
	envSelfUpdateTrustedPublicKey      = "LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY"
	envSelfUpdateAllowExternalDownload = "LABTETHER_AUTO_UPDATE_ALLOW_EXTERNAL_DOWNLOAD"
	envSelfUpdateAcceptUnsigned        = "LABTETHER_AUTO_UPDATE_ACCEPT_UNSIGNED"
	maxSelfUpdateBinarySize            = 100 * 1024 * 1024 // 100MB
	maxSelfUpdateMetadataSize          = 1 * 1024 * 1024   // 1MB
	maxSelfUpdateVersionLength         = 128
	maxSelfUpdatePlatformLength        = 128
	maxSelfUpdateURLLength             = 4096
	maxSelfUpdateSignatureLength       = 512
)

const nativeWrapperSelfUpdateMessage = "self-update is managed by the native LabTether app; update the app instead"

const selfUpdateEndpointUnavailableMessage = "auto-update endpoint unavailable"

var (
	agentExitFn       = os.Exit
	executablePathFn  = os.Executable
	selfUpdateTimeout = 30 * time.Second
)

type agentReleaseMetadata struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	URL       string `json:"url"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type selfUpdateOptions struct {
	Force bool
}

func maybeAutoUpdateOnStartup(cfg RuntimeConfig) error {
	if !cfg.AutoUpdateEnabled {
		return nil
	}

	updated, summary, err := checkAndApplySelfUpdate(cfg)
	if err != nil {
		return err
	}
	if !updated {
		return nil
	}

	// Exit non-zero so service managers configured with restart-on-failure
	// immediately relaunch the process with the new binary.
	_ = summary
	agentExitFn(selfUpdateExitCode)
	return fmt.Errorf("agent restart requested after self-update")
}

func checkAndApplySelfUpdate(cfg RuntimeConfig) (bool, string, error) {
	return checkAndApplySelfUpdateWithOptions(cfg, selfUpdateOptions{})
}

func checkAndApplySelfUpdateWithOptions(cfg RuntimeConfig, opts selfUpdateOptions) (bool, string, error) {
	if nativeWrapperSelfUpdateBlocked("", runtime.GOOS) {
		return false, nativeWrapperSelfUpdateMessage, nil
	}

	checkURL := normalizeHTTPSURL(buildAgentReleaseCheckURL(cfg))
	if checkURL == "" {
		return false, selfUpdateEndpointUnavailableMessage, nil
	}
	executablePath, err := executablePathFn()
	if err != nil {
		return false, "", fmt.Errorf("resolve executable path: %w", err)
	}
	if nativeWrapperSelfUpdateBlocked(executablePath, runtime.GOOS) {
		return false, nativeWrapperSelfUpdateMessage, nil
	}

	release, err := fetchReleaseMetadata(cfg, checkURL)
	if err != nil {
		return false, "", fmt.Errorf("fetch release metadata: %w", err)
	}
	if strings.TrimSpace(release.URL) == "" {
		return false, "", fmt.Errorf("release metadata missing download url")
	}
	downloadURL := resolveReleaseDownloadURL(checkURL, release.URL)
	if downloadURL == "" {
		return false, "", fmt.Errorf("release metadata produced an empty download url")
	}
	if err := validateReleaseMetadata(checkURL, downloadURL, release); err != nil {
		return false, "", err
	}
	if err := verifyReleaseMetadataSignature(release, downloadURL); err != nil {
		return false, "", err
	}
	if err := validateReleaseTarget(cfg, release); err != nil {
		return false, "", err
	}

	localSHA, err := fileSHA256(executablePath)
	if err != nil {
		return false, "", fmt.Errorf("hash local executable: %w", err)
	}
	if !opts.Force && release.SHA256 != "" && strings.EqualFold(localSHA, release.SHA256) {
		return false, "agent is already up to date", nil
	}

	binaryBytes, err := downloadReleaseBinary(cfg, checkURL, downloadURL, release.SizeBytes)
	if err != nil {
		return false, "", fmt.Errorf("download release binary: %w", err)
	}
	downloadSHA := sha256Hex(binaryBytes)
	if release.SHA256 != "" && !strings.EqualFold(downloadSHA, release.SHA256) {
		return false, "", fmt.Errorf("download checksum mismatch")
	}

	if err := replaceExecutable(executablePath, binaryBytes); err != nil {
		return false, "", fmt.Errorf("replace executable: %w", err)
	}
	version := strings.TrimSpace(release.Version)
	if version == "" {
		version = downloadSHA[:12]
	}
	if opts.Force {
		return true, fmt.Sprintf("forced update applied to %s", version), nil
	}
	return true, fmt.Sprintf("updated agent binary to %s", version), nil
}

func nativeWrapperSelfUpdateBlocked(executablePath, goos string) bool {
	// Native hosts set this containment boundary for every bundled child. The
	// host owns the signed application as one artifact, so replacing only its
	// nested agent would invalidate the parent signature on both macOS and
	// Windows.
	if strings.TrimSpace(os.Getenv(envNativeWrapperParentPID)) != "" {
		return true
	}

	// Defense in depth for a macOS bundle launched without the expected parent
	// environment. Any executable beneath <name>.app/Contents is still part of
	// that signed application and must be updated with the whole app.
	if !strings.EqualFold(strings.TrimSpace(goos), "darwin") {
		return false
	}
	parts := strings.Split(filepath.ToSlash(filepath.Clean(executablePath)), "/")
	for index := 0; index+1 < len(parts); index++ {
		if strings.HasSuffix(strings.ToLower(parts[index]), ".app") &&
			strings.EqualFold(parts[index+1], "Contents") {
			return true
		}
	}
	return false
}

func buildAgentReleaseCheckURL(cfg RuntimeConfig) string {
	if custom := strings.TrimSpace(cfg.AutoUpdateCheckURL); custom != "" {
		return normalizeHTTPSURL(custom)
	}
	if api := strings.TrimSpace(cfg.APIBaseURL); api != "" {
		return strings.TrimRight(normalizeAPIBaseURL(api), "/") + "/api/v1/agent/releases/latest"
	}
	ws := normalizeWSBaseURL(cfg.WSBaseURL)
	if ws == "" {
		return ""
	}
	parsed, err := url.Parse(ws)
	if err != nil || strings.TrimSpace(parsed.Host) == "" {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "wss":
		parsed.Scheme = "https"
	case "ws":
		parsed.Scheme = "http"
	case "https", "http":
		// keep as-is
	default:
		return ""
	}
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	base := strings.TrimRight(parsed.String(), "/")
	if base == "" {
		return ""
	}
	return base + "/api/v1/agent/releases/latest"
}

func fetchReleaseMetadata(cfg RuntimeConfig, endpoint string) (agentReleaseMetadata, error) {
	requestURL, err := url.Parse(endpoint)
	if err != nil {
		return agentReleaseMetadata{}, err
	}
	query := requestURL.Query()
	query.Set("os", runtime.GOOS)
	query.Set("arch", runtime.GOARCH)
	requestURL.RawQuery = query.Encode()

	client := newSelfUpdateHTTPClient(cfg)
	req, err := securityruntime.NewOutboundRequestWithContext(context.Background(), http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return agentReleaseMetadata{}, err
	}
	if token := strings.TrimSpace(cfg.APIToken); token != "" && shouldAttachUpdateMetadataToken(cfg, requestURL.String()) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := securityruntime.DoOutboundRequest(client, req)
	if err != nil {
		return agentReleaseMetadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return agentReleaseMetadata{}, fmt.Errorf("release endpoint returned status %d", resp.StatusCode)
	}

	if resp.ContentLength > maxSelfUpdateMetadataSize {
		return agentReleaseMetadata{}, fmt.Errorf("release metadata exceeded maximum size of %d bytes", maxSelfUpdateMetadataSize)
	}
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, maxSelfUpdateMetadataSize+1))
	if err != nil {
		return agentReleaseMetadata{}, err
	}
	if len(encoded) > maxSelfUpdateMetadataSize {
		return agentReleaseMetadata{}, fmt.Errorf("release metadata exceeded maximum size of %d bytes", maxSelfUpdateMetadataSize)
	}
	var payload agentReleaseMetadata
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&payload); err != nil {
		return agentReleaseMetadata{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return agentReleaseMetadata{}, fmt.Errorf("release metadata contains trailing JSON")
		}
		return agentReleaseMetadata{}, fmt.Errorf("release metadata contains trailing data: %w", err)
	}
	return payload, nil
}

func downloadReleaseBinary(cfg RuntimeConfig, checkURL, absoluteURL string, expectedSize int64) ([]byte, error) {
	client := newSelfUpdateHTTPClient(cfg)
	req, err := securityruntime.NewOutboundRequestWithContext(context.Background(), http.MethodGet, absoluteURL, nil)
	if err != nil {
		return nil, err
	}
	if token := strings.TrimSpace(cfg.APIToken); token != "" && shouldAttachUpdateToken(checkURL, absoluteURL) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := securityruntime.DoOutboundRequest(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("download endpoint returned status %d", resp.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxSelfUpdateBinarySize+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxSelfUpdateBinarySize {
		return nil, fmt.Errorf("download exceeded maximum size of %d bytes", maxSelfUpdateBinarySize)
	}
	if expectedSize > 0 && int64(len(payload)) != expectedSize {
		return nil, fmt.Errorf("download size mismatch: expected %d bytes, got %d bytes", expectedSize, len(payload))
	}
	return payload, nil
}

func resolveReleaseDownloadURL(checkURL, releaseURL string) string {
	releaseURL = strings.TrimSpace(releaseURL)
	if releaseURL == "" {
		return ""
	}
	if parsed, err := url.Parse(releaseURL); err == nil && parsed.IsAbs() {
		return parsed.String()
	}
	base, err := url.Parse(checkURL)
	if err != nil {
		return releaseURL
	}
	rel, err := url.Parse(releaseURL)
	if err != nil {
		return releaseURL
	}
	return base.ResolveReference(rel).String()
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- Path is the updater-managed artifact path selected by runtime config.
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func newSelfUpdateHTTPClient(cfg RuntimeConfig) *http.Client {
	transport := &http.Transport{}
	if tlsCfg := buildTLSConfig(&cfg); tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}
	return &http.Client{
		Timeout:   selfUpdateTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if len(via) > 0 && !sameOrigin(via[0].URL.String(), req.URL.String()) {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
}

func shouldAttachUpdateToken(checkURL, downloadURL string) bool {
	return sameOrigin(checkURL, downloadURL)
}

func shouldAttachUpdateMetadataToken(cfg RuntimeConfig, endpoint string) bool {
	canonicalConfig := cfg
	canonicalConfig.AutoUpdateCheckURL = ""
	canonicalEndpoint := buildAgentReleaseCheckURL(canonicalConfig)
	return canonicalEndpoint != "" && sameOrigin(canonicalEndpoint, endpoint)
}

func sameOrigin(leftRaw, rightRaw string) bool {
	left, err := url.Parse(strings.TrimSpace(leftRaw))
	if err != nil {
		return false
	}
	right, err := url.Parse(strings.TrimSpace(rightRaw))
	if err != nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(left.Scheme), strings.TrimSpace(right.Scheme)) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(left.Host), strings.TrimSpace(right.Host))
}
