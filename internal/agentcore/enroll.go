package agentcore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/labtether/labtether-agent/internal/agentidentity"
	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const maxEnrollmentResponseBytes = 1024 * 1024

type enrollmentHTTPStatusError struct {
	statusCode int
}

func (e *enrollmentHTTPStatusError) Error() string {
	return fmt.Sprintf("enroll returned status %d", e.statusCode)
}

func isEnrollmentCredentialRejected(err error) bool {
	var statusErr *enrollmentHTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.statusCode == http.StatusUnauthorized || statusErr.statusCode == http.StatusForbidden
}

// ResolveToken sets cfg.APIToken using the first available source:
// 1. Explicit LABTETHER_API_TOKEN env var (already loaded)
// 2. Persisted token file on disk
// 3. Enrollment with the hub using LABTETHER_ENROLLMENT_TOKEN
func ResolveToken(ctx context.Context, cfg *RuntimeConfig) error {
	return resolveTokenWithIdentity(ctx, cfg, nil)
}

var errAgentTokenPersistence = errors.New("agent token persistence failed")

func resolveTokenWithIdentity(ctx context.Context, cfg *RuntimeConfig, identity *deviceIdentity) error {
	// Priority 1: explicit API token
	if cfg.APIToken != "" {
		if cfg.APIBaseURL == "" {
			cfg.APIBaseURL = apiBaseURLFromWS(cfg.WSBaseURL)
		}
		return nil
	}

	// Priority 2: persisted token file
	if token, err := loadTokenFromFile(cfg.TokenFilePath); err == nil && token != "" {
		log.Printf("agent: loaded token from %s", cfg.TokenFilePath)
		cfg.APIToken = token
		if err := restoreEnrollmentState(cfg); err != nil {
			log.Printf("agent: warning: could not restore enrollment state: %v", err)
		}
		// Preserve an independently staged one-time enrollment token. It arms
		// the authenticated re-enrollment callback if this persisted agent
		// credential is later rejected; it is discarded only after rotation.
		return nil
	}

	// Priority 3: enrollment
	if cfg.EnrollmentToken == "" {
		return nil // no enrollment token set — agent will run without auth (legacy)
	}
	if cfg.WSBaseURL == "" && cfg.APIBaseURL == "" {
		return fmt.Errorf("enrollment requires LABTETHER_WS_URL or LABTETHER_API_BASE_URL")
	}

	log.Printf("agent: enrolling with hub...")
	resp, err := enrollWithHubWithIdentity(ctx, cfg, identity)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	cfg.APIToken = resp.AgentToken
	if resp.AssetID != "" {
		cfg.AssetID = resp.AssetID
	}
	if normalized := normalizeWSBaseURL(resp.HubWSURL); normalized != "" {
		cfg.WSBaseURL = normalized
	}
	if normalized := normalizeAPIBaseURL(resp.HubAPIURL); normalized != "" {
		cfg.APIBaseURL = normalized
	}

	// Persist token to disk. If persistence fails after the hub has consumed the
	// one-time enrollment credential, remove any stale credential at the target
	// path and return a visible degraded-state error. The freshly issued token
	// remains in cfg for this process, but a restart must not mistake an older
	// disk token for a usable credential.
	var tokenPersistenceErr error
	if err := saveTokenToFile(cfg.TokenFilePath, resp.AgentToken); err != nil {
		removeErr := removePersistedAgentToken(cfg.TokenFilePath)
		if removeErr != nil {
			tokenPersistenceErr = fmt.Errorf("persist issued agent token: %w; remove stale token file: %v", err, removeErr)
		} else {
			tokenPersistenceErr = fmt.Errorf("persist issued agent token: %w (stale token file removed)", err)
		}
		log.Printf("agent: ERROR: enrollment succeeded but token persistence failed; replacement credential is memory-only: %v", tokenPersistenceErr)
	} else {
		log.Printf("agent: token persisted to %s", cfg.TokenFilePath)
		if err := saveEnrollmentState(cfg.TokenFilePath, enrollmentState{
			AssetID:   cfg.AssetID,
			HubWSURL:  cfg.WSBaseURL,
			HubAPIURL: cfg.APIBaseURL,
		}); err != nil {
			log.Printf("agent: warning: could not persist enrollment state: %v", err)
		}
	}
	consumedTokenCleanupErr := discardConsumedEnrollmentToken(cfg)
	if consumedTokenCleanupErr != nil {
		log.Printf("agent: ERROR: consumed enrollment token cleanup failed: %v", consumedTokenCleanupErr)
	}

	// Save hub CA certificate if provided (validate it's actually a CA cert first).
	if resp.CACertPEM != "" && cfg.TokenFilePath != "" {
		if err := validateCACertPEM(resp.CACertPEM); err != nil {
			log.Printf("agent: warning: hub returned invalid CA certificate: %v (ignoring)", err)
		} else {
			caPath := filepath.Join(filepath.Dir(cfg.TokenFilePath), "ca.crt")
			if err := writeManagedFileAtomic(caPath, []byte(resp.CACertPEM), 0o644, false); err != nil {
				log.Printf("agent: warning: could not save hub CA to %s: %v", caPath, err)
			} else {
				log.Printf("agent: saved hub CA certificate to %s", caPath)
				cfg.TLSCAFile = caPath
			}
		}
	}

	log.Printf("agent: enrolled successfully as %s", cfg.AssetID)
	if tokenPersistenceErr != nil && consumedTokenCleanupErr != nil {
		return fmt.Errorf("%w: %v; %v", errAgentTokenPersistence, tokenPersistenceErr, consumedTokenCleanupErr)
	}
	if tokenPersistenceErr != nil {
		return fmt.Errorf("%w: %v", errAgentTokenPersistence, tokenPersistenceErr)
	}
	if consumedTokenCleanupErr != nil {
		return consumedTokenCleanupErr
	}
	return nil
}

func discardConsumedEnrollmentToken(cfg *RuntimeConfig) error {
	if cfg == nil {
		return nil
	}
	var cleanupErr error
	if cfg.EnrollmentTokenFromFile && strings.TrimSpace(cfg.EnrollmentTokenFilePath) != "" {
		if err := os.Remove(cfg.EnrollmentTokenFilePath); err != nil && !os.IsNotExist(err) {
			cleanupErr = fmt.Errorf("remove consumed enrollment token file: %w", err)
		} else {
			log.Printf("agent: removed consumed enrollment token file")
		}
	}
	cfg.EnrollmentToken = ""
	cfg.EnrollmentTokenFromFile = false
	_ = os.Unsetenv("LABTETHER_ENROLLMENT_TOKEN")
	return cleanupErr
}

func removePersistedAgentToken(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTDIR) {
		return err
	}
	return nil
}

type enrollRequest struct {
	EnrollmentToken    string `json:"enrollment_token"`
	Hostname           string `json:"hostname"`
	Platform           string `json:"platform"`
	GroupID            string `json:"group_id,omitempty"`
	DeviceKeyAlg       string `json:"device_key_algorithm,omitempty"`
	DevicePublicKey    string `json:"device_public_key,omitempty"`
	DeviceFingerprint  string `json:"device_fingerprint,omitempty"`
	DeviceSignature    string `json:"device_signature,omitempty"`
	DeviceProofVersion string `json:"device_proof_version,omitempty"`
}

type enrollResponse struct {
	AgentToken string `json:"agent_token"`
	AssetID    string `json:"asset_id"`
	HubWSURL   string `json:"hub_ws_url"`
	HubAPIURL  string `json:"hub_api_url"`
	CACertPEM  string `json:"ca_cert_pem,omitempty"`
}

func enrollWithHub(ctx context.Context, cfg *RuntimeConfig) (*enrollResponse, error) {
	return enrollWithHubWithIdentity(ctx, cfg, nil)
}

func enrollWithHubWithIdentity(ctx context.Context, cfg *RuntimeConfig, identity *deviceIdentity) (*enrollResponse, error) {
	return enrollWithHubWithIdentityProof(ctx, cfg, identity, "")
}

func enrollWithHubWithContinuityIdentity(ctx context.Context, cfg *RuntimeConfig, identity *deviceIdentity, canonicalAssetID string) (*enrollResponse, error) {
	canonicalAssetID = strings.TrimSpace(canonicalAssetID)
	if canonicalAssetID == "" {
		return nil, fmt.Errorf("canonical asset id is required for continuity enrollment")
	}
	return enrollWithHubWithIdentityProof(ctx, cfg, identity, canonicalAssetID)
}

func enrollWithHubWithIdentityProof(ctx context.Context, cfg *RuntimeConfig, identity *deviceIdentity, continuityAssetID string) (*enrollResponse, error) {
	// Build enroll URL from WSBaseURL or APIBaseURL
	var enrollURL string
	if cfg.APIBaseURL != "" {
		enrollURL = strings.TrimRight(normalizeAPIBaseURL(cfg.APIBaseURL), "/") + "/api/v1/enroll"
	} else if cfg.WSBaseURL != "" {
		parsedWS, err := url.Parse(normalizeWSBaseURL(cfg.WSBaseURL))
		if err != nil || strings.TrimSpace(parsedWS.Host) == "" {
			return nil, fmt.Errorf("invalid websocket url for enrollment")
		}
		switch strings.ToLower(strings.TrimSpace(parsedWS.Scheme)) {
		case "wss":
			parsedWS.Scheme = "https"
		case "ws":
			if allowInsecureTransportOptIn() {
				parsedWS.Scheme = "http"
			} else {
				parsedWS.Scheme = "https"
			}
		default:
			return nil, fmt.Errorf("unsupported websocket scheme for enrollment: %s", parsedWS.Scheme)
		}
		parsedWS.Path = ""
		parsedWS.RawPath = ""
		parsedWS.RawQuery = ""
		parsedWS.Fragment = ""
		enrollURL = strings.TrimRight(parsedWS.String(), "/") + "/api/v1/enroll"
	}

	// AGENT_ASSET_ID is the user-facing enrollment identity exposed by the
	// native wrappers. Prefer it when valid so onboarding does not silently
	// replace the user's requested asset ID with the operating-system hostname.
	// A malformed override cannot poison enrollment: fall back to a valid system
	// hostname, then to a stable safe default.
	systemHostname, _ := os.Hostname()
	hostname := selectEnrollmentHostname(cfg.AssetID, systemHostname)

	reqBody := enrollRequest{
		EnrollmentToken: cfg.EnrollmentToken,
		Hostname:        hostname,
		Platform:        runtime.GOOS,
		GroupID:         cfg.GroupID,
	}
	if identity != nil {
		reqBody.DeviceKeyAlg = identity.KeyAlgorithm
		reqBody.DevicePublicKey = identity.PublicKeyBase64
		reqBody.DeviceFingerprint = identity.Fingerprint
		var signingPayload []byte
		if strings.TrimSpace(continuityAssetID) != "" {
			reqBody.DeviceProofVersion = "v2"
			signingPayload = agentidentity.BuildTokenEnrollmentProofPayloadV2(continuityAssetID, cfg.EnrollmentToken, identity.Fingerprint)
		} else {
			reqBody.DeviceProofVersion = "v1"
			signingPayload = agentidentity.BuildTokenEnrollmentProofPayload(hostname, cfg.EnrollmentToken, identity.Fingerprint)
		}
		reqBody.DeviceSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity.PrivateKey, signingPayload))
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := securityruntime.NewOutboundRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	if tlsCfg := buildTLSConfig(cfg); tlsCfg != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	resp, err := securityruntime.DoOutboundRequest(client, httpReq)
	if err != nil {
		return nil, fmt.Errorf("enroll HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &enrollmentHTTPStatusError{statusCode: resp.StatusCode}
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollmentResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("enroll response read failed: %w", err)
	}
	if len(responseBody) > maxEnrollmentResponseBytes {
		return nil, fmt.Errorf("enroll response exceeds %d bytes", maxEnrollmentResponseBytes)
	}
	var result enrollResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("enroll response decode failed: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("enroll response contains trailing data")
	}
	result.AgentToken, err = normalizeIssuedAgentToken(result.AgentToken)
	if err != nil {
		return nil, fmt.Errorf("enroll response agent_token is invalid: %w", err)
	}
	result.AssetID = strings.TrimSpace(result.AssetID)
	if !validPersistedAssetID(result.AssetID) {
		return nil, fmt.Errorf("enroll response asset_id is invalid")
	}
	result.HubWSURL = normalizeWSBaseURL(result.HubWSURL)
	result.HubAPIURL = normalizeAPIBaseURL(result.HubAPIURL)
	if err := validatePersistedHubURL(result.HubWSURL, true); err != nil {
		return nil, fmt.Errorf("enroll response websocket URL is invalid: %w", err)
	}
	if err := validatePersistedHubURL(result.HubAPIURL, false); err != nil {
		return nil, fmt.Errorf("enroll response API URL is invalid: %w", err)
	}
	return &result, nil
}

const maxEnrollmentHostnameBytes = 253

func selectEnrollmentHostname(configuredAssetID, systemHostname string) string {
	configuredAssetID = strings.TrimSpace(configuredAssetID)
	if validPersistedAssetID(configuredAssetID) {
		return configuredAssetID
	}

	systemHostname = strings.TrimSpace(systemHostname)
	if validEnrollmentRequestHostname(systemHostname) {
		return systemHostname
	}
	return "labtether-agent"
}

func validEnrollmentRequestHostname(value string) bool {
	if value == "" || len(value) > maxEnrollmentHostnameBytes || !utf8.ValidString(value) {
		return false
	}
	for _, ch := range value {
		if unicode.IsControl(ch) {
			return false
		}
	}
	return true
}

func loadTokenFromFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := readBoundedRegularFile(path, maxLocalSecretFileBytes)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func saveTokenToFile(path, token string) error {
	if path == "" {
		return nil
	}
	if err := writeManagedFileAtomic(path, []byte(token+"\n"), 0o600, true); err != nil {
		return fmt.Errorf("secure token file ACL: %w", err)
	}
	return nil
}

// validateCACertPEM parses a PEM-encoded certificate and verifies it has the
// CA basic constraint set. This prevents a compromised hub from injecting a
// non-CA certificate that could be used to intercept traffic.
func validateCACertPEM(pemData string) error {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("PEM data does not contain a CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	if !cert.IsCA {
		return fmt.Errorf("certificate is not a CA (BasicConstraints.IsCA=false)")
	}
	return nil
}
