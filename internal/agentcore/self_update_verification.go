package agentcore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

func validateReleaseMetadata(checkURL, downloadURL string, release agentReleaseMetadata) error {
	if len(strings.TrimSpace(release.Version)) == 0 || len(release.Version) > maxSelfUpdateVersionLength {
		return fmt.Errorf("release metadata includes an invalid version")
	}
	if len(strings.TrimSpace(release.OS)) == 0 || len(release.OS) > maxSelfUpdatePlatformLength {
		return fmt.Errorf("release metadata includes an invalid os")
	}
	if len(strings.TrimSpace(release.Arch)) == 0 || len(release.Arch) > maxSelfUpdatePlatformLength {
		return fmt.Errorf("release metadata includes an invalid architecture")
	}
	if len(release.URL) > maxSelfUpdateURLLength {
		return fmt.Errorf("release metadata download url exceeds %d bytes", maxSelfUpdateURLLength)
	}
	if len(release.Signature) > maxSelfUpdateSignatureLength {
		return fmt.Errorf("release metadata signature exceeds %d bytes", maxSelfUpdateSignatureLength)
	}
	sha := strings.TrimSpace(strings.ToLower(release.SHA256))
	if sha == "" {
		return fmt.Errorf("release metadata missing sha256 digest")
	}
	if _, err := hex.DecodeString(sha); err != nil || len(sha) != 64 {
		return fmt.Errorf("release metadata includes an invalid sha256 digest")
	}
	if release.SizeBytes < 0 {
		return fmt.Errorf("release metadata includes a negative size")
	}
	if release.SizeBytes > maxSelfUpdateBinarySize {
		return fmt.Errorf("release size %d exceeds maximum supported size %d", release.SizeBytes, maxSelfUpdateBinarySize)
	}
	if !parseBoolEnv(envSelfUpdateAllowExternalDownload, false) && !sameOrigin(checkURL, downloadURL) {
		return fmt.Errorf("release download url must match release metadata origin")
	}
	return nil
}

func validateReleaseTarget(cfg RuntimeConfig, release agentReleaseMetadata) error {
	if !strings.EqualFold(strings.TrimSpace(release.OS), runtime.GOOS) {
		return fmt.Errorf("release metadata targets os %q, want %q", strings.TrimSpace(release.OS), runtime.GOOS)
	}
	if !strings.EqualFold(strings.TrimSpace(release.Arch), runtime.GOARCH) {
		return fmt.Errorf("release metadata targets architecture %q, want %q", strings.TrimSpace(release.Arch), runtime.GOARCH)
	}

	releaseVersion, ok := parseStableReleaseVersion(release.Version)
	if !ok {
		return fmt.Errorf("release metadata version %q is not a stable semantic version", strings.TrimSpace(release.Version))
	}
	currentVersion, currentIsStable := parseStableReleaseVersion(cfg.Version)
	if currentIsStable && compareStableReleaseVersions(releaseVersion, currentVersion) < 0 {
		return fmt.Errorf("refusing agent downgrade from %s to %s", strings.TrimSpace(cfg.Version), strings.TrimSpace(release.Version))
	}
	return nil
}

type stableReleaseVersion [3]string

func parseStableReleaseVersion(raw string) (stableReleaseVersion, bool) {
	var parsed stableReleaseVersion
	value := strings.TrimSpace(raw)
	if len(value) > 0 && (value[0] == 'v' || value[0] == 'V') {
		value = value[1:]
	}
	parts := strings.Split(value, ".")
	if len(parts) != len(parsed) {
		return parsed, false
	}
	for index, part := range parts {
		if part == "" {
			return parsed, false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return parsed, false
			}
		}
		normalized := strings.TrimLeft(part, "0")
		if normalized == "" {
			normalized = "0"
		}
		parsed[index] = normalized
	}
	return parsed, true
}

func compareStableReleaseVersions(left, right stableReleaseVersion) int {
	for index := range left {
		if len(left[index]) < len(right[index]) || (len(left[index]) == len(right[index]) && left[index] < right[index]) {
			return -1
		}
		if len(left[index]) > len(right[index]) || (len(left[index]) == len(right[index]) && left[index] > right[index]) {
			return 1
		}
	}
	return 0
}

// builtinSelfUpdatePublicKey is the release signing public key linked into
// release builds through SetBuiltinSelfUpdatePublicKey. Development builds
// leave it empty.
var builtinSelfUpdatePublicKey string

const builtinSelfUpdateKeySource = "the built-in release key"

// SetBuiltinSelfUpdatePublicKey records the release signing public key that
// the release build linked into this binary, so agents installed without
// LABTETHER_AUTO_UPDATE_TRUSTED_PUBLIC_KEY can still verify updates.
func SetBuiltinSelfUpdatePublicKey(key string) {
	builtinSelfUpdatePublicKey = strings.TrimSpace(key)
}

// trustedSelfUpdatePublicKey returns the key every update must be signed with
// and where it came from. A key in the environment replaces the built-in key,
// for a key change or a private build, but no setting can turn verification
// off while either key exists: the unsigned opt-in applies only when neither
// is present.
func trustedSelfUpdatePublicKey() (key string, source string) {
	if raw := strings.TrimSpace(os.Getenv(envSelfUpdateTrustedPublicKey)); raw != "" {
		return raw, envSelfUpdateTrustedPublicKey
	}
	if builtinSelfUpdatePublicKey != "" {
		return builtinSelfUpdatePublicKey, builtinSelfUpdateKeySource
	}
	return "", ""
}

func verifyReleaseMetadataSignature(release agentReleaseMetadata, downloadURL string) error {
	trustedKeyRaw, keySource := trustedSelfUpdatePublicKey()
	if trustedKeyRaw == "" {
		if parseBoolEnv(envSelfUpdateAcceptUnsigned, false) {
			log.Printf("self-update: WARNING %s is unset and %s=true — applying release without signature verification", envSelfUpdateTrustedPublicKey, envSelfUpdateAcceptUnsigned)
			return nil
		}
		return fmt.Errorf("self-update refused: %s is not configured (set %s=true to accept unsigned releases at your own risk)", envSelfUpdateTrustedPublicKey, envSelfUpdateAcceptUnsigned)
	}
	keyBytes, err := decodeSelfUpdatePublicKey(trustedKeyRaw)
	if err != nil {
		return fmt.Errorf("decode %s: %w", keySource, err)
	}
	signatureRaw := strings.TrimSpace(release.Signature)
	if signatureRaw == "" {
		return fmt.Errorf("release metadata signature is required when %s is configured", keySource)
	}
	signature, err := decodeSelfUpdateSignature(signatureRaw)
	if err != nil {
		return fmt.Errorf("decode release signature: %w", err)
	}
	payload := []byte(selfUpdateSignaturePayload(release))
	if !ed25519.Verify(ed25519.PublicKey(keyBytes), payload, signature) {
		return fmt.Errorf("release metadata signature verification failed")
	}
	return nil
}

func decodeSelfUpdatePublicKey(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("public key is required")
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
		return decoded, nil
	}
	return nil, fmt.Errorf("public key must be %d-byte base64 or hex", ed25519.PublicKeySize)
}

func decodeSelfUpdateSignature(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("signature is required")
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.SignatureSize {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.SignatureSize {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.SignatureSize {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == ed25519.SignatureSize {
		return decoded, nil
	}
	return nil, fmt.Errorf("signature must be %d-byte base64 or hex", ed25519.SignatureSize)
}

// selfUpdateSignaturePayload returns the canonical byte sequence the release
// signer covers. The download URL is intentionally excluded: it is constructed
// by the hub at request time and cannot be determined by the CI signer. The
// SHA-256 digest already binds the returned binary to the signed metadata —
// any URL swap fails the hash check downstream.
func selfUpdateSignaturePayload(release agentReleaseMetadata) string {
	return strings.Join([]string{
		strings.TrimSpace(release.Version),
		strings.TrimSpace(release.OS),
		strings.TrimSpace(release.Arch),
		strings.ToLower(strings.TrimSpace(release.SHA256)),
		fmt.Sprintf("%d", release.SizeBytes),
	}, "\n")
}
