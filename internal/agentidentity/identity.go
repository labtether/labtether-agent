package agentidentity

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

const KeyAlgorithmEd25519 = "ed25519"

// FingerprintFromPublicKey returns a stable, human-friendly fingerprint for a
// device public key.
func FingerprintFromPublicKey(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return "LT-" + groupFingerprint(encoded, 4)
}

// BuildEnrollmentProofPayload builds the canonical bytes an agent signs to
// prove possession of its device private key during pending enrollment.
func BuildEnrollmentProofPayload(connectionID, nonce, fingerprint string) []byte {
	return []byte(
		"labtether-enrollment-proof|" +
			strings.TrimSpace(connectionID) + "|" +
			strings.TrimSpace(nonce) + "|" +
			strings.TrimSpace(fingerprint),
	)
}

// BuildTokenEnrollmentProofPayload builds the canonical bytes an agent signs
// when using a one-time enrollment token. It is domain-separated from the
// interactive pending-enrollment proof and binds the proof to the exact token
// and hostname while keeping the raw bearer token out of the payload.
func BuildTokenEnrollmentProofPayload(hostname, enrollmentToken, fingerprint string) []byte {
	tokenHash := sha256.Sum256([]byte(strings.TrimSpace(enrollmentToken)))
	return []byte(
		"labtether-token-enrollment-proof-v1|" +
			strings.TrimSpace(hostname) + "|" +
			hex.EncodeToString(tokenHash[:]) + "|" +
			strings.TrimSpace(fingerprint),
	)
}

// BuildTokenEnrollmentProofPayloadV2 binds continuity recovery to the exact
// canonical asset ID selected by the hub. It is intentionally separate from
// the hostname-bound v1 payload retained for initial-enrollment compatibility.
func BuildTokenEnrollmentProofPayloadV2(assetID, enrollmentToken, fingerprint string) []byte {
	tokenHash := sha256.Sum256([]byte(strings.TrimSpace(enrollmentToken)))
	return []byte(
		"labtether-token-enrollment-proof-v2|" +
			strings.TrimSpace(assetID) + "|" +
			hex.EncodeToString(tokenHash[:]) + "|" +
			strings.TrimSpace(fingerprint),
	)
}

func groupFingerprint(raw string, groupSize int) string {
	if groupSize <= 0 {
		return raw
	}
	raw = strings.ToUpper(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}

	var b strings.Builder
	for i, r := range raw {
		if i > 0 && i%groupSize == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}
