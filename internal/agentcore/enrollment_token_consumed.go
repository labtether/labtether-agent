package agentcore

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// A one-time enrollment token supplied through a read-only mount (for example
// a container secret) cannot be deleted after the Hub consumes it. The agent
// then records the token's SHA-256 beside its own credential and ignores a
// matching token on every later start, so a consumed token is never offered to
// the Hub again. A different, freshly staged token is still honored.
const consumedEnrollmentTokenFileName = "consumed-enrollment-token.sha256"

func consumedEnrollmentTokenPath(tokenFilePath string) string {
	if strings.TrimSpace(tokenFilePath) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(tokenFilePath), consumedEnrollmentTokenFileName)
}

func enrollmentTokenDigest(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func recordConsumedEnrollmentToken(tokenFilePath, token string) error {
	path := consumedEnrollmentTokenPath(tokenFilePath)
	if path == "" {
		return fmt.Errorf("no agent state directory to record the consumed enrollment token")
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("consumed enrollment token is empty")
	}
	return writeManagedFileAtomic(path, []byte(enrollmentTokenDigest(token)+"\n"), 0o600, true)
}

func isConsumedEnrollmentToken(tokenFilePath, token string) bool {
	path := consumedEnrollmentTokenPath(tokenFilePath)
	if path == "" || strings.TrimSpace(token) == "" {
		return false
	}
	raw, err := readBoundedRegularFile(path, maxLocalSecretFileBytes)
	if err != nil {
		return false
	}
	recorded := []byte(strings.TrimSpace(string(raw)))
	return subtle.ConstantTimeCompare(recorded, []byte(enrollmentTokenDigest(token))) == 1
}

// dropConsumedEnrollmentToken disarms a file-sourced enrollment token that this
// agent already used. It runs before token resolution arms enrollment or
// re-enrollment, and it never deletes the operator's file.
func dropConsumedEnrollmentToken(cfg *RuntimeConfig) {
	if cfg == nil || !cfg.EnrollmentTokenFromFile || !isConsumedEnrollmentToken(cfg.TokenFilePath, cfg.EnrollmentToken) {
		return
	}
	log.Printf("agent: ignoring enrollment token file %s: this token was already used to enroll; remove the file or stage a new token", cfg.EnrollmentTokenFilePath)
	cfg.EnrollmentToken = ""
	cfg.EnrollmentTokenFromFile = false
}

// removeConsumedEnrollmentTokenFile deletes the consumed token file. When the
// file cannot be deleted (read-only or bind-mounted secret), it records the
// token as consumed instead, so startup continues and the token is not reused.
func removeConsumedEnrollmentTokenFile(cfg *RuntimeConfig) error {
	removeErr := os.Remove(cfg.EnrollmentTokenFilePath)
	if removeErr == nil {
		log.Printf("agent: removed consumed enrollment token file")
		return nil
	}
	if os.IsNotExist(removeErr) {
		return nil
	}
	if err := recordConsumedEnrollmentToken(cfg.TokenFilePath, cfg.EnrollmentToken); err != nil {
		return fmt.Errorf("remove consumed enrollment token file: %w; record consumed token: %v", removeErr, err)
	}
	log.Printf("agent: warning: could not remove consumed enrollment token file (%v); it is marked as used and will be ignored", removeErr)
	return nil
}
