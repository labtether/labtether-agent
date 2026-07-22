package agentcore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/labtether/protocol"
)

func TestHandleEnrollmentApprovedPersistenceFailureRemovesStaleTokenAndSurfacesStatus(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "agent-token")
	if err := os.WriteFile(tokenFile, []byte("stale-revoked-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	originalSave := savePendingEnrollmentToken
	savePendingEnrollmentToken = func(string, string) error { return errors.New("simulated persistence failure") }
	t.Cleanup(func() { savePendingEnrollmentToken = originalSave })

	transport := newWSTransport("", "", "pending-node", "linux", "test", nil, tokenFile, nil)
	payload, err := json.Marshal(protocol.EnrollmentApprovedData{
		Token:   "memory-only-approved-token",
		AssetID: "canonical-approved-node",
	})
	if err != nil {
		t.Fatal(err)
	}
	handleEnrollmentApproved(transport, protocol.Message{Type: protocol.MsgEnrollmentApproved, Data: payload}, RuntimeConfig{
		TokenFilePath: tokenFile,
	})

	identity := transport.identitySource().Snapshot()
	gotToken := identity.BearerToken
	gotAssetID := identity.AssetID
	if gotToken != "memory-only-approved-token" || gotAssetID != "canonical-approved-node" {
		t.Fatalf("in-memory credential=(%q,%q)", gotToken, gotAssetID)
	}
	state, lastErr, _ := transport.ConnectionState()
	if state != "connecting" || lastErr != agentTokenPersistenceFailed {
		t.Fatalf("status=(%q,%q), want bounded persistence warning", state, lastErr)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Fatalf("stale token file remained after failed approval persistence: %v", err)
	}
	if token, err := loadTokenFromFile(tokenFile); err == nil && token != "" {
		t.Fatalf("restart could silently reload stale token %q", token)
	}
}
