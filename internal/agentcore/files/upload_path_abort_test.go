package files

import (
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/labtether/protocol"
)

func TestUploadInvalidNextPathAbortsAndCleansPendingFile(t *testing.T) {
	fm := newUploadLimitTestManager(t, nil, 0)
	_, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "path-failure", Path: "partial.txt",
		Data: base64.StdEncoding.EncodeToString([]byte("partial")),
	})
	if err != nil {
		t.Fatal(err)
	}
	written, err := fm.WriteChunk(protocol.FileWriteData{
		RequestID: "path-failure", Path: filepath.Join("..", "outside.txt"),
		Offset: 7, Done: true,
	})
	if err == nil {
		t.Fatal("outside path accepted")
	}
	if written != 7 {
		t.Fatalf("written = %d, want 7", written)
	}
	if fm.HasPendingWrite("path-failure") {
		t.Fatal("failed upload kept an open file and occupied its slot")
	}
	assertNoUploadTemps(t, fm.BaseDir)
}
