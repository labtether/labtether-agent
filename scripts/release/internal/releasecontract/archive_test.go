package releasecontract

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Risk: seal and verify must accept the Linux archives that prepare writes.
// The writer stores gzip MTIME 0, which Go's reader returns as the zero time;
// the verifier once demanded time.Unix(0, 0) and refused every real archive,
// blocking the whole local release lane. A real timestamp must still fail.
func TestVerifyDeterministicArchiveAcceptsPreparedArchive(t *testing.T) {
	dir := t.TempDir()
	const entry = "labtether-agent-linux-amd64"
	binaryPath := filepath.Join(dir, entry)
	if err := os.WriteFile(binaryPath, []byte("\x7fELF release fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, entry+"-v0.0.1.tar.gz")
	if err := CreateDeterministicArchive(binaryPath, archivePath, entry); err != nil {
		t.Fatalf("create archive: %v", err)
	}
	if err := VerifyDeterministicArchive(archivePath, binaryPath, entry); err != nil {
		t.Fatalf("verify prepared archive: %v", err)
	}

	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	// Bytes 4..7 of the gzip header hold MTIME; no header CRC covers them.
	binary.LittleEndian.PutUint32(archive[4:8], 1700000000)
	stampedPath := filepath.Join(dir, entry+"-stamped.tar.gz")
	if err := os.WriteFile(stampedPath, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	err = VerifyDeterministicArchive(stampedPath, binaryPath, entry)
	if err == nil || !strings.Contains(err.Error(), "gzip header is not deterministic") {
		t.Fatalf("archive with a real gzip timestamp: got %v, want header rejection", err)
	}
}
