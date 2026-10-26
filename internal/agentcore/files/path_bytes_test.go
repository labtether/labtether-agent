package files

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/labtether/protocol"
)

func TestFileOperationsPreserveSpacesInHomeAndFileNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Win32 does not support trailing-space path components")
	}
	home := filepath.Join(t.TempDir(), "home ")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := ResolveFileBaseDirWithHome("home", home); got != home {
		t.Fatalf("home bytes changed: %q", got)
	}
	if !IsWritableDirectory(home) {
		t.Fatal("exact home directory was not checked")
	}
	fm := &Manager{BaseDir: home, HomeDir: home}
	defer fm.CloseAll()
	const original = "~/ file "
	const renamed = "~/ renamed "
	contents := []byte("exact bytes\n")
	if _, err := fm.WriteChunk(protocol.FileWriteData{RequestID: "spaces", Path: original, Data: base64.StdEncoding.EncodeToString(contents), Done: true}); err != nil {
		t.Fatal(err)
	}
	transport := &testFileTransport{}
	data, _ := json.Marshal(protocol.FileRenameData{RequestID: "rename", OldPath: original, NewPath: renamed})
	fm.HandleFileRename(transport, protocol.Message{Data: data})
	if result := lastFileResult(t, transport); !result.OK {
		t.Fatalf("rename failed: %+v", result)
	}
	transport.messages = nil
	data, _ = json.Marshal(protocol.FileReadData{RequestID: "read", Path: renamed})
	fm.HandleFileRead(transport, protocol.Message{Data: data})
	var got []byte
	for _, message := range transport.messages {
		var chunk protocol.FileDataPayload
		if err := json.Unmarshal(message.Data, &chunk); err != nil {
			t.Fatal(err)
		}
		if chunk.Error != "" {
			t.Fatal(chunk.Error)
		}
		decoded, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, decoded...)
	}
	if !bytes.Equal(got, contents) {
		t.Fatalf("download bytes changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, " renamed ")); err != nil {
		t.Fatal(err)
	}
}
