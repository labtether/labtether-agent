//go:build windows

package files

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/labtether/protocol"
)

// A real junction with the hidden and system attributes, as Windows makes
// "Cookies" in a home folder, through the real listing: left out unless
// hidden entries are asked for, and then listed as a link, not as a file.
func TestListTreatsAHiddenSystemJunctionAsAHiddenLink(t *testing.T) {
	base := t.TempDir()
	target, link := filepath.Join(base, "Documents"), filepath.Join(base, "Cookies")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot make a junction: %v: %s", err, out)
	}
	if out, err := exec.Command("attrib", "+h", "+s", "/l", link).CombinedOutput(); err != nil {
		t.Skipf("cannot set the junction's attributes: %v: %s", err, out)
	}

	fm := &Manager{writers: make(map[string]*PendingWrite), BaseDir: base, HomeDir: base}
	list := func(showHidden bool) map[string]protocol.FileEntry {
		transport := &testFileTransport{}
		fm.HandleFileList(transport, protocol.Message{Data: marshalTestMessage(t, protocol.FileListData{
			RequestID: "list", Path: base, ShowHidden: showHidden,
		})})
		var listed protocol.FileListedData
		if err := json.Unmarshal(transport.messages[len(transport.messages)-1].Data, &listed); err != nil || listed.Error != "" {
			t.Fatalf("list: %v %s", err, listed.Error)
		}
		entries := make(map[string]protocol.FileEntry, len(listed.Entries))
		for _, entry := range listed.Entries {
			entries[entry.Name] = entry
		}
		return entries
	}

	visible := list(false)
	if _, listed := visible["Cookies"]; listed {
		t.Error("the hidden system junction is listed without show hidden")
	}
	if got := visible["Documents"]; !got.IsDir || got.Mode != "drwxrwxrwx" {
		t.Errorf("folder = %+v, want a plain folder", got)
	}
	if got, listed := list(true)["Cookies"]; !listed || got.IsDir || got.Mode != "Lrw-rw-rw-" {
		t.Errorf("junction with show hidden = %+v (listed=%v), want a link with mode Lrw-rw-rw-", got, listed)
	}
}
