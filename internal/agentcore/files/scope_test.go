package files

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/labtether/protocol"
)

// Full mode on Windows must reach every fixed drive, not only the system
// drive. Two temporary folders stand in for the C: and D: drive roots.
func TestFullModeReachesEveryDriveRoot(t *testing.T) {
	systemDrive, dataDrive, outside := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDrive, "media.txt"), []byte("on D:"), 0o600); err != nil {
		t.Fatal(err)
	}
	fm := &Manager{
		writers:    make(map[string]*PendingWrite),
		BaseDir:    systemDrive,
		HomeDir:    systemDrive,
		extraRoots: func() []string { return []string{dataDrive} },
	}

	root, rel, _, err := fm.OpenRootPath(filepath.Join(dataDrive, "media.txt"))
	if err != nil {
		t.Fatalf("second drive not reachable: %v", err)
	}
	data, err := root.ReadFile(rel)
	_ = root.Close()
	if err != nil || string(data) != "on D:" {
		t.Fatalf("read on second drive = %q, %v", data, err)
	}
	if _, _, _, err := fm.OpenRootPath(filepath.Join(outside, "secret.txt")); err == nil {
		t.Fatal("a path outside every drive root was allowed")
	}

	transport := &testFileTransport{}
	fm.HandleFileCopy(transport, protocol.Message{Data: marshalTestMessage(t, protocol.FileCopyData{
		RequestID: "copy", SrcPath: filepath.Join(dataDrive, "media.txt"), DstPath: filepath.Join(systemDrive, "copy.txt"),
	})})
	if result := lastFileResult(t, transport); !result.OK {
		t.Fatalf("copy between drives failed: %s", result.Error)
	}
	if data, err := os.ReadFile(filepath.Join(systemDrive, "copy.txt")); err != nil || string(data) != "on D:" {
		t.Fatalf("copied file = %q, %v", data, err)
	}

	fm.HandleFileRename(transport, protocol.Message{Data: marshalTestMessage(t, protocol.FileRenameData{
		RequestID: "move", OldPath: filepath.Join(dataDrive, "media.txt"), NewPath: filepath.Join(systemDrive, "moved.txt"),
	})})
	if result := lastFileResult(t, transport); result.OK || !strings.Contains(result.Error, "between drives") {
		t.Fatalf("rename between drives = %+v, want a clear refusal", result)
	}

	fm.HandleFileDelete(transport, protocol.Message{Data: marshalTestMessage(t, protocol.FileDeleteData{
		RequestID: "delete-root", Path: dataDrive,
	})})
	if result := lastFileResult(t, transport); result.OK {
		t.Fatal("deleting a drive root was allowed")
	}
}

// Fault: on Windows "~\folder" was taken as a relative name, so new folders,
// uploads and renames went into a folder literally named "~". Elsewhere a
// backslash is an ordinary file-name character and the path stays relative.
func TestHomePathAcceptsThePlatformSeparators(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	fm := &Manager{writers: make(map[string]*PendingWrite), BaseDir: base, HomeDir: home}

	cases := map[string]string{
		"~":         home,
		"~/notes/a": filepath.Join(home, "notes", "a"),
		`~\notes\a`: filepath.Join(base, `~\notes\a`),
		"~notes":    filepath.Join(base, "~notes"),
	}
	if filepath.Separator == '\\' {
		cases[`~\notes\a`] = filepath.Join(home, "notes", "a")
	}
	for request, want := range cases {
		root, _, display, err := fm.OpenRootPath(request)
		if err != nil {
			t.Errorf("%q: %v", request, err)
			continue
		}
		_ = root.Close()
		if display != want {
			t.Errorf("%q opened %q, want %q", request, display, want)
		}
	}
}

// Fault: a refusal was printed with %q, so the Hub showed a Windows path with
// every backslash doubled ("C:\\Windows"). The console also reads the path
// back out of this exact sentence.
func TestRefusalShowsThePathAsWritten(t *testing.T) {
	base := t.TempDir()
	fm := &Manager{writers: make(map[string]*PendingWrite), BaseDir: base, HomeDir: base}
	request := `/srv\backup\a`
	if runtime.GOOS == "windows" {
		request = `C:\Windows\System32\drivers`
	}

	_, _, _, err := fm.OpenRootPath(request)
	want := `path "` + request + `" is outside the allowed base directory`
	if err == nil || err.Error() != want {
		t.Fatalf("refusal = %v, want %s", err, want)
	}
}
