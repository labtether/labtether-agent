package remoteaccess

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A desktop session must never expose an unauthenticated VNC server, and the
// session password must never appear in x11vnc's argv (visible through ps).
func TestPrepareX11VNCLaunchRefusesMissingPassword(t *testing.T) {
	isolateVNCTempDir(t)
	for _, password := range []string{"", "   "} {
		args, authDir, err := prepareX11VNCLaunch(":0", 5901, "medium", password, "", "")
		if !errors.Is(err, errVNCPasswordRequired) {
			t.Fatalf("password %q: err=%v, want errVNCPasswordRequired", password, err)
		}
		if args != nil || authDir != "" {
			t.Fatalf("password %q: launch prepared without a password: %v %q", password, args, authDir)
		}
	}
	if _, err := BuildX11VNCArgs(":0", 5901, "medium", "", ""); !errors.Is(err, errVNCPasswordRequired) {
		t.Fatalf("BuildX11VNCArgs without password file: err=%v", err)
	}
	if entries, _ := os.ReadDir(os.TempDir()); len(entries) != 0 {
		t.Fatalf("refused launch left files behind: %v", entries)
	}
}

func TestPrepareX11VNCLaunchKeepsPasswordOutOfArgs(t *testing.T) {
	isolateVNCTempDir(t)
	const password = "Hx7kQ2pZ"
	args, authDir, err := prepareX11VNCLaunch(":0", 5901, "medium", password, "", "")
	if err != nil {
		t.Fatalf("prepare launch: %v", err)
	}
	for _, arg := range args {
		if strings.Contains(arg, password) {
			t.Fatalf("password leaked into x11vnc args: %v", args)
		}
		if arg == "-nopw" || arg == "-passwd" {
			t.Fatalf("unsafe x11vnc auth flag %q in %v", arg, args)
		}
	}
	passwordFile := filepath.Join(authDir, x11vncPasswordFileName)
	requireArgPair(t, args, "-passwdfile", "rm:"+passwordFile)

	data, err := os.ReadFile(passwordFile)
	if err != nil || string(data) != password+"\n" {
		t.Fatalf("password file content=%q err=%v", data, err)
	}
	if runtime.GOOS != "windows" {
		requireMode(t, authDir, 0o700)
		requireMode(t, passwordFile, 0o600)
	}

	RemoveVNCAuthDir(authDir)
	if _, err := os.Stat(authDir); !os.IsNotExist(err) {
		t.Fatalf("auth directory survived session cleanup: %v", err)
	}
}

func TestValidateX11VNCPasswordRejectsPasswordFileSyntax(t *testing.T) {
	for _, password := range []string{"#comment", "a__EMPTY__", "two\nlines", "has space"} {
		if err := validateX11VNCPassword(password); err == nil {
			t.Fatalf("password %q accepted", password)
		}
	}
}

func isolateVNCTempDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
}

func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode=%v, want %v", path, got, want)
	}
}
