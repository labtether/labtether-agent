package remoteaccess

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDiscoverDisplayXAuthorityFromProc(t *testing.T) {
	tempDir := t.TempDir()
	procDir := filepath.Join(tempDir, "proc")
	if err := os.MkdirAll(filepath.Join(procDir, "901"), 0o755); err != nil {
		t.Fatalf("mkdir proc: %v", err)
	}

	authPath := filepath.Join(tempDir, "run", "user", "1000", "gdm", "Xauthority")
	if err := os.MkdirAll(filepath.Dir(authPath), 0o755); err != nil {
		t.Fatalf("mkdir auth dir: %v", err)
	}
	if err := os.WriteFile(authPath, []byte("cookie"), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	originalProcRoot := X11ProcRoot
	t.Cleanup(func() {
		X11ProcRoot = originalProcRoot
	})
	X11ProcRoot = procDir

	// Xorg owns the server cookie; all its screens and numeric aliases share it.
	for _, server := range []string{":93", ":093"} {
		cmdline := "/usr/lib/xorg/Xorg\x00" + server + "\x00-seat\x00seat0\x00-auth\x00" + authPath + "\x00-nolisten\x00tcp\x00"
		if err := os.WriteFile(filepath.Join(procDir, "901", "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatalf("write cmdline: %v", err)
		}
		for _, display := range []string{":93", ":93.1", ":093.1"} {
			if got := DiscoverDisplayXAuthority(display); got != authPath {
				t.Fatalf("server %s, display %s: auth=%q, want %q", server, display, got, authPath)
			}
			env := BuildX11ClientEnv(display, "")
			if !slices.Contains(env, "DISPLAY="+display) || !slices.Contains(env, "XAUTHORITY="+authPath) {
				t.Fatalf("server %s, display %s: client must keep selected screen and share its server cookie", server, display)
			}
		}
		if got := DiscoverDisplayXAuthorityFromProc(":94.1"); got != "" {
			t.Fatalf("unrelated server received auth %q", got)
		}
	}
	candidates := DisplayXAuthorityCandidates(":093.1")
	if len(candidates) < 2 || candidates[0] != filepath.Join("/run/lightdm/root", ":93") ||
		candidates[1] != filepath.Join("/var/run/lightdm/root", ":93") {
		t.Fatalf("LightDM auth paths must name the X server, got %v", candidates)
	}
	if candidates := DisplayXAuthorityCandidates("invalid.1"); len(candidates) != 0 {
		t.Fatalf("invalid display returned auth paths: %v", candidates)
	}
}
