package files

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidatePathPreventsTraversal verifies that paths outside baseDir are rejected.
func TestValidatePathPreventsTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: tmpDir,
	}

	cases := []string{
		"../../etc/passwd",
		"/etc/passwd",
		"../../../root/.ssh/id_rsa",
	}

	for _, tc := range cases {
		_, err := fm.ValidatePath(tc)
		if err == nil {
			t.Errorf("expected error for path %q, got nil", tc)
		}
	}
}

// TestValidatePathAllowsSubdirectories verifies paths within baseDir are accepted.
func TestValidatePathAllowsSubdirectories(t *testing.T) {
	tmpDir := t.TempDir()
	// Resolve symlinks on baseDir itself (macOS /tmp -> /private/var/...).
	resolvedBase, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(resolvedBase, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: resolvedBase,
	}

	resolved, err := fm.ValidatePath("sub/file.txt")
	if err != nil {
		t.Fatalf("unexpected error for valid subpath: %v", err)
	}
	expected := filepath.Join(resolvedBase, "sub", "file.txt")
	if resolved != expected {
		t.Fatalf("expected %q, got %q", expected, resolved)
	}
}

// TestValidatePathEmpty returns baseDir for empty input.
func TestValidatePathEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	resolvedBase, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: resolvedBase,
	}

	resolved, err := fm.ValidatePath("")
	if err != nil {
		t.Fatalf("unexpected error for empty path: %v", err)
	}
	if resolved != resolvedBase {
		t.Fatalf("expected %q, got %q", resolvedBase, resolved)
	}
}

// TestValidatePathRejectsSymlinkToOutside ensures symlink final components
// cannot escape the base directory (regression for symlink traversal bug).
func TestValidatePathRejectsSymlinkToOutside(t *testing.T) {
	baseDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(baseDir, "outside-link")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}

	if _, err := fm.ValidatePath("outside-link"); err == nil {
		t.Fatalf("expected symlink path to be rejected")
	}
}

// TestValidatePathRejectsSymlinkDirectoryOutside ensures symlink directories are
// also blocked when the symlink itself is the final path component.
func TestValidatePathRejectsSymlinkDirectoryOutside(t *testing.T) {
	baseDir := t.TempDir()
	outsideDir := t.TempDir()

	linkPath := filepath.Join(baseDir, "outside-dir")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}

	if _, err := fm.ValidatePath("outside-dir"); err == nil {
		t.Fatalf("expected symlink directory path to be rejected")
	}
}

func TestValidatePathRejectsMissingDescendantThroughSymlinkedParent(t *testing.T) {
	baseDir := t.TempDir()
	outsideDir := t.TempDir()

	linkPath := filepath.Join(baseDir, "outside-dir")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}

	if _, err := fm.ValidatePath(filepath.Join("outside-dir", "new", "file.txt")); err == nil {
		t.Fatal("expected missing descendant under symlinked parent to be rejected")
	}
	if _, err := fm.ValidatePathNoFollowFinal(filepath.Join("outside-dir", "new", "file.txt")); err == nil {
		t.Fatal("expected no-follow validation to reject symlinked parent escape")
	}
}

func TestValidatePathNoFollowFinalAllowsFinalSymlinkToOutside(t *testing.T) {
	baseDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(baseDir, "outside-link")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: baseDir,
	}

	got, err := fm.ValidatePathNoFollowFinal("outside-link")
	if err != nil {
		t.Fatalf("expected final symlink itself to be accepted: %v", err)
	}
	if got != linkPath {
		t.Fatalf("expected lexical link path %q, got %q", linkPath, got)
	}
}

func TestResolveFileBaseDirHomeModeUsesHomeByDefault(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		t.Skip("home directory unavailable")
	}
	got := ResolveFileBaseDir("home")
	if filepath.Clean(got) != filepath.Clean(home) {
		t.Fatalf("ResolveFileBaseDir(home) = %q, want %q", got, home)
	}
}

func TestResolveAgentFileHomeDirFallsBackToDesktopSessionHomeWhenProcessHomeReadOnly(t *testing.T) {
	originalHome := FileUserHomeDirFn
	originalLookupUser := FileLookupUserByUsernameFn
	originalLookupUID := FileLookupUserByUIDFn
	originalWritable := FileIsWritableDirFn
	originalDetect := DetectDesktopSessionFn
	originalTempDir := FileTempDirFn
	originalGetwd := FileGetwdFn
	t.Cleanup(func() {
		FileUserHomeDirFn = originalHome
		FileLookupUserByUsernameFn = originalLookupUser
		FileLookupUserByUIDFn = originalLookupUID
		FileIsWritableDirFn = originalWritable
		DetectDesktopSessionFn = originalDetect
		FileTempDirFn = originalTempDir
		FileGetwdFn = originalGetwd
	})

	FileUserHomeDirFn = func() (string, error) { return "/root", nil }
	FileLookupUserByUsernameFn = func(username string) (*user.User, error) {
		if username != "captain" {
			t.Fatalf("username=%q, want captain", username)
		}
		return &user.User{HomeDir: "/home/captain"}, nil
	}
	FileLookupUserByUIDFn = func(uid string) (*user.User, error) {
		t.Fatalf("unexpected uid lookup: %s", uid)
		return nil, nil
	}
	FileIsWritableDirFn = func(path string) bool {
		return filepath.Clean(path) == "/home/captain"
	}
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		return DesktopSessionInfo{Username: "captain", UID: 1000}
	}
	FileTempDirFn = func() string {
		t.Fatal("did not expect temp fallback")
		return ""
	}
	FileGetwdFn = func() (string, error) {
		t.Fatal("did not expect cwd fallback")
		return "", nil
	}

	if got := ResolveAgentFileHomeDir(); got != "/home/captain" {
		t.Fatalf("ResolveAgentFileHomeDir() = %q, want /home/captain", got)
	}
}

func TestResolveAgentFileHomeDirFallsBackToStagingDirWhenHomesAreReadOnly(t *testing.T) {
	originalHome := FileUserHomeDirFn
	originalLookupUser := FileLookupUserByUsernameFn
	originalLookupUID := FileLookupUserByUIDFn
	originalWritable := FileIsWritableDirFn
	originalDetect := DetectDesktopSessionFn
	originalTempDir := FileTempDirFn
	originalGetwd := FileGetwdFn
	t.Cleanup(func() {
		FileUserHomeDirFn = originalHome
		FileLookupUserByUsernameFn = originalLookupUser
		FileLookupUserByUIDFn = originalLookupUID
		FileIsWritableDirFn = originalWritable
		DetectDesktopSessionFn = originalDetect
		FileTempDirFn = originalTempDir
		FileGetwdFn = originalGetwd
	})

	tempDir := t.TempDir()
	FileUserHomeDirFn = func() (string, error) { return "/root", nil }
	FileLookupUserByUsernameFn = func(string) (*user.User, error) {
		return &user.User{HomeDir: "/home/captain"}, nil
	}
	FileLookupUserByUIDFn = func(string) (*user.User, error) { return nil, os.ErrNotExist }
	FileIsWritableDirFn = func(path string) bool {
		return strings.HasPrefix(filepath.Clean(path), filepath.Clean(tempDir))
	}
	DetectDesktopSessionFn = func() DesktopSessionInfo {
		return DesktopSessionInfo{Username: "captain", UID: 1000}
	}
	FileTempDirFn = func() string { return tempDir }
	FileGetwdFn = func() (string, error) { return "/srv/labtether", nil }

	got := ResolveAgentFileHomeDir()
	want := filepath.Join(tempDir, "labtether-agent-home")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("ResolveAgentFileHomeDir() = %q, want %q", got, want)
	}
}

func TestResolveFileBaseDirFullModeContainsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		t.Skip("home directory unavailable")
	}
	got := ResolveFileBaseDir("full")
	if got == "" {
		t.Fatal("ResolveFileBaseDir(full) returned empty base dir")
	}
	if !PathWithinBaseDir(got, home) {
		t.Fatalf("ResolveFileBaseDir(full) = %q does not contain home %q", got, home)
	}
}

func TestValidatePathExpandsHomeUsingResolvedFileHome(t *testing.T) {
	fm := &Manager{
		writers: make(map[string]*PendingWrite),
		BaseDir: "/tmp/labtether-agent-home",
		HomeDir: "/tmp/labtether-agent-home",
	}

	got, err := fm.ValidatePath("~/notes.txt")
	if err != nil {
		t.Fatalf("ValidatePath returned error: %v", err)
	}
	tmpRoot, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		tmpRoot = "/tmp"
	}
	if filepath.Clean(got) != filepath.Join(tmpRoot, "labtether-agent-home", "notes.txt") {
		t.Fatalf("ValidatePath expanded path = %q", got)
	}
}
