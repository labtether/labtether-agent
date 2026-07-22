package files

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// DesktopSessionInfo carries the minimal desktop session fields needed for
// home directory resolution. This mirrors the subset of the root agentcore
// desktopSessionInfo that file path resolution requires.
type DesktopSessionInfo struct {
	Username string
	UID      int
}

// DetectDesktopSessionFn is called to discover the active desktop session.
// Root agentcore wires this to its own detectDesktopSession at init time.
var DetectDesktopSessionFn = func() DesktopSessionInfo { return DesktopSessionInfo{} }

var (
	FileUserHomeDirFn          = os.UserHomeDir
	FileLookupUserByUsernameFn = user.Lookup
	FileLookupUserByUIDFn      = user.LookupId
	FileIsWritableDirFn        = IsWritableDirectory
	FileTempDirFn              = os.TempDir
	FileGetwdFn                = os.Getwd
)

// ResolveFileBaseDir resolves the file base directory for the given mode.
func ResolveFileBaseDir(fileRootMode string) string {
	return ResolveFileBaseDirWithHome(fileRootMode, ResolveAgentFileHomeDir())
}

// ResolveFileBaseDirWithHome resolves the file base directory given a mode and pre-resolved home.
func ResolveFileBaseDirWithHome(fileRootMode, homeDir string) string {
	mode := strings.TrimSpace(strings.ToLower(fileRootMode))
	home := strings.TrimSpace(homeDir)
	if home == "" {
		home = string(filepath.Separator)
	}
	if mode == "full" {
		return FilesystemRootForPath(home)
	}
	if home != "" {
		return filepath.Clean(home)
	}
	if cwd, err := FileGetwdFn(); err == nil && strings.TrimSpace(cwd) != "" {
		return filepath.Clean(cwd)
	}
	return string(filepath.Separator)
}

// ResolveAgentFileHomeDir resolves the agent's effective home directory.
func ResolveAgentFileHomeDir() string {
	if home := strings.TrimSpace(resolveProcessUserHomeDir()); home != "" && FileIsWritableDirFn(home) {
		return filepath.Clean(home)
	}

	session := DetectDesktopSessionFn()
	if home := strings.TrimSpace(resolveDesktopSessionHomeDir(session)); home != "" && FileIsWritableDirFn(home) {
		return filepath.Clean(home)
	}

	stagingHome := filepath.Join(FileTempDirFn(), "labtether-agent-home")
	if err := os.MkdirAll(stagingHome, 0o750); err == nil && FileIsWritableDirFn(stagingHome) {
		return filepath.Clean(stagingHome)
	}

	if cwd, err := FileGetwdFn(); err == nil && strings.TrimSpace(cwd) != "" && FileIsWritableDirFn(cwd) {
		return filepath.Clean(cwd)
	}

	if home := strings.TrimSpace(resolveProcessUserHomeDir()); home != "" {
		return filepath.Clean(home)
	}

	return string(filepath.Separator)
}

func resolveProcessUserHomeDir() string {
	home, err := FileUserHomeDirFn()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(home)
}

func resolveDesktopSessionHomeDir(session DesktopSessionInfo) string {
	if username := strings.TrimSpace(session.Username); username != "" {
		if usr, err := FileLookupUserByUsernameFn(username); err == nil {
			if home := strings.TrimSpace(usr.HomeDir); home != "" {
				return home
			}
		}
	}
	if session.UID > 0 {
		if usr, err := FileLookupUserByUIDFn(fmt.Sprintf("%d", session.UID)); err == nil {
			if home := strings.TrimSpace(usr.HomeDir); home != "" {
				return home
			}
		}
	}
	return ""
}

// IsWritableDirectory checks whether path is an existing writable directory.
func IsWritableDirectory(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	probe, err := os.CreateTemp(path, ".labtether-write-check-*")
	if err != nil {
		return false
	}
	probePath := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probePath) // #nosec G703 -- Temp probe path comes from os.CreateTemp and is package-controlled.
	return true
}

// FilesystemRootForPath returns the filesystem root for a given path.
func FilesystemRootForPath(path string) string {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	volume := filepath.VolumeName(cleaned)
	if volume != "" {
		return volume + string(filepath.Separator)
	}
	return string(filepath.Separator)
}

// ValidatePath resolves and validates a path, preventing traversal attacks.
// The resolved path must remain under BaseDir.
func (fm *Manager) ValidatePath(rawPath string) (string, error) {
	if rawPath == "" {
		rawPath = fm.BaseDir
	}

	// Expand ~ to home directory.
	if strings.HasPrefix(rawPath, "~/") || rawPath == "~" {
		home := strings.TrimSpace(fm.HomeDir)
		if home == "" {
			home = strings.TrimSpace(ResolveAgentFileHomeDir())
		}
		if home == "" {
			return "", fmt.Errorf("cannot resolve home directory")
		}
		rawPath = filepath.Join(home, strings.TrimPrefix(rawPath, "~"))
	}

	// Make absolute.
	if !filepath.IsAbs(rawPath) {
		rawPath = filepath.Join(fm.BaseDir, rawPath)
	}

	cleaned := filepath.Clean(rawPath)

	// Resolve baseDir symlinks first so path containment checks are performed on
	// canonical paths.
	resolvedBase := resolveBaseForContainment(fm.BaseDir)

	resolved := cleaned
	if info, statErr := os.Lstat(cleaned); statErr == nil && info != nil {
		// Resolve full target path when it exists. This blocks symlink escapes
		// where the final path component points outside baseDir.
		resolvedTarget, evalErr := filepath.EvalSymlinks(cleaned)
		if evalErr != nil {
			return "", fmt.Errorf("resolve path %q: %w", cleaned, evalErr)
		}
		resolved = resolvedTarget
	} else if statErr == nil {
		// Should never happen, but keep a deterministic fallback.
		resolved = cleaned
	} else if errors.Is(statErr, os.ErrNotExist) {
		// For new targets, resolve the deepest existing parent first. A direct
		// EvalSymlinks(parent) can fail when later parent segments do not exist
		// yet, which must not hide an earlier symlink escape.
		resolvedParent, evalErr := resolveParentForContainment(cleaned)
		if evalErr != nil {
			return "", evalErr
		}
		resolved = filepath.Join(resolvedParent, filepath.Base(cleaned))
	} else {
		return "", fmt.Errorf("stat path %q: %w", cleaned, statErr)
	}

	if !PathWithinBaseDir(resolvedBase, resolved) {
		return "", fmt.Errorf("path %q is outside the allowed base directory", rawPath)
	}

	return resolved, nil
}

// ValidatePathNoFollowFinal validates containment like ValidatePath but returns
// the lexical target path instead of the final symlink target. Mutating
// operations use this so deleting, renaming, or overwriting a symlink acts on
// the link itself rather than the file or directory it points to.
func (fm *Manager) ValidatePathNoFollowFinal(rawPath string) (string, error) {
	if rawPath == "" {
		rawPath = fm.BaseDir
	}
	if strings.HasPrefix(rawPath, "~/") || rawPath == "~" {
		home := strings.TrimSpace(fm.HomeDir)
		if home == "" {
			home = strings.TrimSpace(ResolveAgentFileHomeDir())
		}
		if home == "" {
			return "", fmt.Errorf("cannot resolve home directory")
		}
		rawPath = filepath.Join(home, strings.TrimPrefix(rawPath, "~"))
	}
	if !filepath.IsAbs(rawPath) {
		rawPath = filepath.Join(fm.BaseDir, rawPath)
	}

	cleaned := filepath.Clean(rawPath)
	resolvedBase := resolveBaseForContainment(fm.BaseDir)
	if cleaned == filepath.Clean(fm.BaseDir) {
		return cleaned, nil
	}

	resolvedParent, parentErr := resolveParentForContainment(cleaned)
	if parentErr != nil {
		return "", parentErr
	}
	containmentPath := filepath.Join(resolvedParent, filepath.Base(cleaned))
	if _, statErr := os.Lstat(cleaned); statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("stat path %q: %w", cleaned, statErr)
	}

	if !PathWithinBaseDir(resolvedBase, containmentPath) {
		return "", fmt.Errorf("path %q is outside the allowed base directory", rawPath)
	}
	return cleaned, nil
}

// OpenRootPath converts an operator path to a lexical path beneath BaseDir and
// opens an os.Root for race-safe filesystem access. os.Root resolves every
// component relative to an open directory handle and refuses symlink targets
// outside the root, closing the validation/open TOCTOU window present in plain
// filepath.EvalSymlinks followed by os.Open.
func (fm *Manager) OpenRootPath(rawPath string) (*os.Root, string, string, error) {
	if rawPath == "" {
		rawPath = fm.BaseDir
	}
	if strings.HasPrefix(rawPath, "~/") || rawPath == "~" {
		home := strings.TrimSpace(fm.HomeDir)
		if home == "" {
			home = strings.TrimSpace(ResolveAgentFileHomeDir())
		}
		if home == "" {
			return nil, "", "", fmt.Errorf("cannot resolve home directory")
		}
		rawPath = filepath.Join(home, strings.TrimPrefix(rawPath, "~"))
	}
	if !filepath.IsAbs(rawPath) {
		rawPath = filepath.Join(fm.BaseDir, rawPath)
	}

	base := filepath.Clean(fm.BaseDir)
	displayPath := filepath.Clean(rawPath)
	rel, err := filepath.Rel(base, displayPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", "", fmt.Errorf("path %q is outside the allowed base directory", rawPath)
	}
	if rel == "" {
		rel = "."
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, "", "", fmt.Errorf("open file root: %w", err)
	}
	return root, rel, displayPath, nil
}

func resolveParentForContainment(cleaned string) (string, error) {
	return resolveExistingPathForContainment(filepath.Dir(cleaned))
}

func resolveBaseForContainment(baseDir string) string {
	cleaned := filepath.Clean(baseDir)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return resolved
	}
	if resolved, err := resolveExistingPathForContainment(cleaned); err == nil {
		return resolved
	}
	return cleaned
}

func resolveExistingPathForContainment(path string) (string, error) {
	current := filepath.Clean(path)
	missing := []string{}
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, evalErr := filepath.EvalSymlinks(current)
			if evalErr != nil {
				return "", fmt.Errorf("resolve path %q: %w", current, evalErr)
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("stat path %q: %w", current, err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			return current, nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

// PathWithinBaseDir checks whether path is within baseDir.
func PathWithinBaseDir(baseDir, path string) bool {
	baseDir = filepath.Clean(baseDir)
	path = filepath.Clean(path)

	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
