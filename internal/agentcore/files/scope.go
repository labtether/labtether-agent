package files

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// fileScope is the set of directories that file requests may reach.
type fileScope struct {
	base  string   // where "" and relative paths resolve
	home  string   // where "~" resolves
	roots []string // base first, then every other fixed drive in full mode on Windows
}

// scopedPath is a request path opened beneath the allowed root that holds it.
type scopedPath struct {
	root    *os.Root
	base    string // the allowed root that holds the path
	rel     string // the path relative to base
	display string // the clean absolute path shown to the Hub
}

// rootsForMode returns the extra roots a file root mode adds to the base
// directory. Full mode covers every fixed local drive on Windows; elsewhere
// the filesystem root already covers every mount.
func rootsForMode(fileRootMode string) func() []string {
	if strings.TrimSpace(strings.ToLower(fileRootMode)) != "full" {
		return nil
	}
	return fixedDriveRoots
}

// SetRootMode switches between home and full access while the agent runs.
// Later requests use the new scope at once. Uploads still in progress are
// stopped, so none of them finishes outside the new scope.
func (fm *Manager) SetRootMode(fileRootMode string) {
	mode := strings.TrimSpace(strings.ToLower(fileRootMode))
	homeDir := ResolveAgentFileHomeDir()
	fm.scopeMu.Lock()
	if fm.rootMode == mode {
		fm.scopeMu.Unlock()
		return
	}
	fm.rootMode = mode
	fm.BaseDir = ResolveFileBaseDirWithHome(mode, homeDir)
	fm.HomeDir = homeDir
	fm.extraRoots = rootsForMode(mode)
	base := fm.BaseDir
	fm.scopeMu.Unlock()
	fm.CloseAll()
	log.Printf("file: access scope is now %s (%s)", mode, base)
}

func (fm *Manager) scope() fileScope {
	fm.scopeMu.RLock()
	base, home, extraRoots := fm.BaseDir, fm.HomeDir, fm.extraRoots
	fm.scopeMu.RUnlock()
	scope := fileScope{base: base, home: home}
	scope.roots = []string{filepath.Clean(base)}
	if extraRoots != nil {
		for _, root := range extraRoots() {
			if root == "" || scope.isRoot(root) {
				continue
			}
			scope.roots = append(scope.roots, filepath.Clean(root))
		}
	}
	return scope
}

// expand turns a request path into a clean absolute path: "" is the base
// directory, "~" the home directory, and a relative path sits under base.
func (s fileScope) expand(rawPath string) (string, error) {
	if rawPath == "" {
		rawPath = s.base
	}
	if strings.HasPrefix(rawPath, "~/") || rawPath == "~" {
		home := s.home
		if home == "" {
			home = ResolveAgentFileHomeDir()
		}
		if home == "" {
			return "", fmt.Errorf("cannot resolve home directory")
		}
		rawPath = filepath.Join(home, strings.TrimPrefix(rawPath, "~"))
	}
	if !filepath.IsAbs(rawPath) {
		rawPath = filepath.Join(s.base, rawPath)
	}
	return filepath.Clean(rawPath), nil
}

// rootFor returns the allowed root that holds path, and path relative to it.
func (s fileScope) rootFor(path string) (string, string, bool) {
	for _, base := range s.roots {
		rel, err := filepath.Rel(base, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return base, rel, true
	}
	return "", "", false
}

// isRoot reports whether path is one of the allowed roots itself.
func (s fileScope) isRoot(path string) bool {
	for _, root := range s.roots {
		if sameRoot(root, path) {
			return true
		}
	}
	return false
}

// containsResolved reports whether a symlink-resolved path stays inside one
// of the allowed roots, comparing against each root's resolved form.
func (s fileScope) containsResolved(resolved string) bool {
	for _, root := range s.roots {
		if PathWithinBaseDir(resolveBaseForContainment(root), resolved) {
			return true
		}
	}
	return false
}

func sameRoot(left, right string) bool {
	rel, err := filepath.Rel(filepath.Clean(left), filepath.Clean(right))
	return err == nil && rel == "."
}

// openScopedPath opens the allowed root that holds rawPath. Every access goes
// through the returned os.Root, so a symlink cannot lead outside that root.
func (fm *Manager) openScopedPath(rawPath string) (scopedPath, error) {
	scope := fm.scope()
	display, err := scope.expand(rawPath)
	if err != nil {
		return scopedPath{}, err
	}
	base, rel, ok := scope.rootFor(display)
	if !ok {
		return scopedPath{}, fmt.Errorf("path %q is outside the allowed base directory", display)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return scopedPath{}, fmt.Errorf("open file root: %w", err)
	}
	return scopedPath{root: root, base: base, rel: rel, display: display}, nil
}
