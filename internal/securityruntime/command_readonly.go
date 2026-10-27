package securityruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// The shell allowlist runs commands as the agent's account (root or SYSTEM)
// for Hub paths that are not full terminal access: action keys, MCP exec and
// quick commands. These checks keep the allowlisted readers read-only and
// away from secrets: journalctl may not rotate, vacuum or write files, and
// cat, head, tail and grep may not read the agent's own credentials or
// common system secrets.

var journalctlChangingOptions = []string{
	"--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush",
	"--sync", "--relinquish-var", "--smart-relinquish-var", "--setup-keys",
	"--update-catalog", "--cursor-file",
}

var builtinProtectedReadPaths = []string{
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-",
	"/etc/sudoers", "/etc/sudoers.d", "/etc/master.passwd", "/etc/spwd.db",
}

var protectedReadPathsState struct {
	sync.RWMutex
	paths []string
}

// SetProtectedReadPaths records files and folders that allowlisted file
// readers must never read, such as the agent token and its state folder.
func SetProtectedReadPaths(paths ...string) {
	cleaned := make([]string, 0, len(paths))
	for _, path := range paths {
		if path = strings.TrimSpace(path); path != "" && filepath.IsAbs(path) {
			cleaned = append(cleaned, filepath.Clean(path))
		}
	}
	protectedReadPathsState.Lock()
	protectedReadPathsState.paths = cleaned
	protectedReadPathsState.Unlock()
}

// validateReadOnlyCommand applies the read-only rules to an allowlisted
// command line.
func validateReadOnlyCommand(args []string) error {
	name := normalizeExecutableName(args[0])
	switch name {
	case "journalctl":
		for _, arg := range args[1:] {
			option := strings.ToLower(strings.SplitN(arg, "=", 2)[0])
			for _, changing := range journalctlChangingOptions {
				if option == changing {
					return fmt.Errorf("journalctl %s changes system logs and is not allowed here", changing)
				}
			}
		}
	case "cat", "head", "tail", "grep":
		for index, arg := range args[1:] {
			if name == "grep" && grepArgRecurses(arg, args[1:], index) {
				return fmt.Errorf("recursive grep is not allowed here")
			}
			for _, candidate := range readerPathCandidates(name, arg) {
				if readPathProtected(candidate) {
					return fmt.Errorf("reading %s is not allowed here", candidate)
				}
			}
		}
	}
	return nil
}

// readerPathCandidates returns the values in arg that a reader may open: a
// plain argument, the value of --option=VALUE, and the file of grep -fFILE.
func readerPathCandidates(name, arg string) []string {
	if !strings.HasPrefix(arg, "-") {
		return []string{arg}
	}
	if index := strings.IndexByte(arg, '='); index >= 0 {
		return []string{arg[index+1:]}
	}
	if name == "grep" && !strings.HasPrefix(arg, "--") {
		if index := strings.IndexByte(arg, 'f'); index > 0 && index+1 < len(arg) {
			return []string{arg[index+1:]}
		}
	}
	return nil
}

// grepArgRecurses reports whether a grep argument turns on recursion:
// -r, -R, --recursive, --dereference-recursive or -d/--directories recurse.
func grepArgRecurses(arg string, args []string, index int) bool {
	switch {
	case arg == "--recursive" || arg == "--dereference-recursive":
		return true
	case strings.HasPrefix(arg, "--directories"):
		value := strings.TrimPrefix(strings.TrimPrefix(arg, "--directories"), "=")
		if value == "" && index+1 < len(args) {
			value = args[index+1]
		}
		return value == "recurse"
	case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--"):
		for position, flag := range arg[1:] {
			switch flag {
			case 'r', 'R':
				return true
			case 'd':
				value := arg[position+2:]
				if value == "" && index+1 < len(args) {
					value = args[index+1]
				}
				return value == "recurse"
			case 'e', 'f', 'm', 'A', 'B', 'C', 'D':
				return false // the rest of the argument is this option's value
			}
		}
	}
	return false
}

func readPathProtected(candidate string) bool {
	if candidate == "" || candidate == "-" {
		return false
	}
	path := candidate
	if !filepath.IsAbs(path) {
		if wd, err := os.Getwd(); err == nil {
			path = filepath.Join(wd, path)
		}
	}
	path = filepath.Clean(path)
	targets := []string{path}
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
		targets = append(targets, resolved)
	}

	protectedReadPathsState.RLock()
	roots := append(append([]string(nil), builtinProtectedReadPaths...), protectedReadPathsState.paths...)
	protectedReadPathsState.RUnlock()
	for _, root := range roots {
		rootTargets := []string{root}
		if resolved, err := filepath.EvalSymlinks(root); err == nil && resolved != root {
			rootTargets = append(rootTargets, resolved)
		}
		for _, target := range targets {
			for _, rootTarget := range rootTargets {
				if pathWithin(target, rootTarget) {
					return true
				}
			}
		}
	}
	for _, target := range targets {
		if secretPathByName(target) {
			return true
		}
	}
	return false
}

// secretPathByName matches secrets found by name anywhere: SSH private keys
// and the environment or memory of any process (the agent's own environment
// can hold its credentials).
func secretPathByName(path string) bool {
	slashed := filepath.ToSlash(path)
	base := filepath.Base(slashed)
	parent := filepath.Base(filepath.Dir(slashed))
	switch {
	case strings.HasPrefix(slashed, "/proc/") && (base == "environ" || base == "mem"):
		return true
	case strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key"):
		return true
	case parent == ".ssh" && strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub"):
		return true
	}
	return false
}

func pathWithin(path, root string) bool {
	if runtime.GOOS == "windows" {
		path, root = strings.ToLower(path), strings.ToLower(root)
	}
	return path == root || strings.HasPrefix(path, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
}
