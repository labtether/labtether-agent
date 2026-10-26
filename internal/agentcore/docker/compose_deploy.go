package docker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/labtether/protocol"
)

const composeDeployFileName = "docker-compose.yml"

// composeStacksRoot holds the agent-managed directory of each deployed stack.
var composeStacksRoot = func() string { return filepath.Join(os.TempDir(), "labtether-stacks") }

var errComposeDeployDirectory = errors.New("config_dir must be the stack's managed directory or the working directory of its existing Compose project")

// prepareComposeDeploy writes Hub-supplied YAML to one fixed file name. The Hub
// may name a directory, but the agent writes only to the stack's private
// managed directory or the directory Docker already reports for that project.
func (dc *DockerCollector) prepareComposeDeploy(ctx context.Context, req protocol.DockerComposeActionData) (composeSelection, error) {
	name := req.StackName
	if !composeProjectName.MatchString(name) {
		return composeSelection{}, fmt.Errorf("invalid native Compose project name")
	}
	if strings.TrimSpace(req.ComposeYAML) == "" {
		return composeSelection{}, fmt.Errorf("compose_yaml is required")
	}
	root := composeStacksRoot()
	dir, managed := filepath.Join(root, name), true
	if req.ConfigDir != "" && !sameComposeDir(req.ConfigDir, dir) {
		existing, err := dc.existingComposeProjectDir(ctx, name)
		if err != nil || !sameComposeDir(req.ConfigDir, existing) {
			return composeSelection{}, errComposeDeployDirectory
		}
		dir, managed = existing, false
	}
	selected := composeSelection{Name: name, Dir: dir, Files: []string{filepath.Join(dir, composeDeployFileName)}}
	if len(req.ConfigFiles) != 0 && !stringSlicesEqual(selected.Files, req.ConfigFiles) {
		return selected, fmt.Errorf("deploy must select only its written Compose file")
	}
	if err := ctx.Err(); err != nil {
		return selected, err
	}
	if managed {
		for _, path := range []string{root, dir} {
			if err := ensurePrivateComposeDir(path); err != nil {
				return selected, err
			}
		}
	}
	return selected, writeComposeDeployFile(dir, []byte(req.ComposeYAML))
}

// sameComposeDir reports whether the Hub-named directory is dir. Besides an
// exact match, a clean absolute name may reach the same existing directory
// through symlinks, as macOS shows /var/folders as /private/var/folders. The
// caller still writes only to dir, never to the Hub's spelling, and a path
// that cannot be resolved matches only exactly.
func sameComposeDir(named, dir string) bool {
	if named == dir {
		return true
	}
	if !filepath.IsAbs(named) || filepath.Clean(named) != named {
		return false
	}
	namedReal, err := filepath.EvalSymlinks(named)
	if err != nil {
		return false
	}
	dirReal, err := filepath.EvalSymlinks(dir)
	return err == nil && namedReal == dirReal
}

// existingComposeProjectDir returns the working directory reported by the
// daemon labels of every container in the project, never a Hub-supplied path.
func (dc *DockerCollector) existingComposeProjectDir(ctx context.Context, name string) (string, error) {
	rows, err := dc.client.composeProjectContainers(ctx, name)
	if err != nil {
		return "", err
	}
	stacks := inferComposeStacks(rows)
	if len(stacks) != 1 || stacks[0].SelectionError != "" {
		return "", fmt.Errorf("Compose project labels are missing or inconsistent")
	}
	return stacks[0].ConfigDir, nil
}

// ensurePrivateComposeDir creates or accepts only a real directory that no other
// local account can change, so a pre-created shared-temp path cannot redirect
// or later replace the YAML that the agent hands to Compose.
func ensurePrivateComposeDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || !composeDirIsPrivate(info) {
		return fmt.Errorf("Compose stack directory %q is not a private agent-owned directory", path)
	}
	return nil
}

// writeComposeDeployFile writes inside dir through os.Root, which refuses any
// symlink or ".." that would leave it, and never replaces a non-regular file.
func writeComposeDeployFile(dir string, data []byte) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("Compose project directory is unavailable: %w", err)
	}
	defer root.Close()
	if info, err := root.Lstat(composeDeployFileName); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("existing %s is not a regular file", composeDeployFileName)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return root.WriteFile(composeDeployFileName, data, 0o600)
}
