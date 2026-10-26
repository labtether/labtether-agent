package docker

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// useComposeStacksRoot points managed deploys at a private test directory.
func useComposeStacksRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "stacks")
	old := composeStacksRoot
	composeStacksRoot = func() string { return root }
	t.Cleanup(func() { composeStacksRoot = old })
	return root
}

// The Hub may name a deploy directory, but YAML can only land in the stack's
// managed directory or the directory Docker already reports for that project.
func TestComposeDeployWritesOnlyManagedOrDiscoveredDirectory(t *testing.T) {
	root := useComposeStacksRoot(t)
	selected := composeTestSelection(t)
	dc, _, _ := composeFixture(t, selected, composeRows(selected))
	outside := t.TempDir()
	for _, tc := range []struct {
		name, stack, dir, want string
	}{
		{"managed default", "fresh", "", filepath.Join(root, "fresh")},
		{"managed explicit", "named", filepath.Join(root, "named"), filepath.Join(root, "named")},
		{"discovered project", selected.Name, selected.Dir, selected.Dir},
		{"arbitrary directory", selected.Name, outside, ""},
		{"traversal alias", selected.Name, selected.Dir + "/../" + filepath.Base(selected.Dir), ""},
		{"another project's directory", "other", selected.Dir, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := protocol.DockerComposeActionData{StackName: tc.stack, ConfigDir: tc.dir, ComposeYAML: "services: {}\n"}
			got, err := dc.prepareComposeDeploy(context.Background(), req)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("deploy accepted %q", tc.dir)
				}
				for _, dir := range []string{outside, selected.Dir} {
					if _, statErr := os.Lstat(filepath.Join(dir, composeDeployFileName)); !os.IsNotExist(statErr) {
						t.Fatalf("rejected deploy wrote into %s", dir)
					}
				}
				return
			}
			if err != nil || got.Dir != tc.want || len(got.Files) != 1 || got.Files[0] != filepath.Join(tc.want, composeDeployFileName) {
				t.Fatalf("deploy selection = %+v, %v", got, err)
			}
			if data, err := os.ReadFile(got.Files[0]); err != nil || string(data) != req.ComposeYAML {
				t.Fatalf("deploy YAML = %q, %v", data, err)
			}
			_ = os.Remove(got.Files[0])
		})
	}
}

// A pre-created shared directory or link must not redirect the root-owned write.
func TestComposeDeployRefusesRedirectedManagedPaths(t *testing.T) {
	for _, mode := range []string{"root-link", "stack-link", "file-link", "shared-root"} {
		t.Run(mode, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("POSIX links and modes")
			}
			root := useComposeStacksRoot(t)
			victim := filepath.Join(t.TempDir(), "victim.yml")
			if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "root-link":
				err = os.Symlink(t.TempDir(), root)
			case "stack-link":
				if err = os.Mkdir(root, 0o700); err == nil {
					err = os.Symlink(t.TempDir(), filepath.Join(root, "project"))
				}
			case "file-link":
				if err = os.MkdirAll(filepath.Join(root, "project"), 0o700); err == nil {
					err = os.Symlink(victim, filepath.Join(root, "project", composeDeployFileName))
				}
			case "shared-root":
				if err = os.Mkdir(root, 0o700); err == nil {
					err = os.Chmod(root, 0o777) // #nosec G302 -- negative fixture for a shared directory.
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			dc := NewDockerCollector("/tmp/docker.sock", newRecordingCollectorTransport(true), "host", time.Minute)
			req := protocol.DockerComposeActionData{StackName: "project", ComposeYAML: "services: {}\n"}
			if _, err := dc.prepareComposeDeploy(context.Background(), req); err == nil {
				t.Fatal("deploy followed a redirected managed path")
			}
			if data, err := os.ReadFile(victim); err != nil || string(data) != "keep" {
				t.Fatalf("victim changed: %q %v", data, err)
			}
		})
	}
}
