package agentcore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

var errPowerUnsupported = errors.New("power action unsupported")

type powerBackend interface {
	Supported(action powerAction) bool
	Execute(ctx context.Context, action powerAction) error
}

type powerCommandRunner interface {
	Run(ctx context.Context, executable string, args ...string) error
}

type execPowerCommandRunner struct{}

func (execPowerCommandRunner) Run(ctx context.Context, executable string, args ...string) error {
	// Executable and args are selected exclusively from fixed platform tables.
	// No shell is involved and no wire-provided value reaches the command line.
	cmd := exec.CommandContext(ctx, executable, args...) // #nosec G204 -- executable and argv come from fixed powerCommandForPlatform cases.
	return cmd.Run()
}

type powerCommandSpec struct {
	executable string
	args       []string
}

type commandPowerBackend struct {
	goos       string
	systemRoot string
	runner     powerCommandRunner
}

func newPlatformPowerBackend() powerBackend {
	return &commandPowerBackend{
		goos:       runtime.GOOS,
		systemRoot: os.Getenv("SystemRoot"),
		runner:     execPowerCommandRunner{},
	}
}

func (b *commandPowerBackend) Supported(action powerAction) bool {
	if b == nil || b.runner == nil {
		return false
	}
	spec, err := powerCommandForPlatform(b.goos, b.systemRoot, action)
	if err != nil {
		return false
	}
	info, err := os.Stat(spec.executable)
	return err == nil && !info.IsDir()
}

func (b *commandPowerBackend) Execute(ctx context.Context, action powerAction) error {
	if b == nil || b.runner == nil {
		return errPowerUnsupported
	}
	spec, err := powerCommandForPlatform(b.goos, b.systemRoot, action)
	if err != nil {
		return err
	}
	return b.runner.Run(ctx, spec.executable, spec.args...)
}

// powerCommandForPlatform is the complete command allowlist for typed power
// actions. Keep this table closed: never accept an executable or argument from
// a hub message.
func powerCommandForPlatform(goos, systemRoot string, action powerAction) (powerCommandSpec, error) {
	if !action.valid() {
		return powerCommandSpec{}, errPowerUnsupported
	}

	switch strings.ToLower(strings.TrimSpace(goos)) {
	case "linux":
		verb := "reboot"
		if action == powerActionShutdown {
			verb = "poweroff"
		}
		return powerCommandSpec{executable: "/usr/bin/systemctl", args: []string{verb, "--no-wall"}}, nil
	case "darwin":
		flag := "-r"
		if action == powerActionShutdown {
			flag = "-h"
		}
		return powerCommandSpec{executable: "/sbin/shutdown", args: []string{flag, "now"}}, nil
	case "freebsd":
		flag := "-r"
		if action == powerActionShutdown {
			flag = "-p"
		}
		return powerCommandSpec{executable: "/sbin/shutdown", args: []string{flag, "now"}}, nil
	case "windows":
		executable, err := windowsShutdownExecutable(systemRoot)
		if err != nil {
			return powerCommandSpec{}, errPowerUnsupported
		}
		flag := "/r"
		comment := "LabTether requested reboot"
		if action == powerActionShutdown {
			flag = "/s"
			comment = "LabTether requested shutdown"
		}
		return powerCommandSpec{
			executable: executable,
			args:       []string{flag, "/t", "5", "/d", "p:4:1", "/c", comment},
		}, nil
	default:
		return powerCommandSpec{}, errPowerUnsupported
	}
}

func windowsShutdownExecutable(systemRoot string) (string, error) {
	root := strings.ReplaceAll(strings.TrimSpace(systemRoot), "/", `\`)
	if root == "" {
		root = `C:\Windows`
	}
	root = strings.TrimRight(root, `\`)
	if len(root) < 3 || !isASCIIAlpha(root[0]) || root[1] != ':' || root[2] != '\\' {
		return "", fmt.Errorf("invalid SystemRoot")
	}
	for _, component := range strings.Split(root[3:], `\`) {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("invalid SystemRoot")
		}
	}
	return root + `\System32\shutdown.exe`, nil
}

func isASCIIAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}
