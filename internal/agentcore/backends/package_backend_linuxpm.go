package backends

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/labtether/labtether-agent/internal/agentcore/packagepolicy"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// LinuxPackageBackend implements inventory and actions for supported native
// Linux package managers.
type LinuxPackageBackend struct{}

// PackageActionCommand represents a single package manager command to run.
type PackageActionCommand struct {
	Name string
	Args []string
}

var (
	// LinuxPackageLookPath is the function used to find package managers. Overridable for tests.
	LinuxPackageLookPath = exec.LookPath
	// LinuxPackageDpkgLister collects packages via dpkg. Overridable for tests.
	LinuxPackageDpkgLister = collectLinuxPackagesDpkg
	// LinuxPackageRPMLister collects packages via rpm. Overridable for tests.
	LinuxPackageRPMLister = collectLinuxPackagesRPM
	// LinuxPackagePacmanLister collects packages via pacman. Overridable for tests.
	LinuxPackagePacmanLister = collectLinuxPackagesPacman
	// LinuxPackageAPKLister collects packages via apk. Overridable for tests.
	LinuxPackageAPKLister = collectLinuxPackagesAPK
	// DetectLinuxPackageManagerFn detects the available package manager. Overridable for tests.
	DetectLinuxPackageManagerFn = DetectLinuxPackageManager
	// BuildLinuxPackageActionCommandsFn builds the command list for a package action. Overridable for tests.
	BuildLinuxPackageActionCommandsFn = BuildLinuxPackageActionCommands
	// RunLinuxPackageCommand runs a package command. Overridable for tests.
	RunLinuxPackageCommand = securityruntime.CommandContextCombinedOutput
	// DetectLinuxRebootRequiredFn checks if a reboot is required. Overridable for tests.
	DetectLinuxRebootRequiredFn = DetectLinuxRebootRequired
	// LinuxPackageStat is the function used to stat files. Overridable for tests.
	LinuxPackageStat = os.Stat
	// NewLinuxPackageCommand creates a new command. Overridable for tests.
	NewLinuxPackageCommand = securityruntime.NewCommand
)

// ListPackages lists installed Linux packages using the native package database.
func (LinuxPackageBackend) ListPackages() ([]protocol.PackageInfo, error) {
	// Prefer the inventory database associated with the detected action manager.
	// This avoids reporting a secondary RPM database on Arch/Alpine hosts where
	// the rpm utility happens to be installed alongside pacman/apk.
	if manager, err := DetectLinuxPackageManagerFn(); err == nil {
		switch manager {
		case "apt-get":
			if path, lookErr := LinuxPackageLookPath("dpkg-query"); lookErr == nil && path != "" {
				return LinuxPackageDpkgLister()
			}
		case "dnf", "yum", "zypper":
			if path, lookErr := LinuxPackageLookPath("rpm"); lookErr == nil && path != "" {
				return LinuxPackageRPMLister()
			}
		case "pacman":
			return LinuxPackagePacmanLister()
		case "apk":
			return LinuxPackageAPKLister()
		}
	}

	// Retain direct database fallbacks for minimal systems where only the query
	// utility is present.
	if path, err := LinuxPackageLookPath("dpkg-query"); err == nil && path != "" {
		return LinuxPackageDpkgLister()
	}
	if path, err := LinuxPackageLookPath("rpm"); err == nil && path != "" {
		return LinuxPackageRPMLister()
	}
	if path, err := LinuxPackageLookPath("pacman"); err == nil && path != "" {
		return LinuxPackagePacmanLister()
	}
	if path, err := LinuxPackageLookPath("apk"); err == nil && path != "" {
		return LinuxPackageAPKLister()
	}
	return nil, ErrNoLinuxPackageManager
}

// PerformAction performs a Linux package action (install, remove, upgrade).
func (LinuxPackageBackend) PerformAction(action string, packages []string) (PackageActionResult, error) {
	pkgManager, err := DetectLinuxPackageManagerFn()
	if err != nil {
		return PackageActionResult{}, err
	}
	commands, err := BuildLinuxPackageActionCommandsFn(pkgManager, action, packages)
	if err != nil {
		return PackageActionResult{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), PackageActionCommandTimeout)
	defer cancel()

	// Retain one byte past the result limit so the existing formatter can add
	// its truncation marker, while draining all package-manager output.
	combined := securityruntime.NewCappedRetainingWriter(MaxCommandOutputBytes + 1)
	for _, command := range commands {
		out, runErr := RunLinuxPackageCommand(ctx, command.Name, command.Args...)
		if combined.Len() > 0 && len(out) > 0 {
			if err := combined.WriteByte('\n'); err != nil {
				return PackageActionResult{}, fmt.Errorf("buffer package output: %w", err)
			}
		}
		if _, err := combined.Write(out); err != nil {
			return PackageActionResult{}, fmt.Errorf("buffer package output: %w", err)
		}
		result := PackageActionResult{
			Output:         TruncateCommandOutput(combined.Bytes(), MaxCommandOutputBytes),
			RebootRequired: DetectLinuxRebootRequiredFn(),
		}
		if runErr != nil {
			if errors.Is(runErr, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
				return result, fmt.Errorf("package action timed out")
			}
			return result, runErr
		}
	}

	return PackageActionResult{
		Output:         TruncateCommandOutput(combined.Bytes(), MaxCommandOutputBytes),
		RebootRequired: DetectLinuxRebootRequiredFn(),
	}, nil
}

// BuildLinuxPackageActionCommands builds the list of commands for a package action.
func BuildLinuxPackageActionCommands(manager, action string, packages []string) ([]PackageActionCommand, error) {
	args, err := buildLinuxPackageActionArgs(manager, action, packages)
	if err != nil {
		return nil, err
	}

	commands := []PackageActionCommand{{
		Name: manager,
		Args: args,
	}}
	if manager == "apt-get" && (action == "install" || action == "upgrade") {
		commands = append([]PackageActionCommand{{
			Name: manager,
			Args: []string{"update"},
		}}, commands...)
	}
	return commands, nil
}

// DetectLinuxPackageManager detects the available Linux package manager.
func DetectLinuxPackageManager() (string, error) {
	for _, candidate := range []string{"apt-get", "dnf", "yum", "zypper", "pacman", "apk"} {
		if path, err := LinuxPackageLookPath(candidate); err == nil && path != "" {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no supported package manager found")
}

func buildLinuxPackageActionArgs(manager, action string, packages []string) ([]string, error) {
	normalizedPackages, err := packagepolicy.NormalizeAndValidate(packages)
	if err != nil {
		return nil, err
	}
	packages = normalizedPackages

	switch manager {
	case "apt-get":
		switch action {
		case "install":
			return append([]string{"-y", "install", "--"}, packages...), nil
		case "remove":
			return append([]string{"-y", "remove", "--"}, packages...), nil
		case "upgrade":
			if len(packages) > 0 {
				return append([]string{"-y", "install", "--only-upgrade", "--"}, packages...), nil
			}
			return []string{"-y", "upgrade"}, nil
		}
	case "dnf", "yum":
		switch action {
		case "install":
			return append([]string{"-y", "install"}, packages...), nil
		case "remove":
			return append([]string{"-y", "remove"}, packages...), nil
		case "upgrade":
			if len(packages) > 0 {
				return append([]string{"-y", "upgrade"}, packages...), nil
			}
			return []string{"-y", "upgrade"}, nil
		}
	case "zypper":
		switch action {
		case "install":
			return append([]string{"--non-interactive", "install"}, packages...), nil
		case "remove":
			return append([]string{"--non-interactive", "remove"}, packages...), nil
		case "upgrade":
			if len(packages) > 0 {
				return append([]string{"--non-interactive", "update"}, packages...), nil
			}
			return []string{"--non-interactive", "update"}, nil
		}
	case "pacman":
		switch action {
		case "install":
			return append([]string{"--noconfirm", "-S", "--"}, packages...), nil
		case "remove":
			return append([]string{"--noconfirm", "-R", "--"}, packages...), nil
		case "upgrade":
			if len(packages) > 0 {
				return append([]string{"--noconfirm", "-S", "--"}, packages...), nil
			}
			return []string{"--noconfirm", "-Syu"}, nil
		}
	case "apk":
		switch action {
		case "install":
			return append([]string{"add"}, packages...), nil
		case "remove":
			return append([]string{"del"}, packages...), nil
		case "upgrade":
			if len(packages) > 0 {
				return append([]string{"add", "--upgrade"}, packages...), nil
			}
			return []string{"upgrade"}, nil
		}
	}
	return nil, fmt.Errorf("unsupported package action for %s", manager)
}

// DetectLinuxRebootRequired checks if a reboot is required on Linux.
func DetectLinuxRebootRequired() bool {
	if _, err := LinuxPackageStat("/run/reboot-required"); err == nil {
		return true
	}
	if _, err := LinuxPackageStat("/var/run/reboot-required"); err == nil {
		return true
	}

	needsRestartPath, err := LinuxPackageLookPath("needs-restarting")
	if err == nil && needsRestartPath != "" {
		// Exit code 1 indicates reboot required.
		cmd, cmdErr := NewLinuxPackageCommand(needsRestartPath, "-r")
		if cmdErr != nil {
			return false
		}
		if runErr := cmd.Run(); runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				return true
			}
		}
	}

	return false
}

// ErrNoLinuxPackageManager is returned when no supported package manager is found.
var ErrNoLinuxPackageManager = &PackageError{Msg: "no supported package manager"}

// PackageError represents a package manager error.
type PackageError struct {
	Msg string
}

func (e *PackageError) Error() string { return e.Msg }

func collectLinuxPackagesDpkg() ([]protocol.PackageInfo, error) {
	out, err := securityruntime.CommandCombinedOutput("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Status}\n")
	if err != nil {
		return nil, err
	}

	var pkgs []protocol.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 3 {
			continue
		}

		// Status field from dpkg is like "install ok installed" — extract last word.
		statusParts := strings.Fields(fields[2])
		status := fields[2]
		if len(statusParts) > 0 {
			status = statusParts[len(statusParts)-1]
		}

		pkgs = append(pkgs, protocol.PackageInfo{
			Name:    fields[0],
			Version: fields[1],
			Status:  status,
		})
	}

	return pkgs, nil
}

func collectLinuxPackagesRPM() ([]protocol.PackageInfo, error) {
	out, err := securityruntime.CommandCombinedOutput("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\tinstalled\n")
	if err != nil {
		return nil, err
	}

	var pkgs []protocol.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 3 {
			continue
		}
		pkgs = append(pkgs, protocol.PackageInfo{
			Name:    fields[0],
			Version: fields[1],
			Status:  fields[2],
		})
	}

	return pkgs, nil
}

func collectLinuxPackagesPacman() ([]protocol.PackageInfo, error) {
	out, err := securityruntime.CommandCombinedOutput("pacman", "-Q")
	if err != nil {
		return nil, err
	}
	return ParsePacmanPackageList(out)
}

// ParsePacmanPackageList parses `pacman -Q` output ("name version" per line).
func ParsePacmanPackageList(out []byte) ([]protocol.PackageInfo, error) {
	var pkgs []protocol.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		pkgs = append(pkgs, protocol.PackageInfo{
			Name:    fields[0],
			Version: fields[1],
			Status:  "installed",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse pacman package list: %w", err)
	}
	return pkgs, nil
}

func collectLinuxPackagesAPK() ([]protocol.PackageInfo, error) {
	out, err := securityruntime.CommandCombinedOutput("apk", "info", "-v")
	if err != nil {
		return nil, err
	}
	return ParseAPKPackageList(out)
}

var apkPackageVersionPattern = regexp.MustCompile(`^(.+)-([0-9][0-9A-Za-z._+~:-]*(?:-r[0-9]+)?)$`)

// ParseAPKPackageList parses `apk info -v` output ("name-version" per line).
// Alpine package versions begin with a digit, which disambiguates the final
// package-name/version boundary even when the package name itself has dashes.
func ParseAPKPackageList(out []byte) ([]protocol.PackageInfo, error) {
	var pkgs []protocol.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := apkPackageVersionPattern.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		pkgs = append(pkgs, protocol.PackageInfo{
			Name:    matches[1],
			Version: matches[2],
			Status:  "installed",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse apk package list: %w", err)
	}
	return pkgs, nil
}
