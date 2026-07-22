package backends

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/labtether/labtether-agent/internal/agentcore/packagepolicy"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

const (
	PackageInventoryInstalled  = "installed"
	PackageInventoryUpgradable = "upgradable"

	MaxPackageInventoryItems        = 10_000
	MaxPackageInventoryOutputBytes  = 2 * 1024 * 1024
	MaxPackageInventoryPayloadBytes = 8 * 1024 * 1024
	MaxPackageInventoryVersionBytes = 1_024
	PackageInventoryCommandTimeout  = 45 * time.Second
)

// RunPackageInventoryCommand executes a read-only package-manager query with
// a strict capture ceiling. Platform tests replace it through their scoped
// runner variables rather than invoking the host package manager.
func RunPackageInventoryCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd, err := securityruntime.NewCommandContext(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	// Parsers consume stable machine-oriented English output. Override locale
	// for this child only; Windows package managers ignore these variables.
	env := cmd.Env[:0]
	for _, entry := range cmd.Env {
		if strings.HasPrefix(entry, "LC_ALL=") ||
			strings.HasPrefix(entry, "LANG=") ||
			strings.HasPrefix(entry, "HOMEBREW_NO_AUTO_UPDATE=") ||
			strings.HasPrefix(entry, "HOMEBREW_NO_ANALYTICS=") {
			continue
		}
		env = append(env, entry)
	}
	cmd.Env = append(env,
		"LC_ALL=C",
		"LANG=C",
		"HOMEBREW_NO_AUTO_UPDATE=1",
		"HOMEBREW_NO_ANALYTICS=1",
	)
	return securityruntime.CaptureCombinedOutput(cmd, MaxPackageInventoryOutputBytes)
}

func normalizeUpgradablePackages(packages []UpgradablePackageInfo) ([]UpgradablePackageInfo, error) {
	if len(packages) > MaxPackageInventoryItems {
		return nil, fmt.Errorf("upgradable package inventory exceeds %d entries", MaxPackageInventoryItems)
	}

	normalized := make([]UpgradablePackageInfo, 0, len(packages))
	seen := make(map[string]struct{}, len(packages))
	for index, item := range packages {
		name := strings.TrimSpace(item.Name)
		validated, err := packagepolicy.NormalizeAndValidate([]string{name})
		if err != nil || len(validated) != 1 {
			return nil, fmt.Errorf("upgradable package entry %d has an invalid name", index+1)
		}
		name = validated[0]
		current := strings.TrimSpace(item.Version)
		available := strings.TrimSpace(item.AvailableVersion)
		if err := validatePackageVersion(current); err != nil {
			return nil, fmt.Errorf("upgradable package %q current version: %w", name, err)
		}
		if err := validatePackageVersion(available); err != nil {
			return nil, fmt.Errorf("upgradable package %q available version: %w", name, err)
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, UpgradablePackageInfo{
			Name:             name,
			Version:          current,
			AvailableVersion: available,
			Status:           PackageInventoryUpgradable,
		})
	}

	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Name < normalized[j].Name
	})
	return normalized, nil
}

func validateInstalledPackageInventory(packages []protocol.PackageInfo) error {
	if len(packages) > MaxPackageInventoryItems {
		return fmt.Errorf("installed package inventory exceeds %d entries", MaxPackageInventoryItems)
	}
	for index, item := range packages {
		if err := validatePackageInventoryText(item.Name, 1_024, true); err != nil {
			return fmt.Errorf("installed package entry %d name: %w", index+1, err)
		}
		if err := validatePackageInventoryText(item.Version, MaxPackageInventoryVersionBytes, false); err != nil {
			return fmt.Errorf("installed package entry %d version: %w", index+1, err)
		}
		if err := validatePackageInventoryText(item.Status, 256, false); err != nil {
			return fmt.Errorf("installed package entry %d status: %w", index+1, err)
		}
	}
	return nil
}

func validatePackageInventoryText(value string, maxBytes int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return errors.New("is required")
	}
	if !utf8.ValidString(value) {
		return errors.New("is not valid UTF-8")
	}
	if len(value) > maxBytes {
		return fmt.Errorf("exceeds %d bytes", maxBytes)
	}
	if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("contains a control character")
	}
	return nil
}

func validatePackageVersion(value string) error {
	return validatePackageInventoryText(value, MaxPackageInventoryVersionBytes, true)
}

func packageInventoryCommandError(ctx context.Context, manager, operation string, output []byte, err error, acceptedExitCodes ...int) error {
	if err == nil {
		return nil
	}
	if ctx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s %s timed out", manager, operation)
	}
	if errors.Is(err, securityruntime.ErrCommandOutputLimit) {
		return fmt.Errorf("%s %s output exceeded %d bytes", manager, operation, MaxPackageInventoryOutputBytes)
	}
	for _, accepted := range acceptedExitCodes {
		if exitCode(err) == accepted {
			return nil
		}
	}
	trimmed := strings.TrimSpace(string(output))
	if len(trimmed) > 4_096 {
		trimmed = trimmed[:4_096] + "..."
	}
	if trimmed != "" {
		return fmt.Errorf("%s %s failed: %s", manager, operation, trimmed)
	}
	return fmt.Errorf("%s %s failed: %w", manager, operation, err)
}

type exitCoder interface {
	ExitCode() int
}

func exitCode(err error) int {
	var coded exitCoder
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return -1
}
