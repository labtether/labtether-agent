package backends

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/labtether/labtether-agent/internal/agentcore/packagepolicy"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"github.com/labtether/protocol"
)

// RunWindowsPackageCommand is the function used to run WinGet/choco commands. Overridable for tests.
var RunWindowsPackageCommand = securityruntime.CommandContextCombinedOutput

// RunWindowsPackageInventoryCommand runs read-only update inventory commands
// with the package inventory's tighter output ceiling. Overridable for tests.
var RunWindowsPackageInventoryCommand = RunPackageInventoryCommand

// WindowsPackageBackend implements PackageBackend using WinGet with Chocolatey fallback.
type WindowsPackageBackend struct {
	// backend is "winget" or "choco".
	backend string
}

// wingetPackageRow is an intermediate representation of a parsed WinGet table row.
type wingetPackageRow struct {
	name      string
	id        string
	version   string
	available string
}

// ListPackages lists installed packages via WinGet or Chocolatey.
func (b WindowsPackageBackend) ListPackages() ([]protocol.PackageInfo, error) {
	// WinGet is normally installed as a per-user app execution alias and is
	// therefore absent from the PATH and package state of a LocalSystem service.
	// The machine uninstall registry is the authoritative, non-interactive
	// inventory source for the Windows agent service. Package actions continue
	// to use the explicitly selected package manager below.
	if runtime.GOOS == "windows" {
		return listWindowsRegistryPackages()
	}

	ctx, cancel := context.WithTimeout(context.Background(), PackageActionCommandTimeout)
	defer cancel()

	switch b.backend {
	case "choco":
		out, err := RunWindowsPackageCommand(ctx, "choco", "list", "--local-only")
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("choco package listing timed out")
			}
			trimmed := strings.TrimSpace(string(out))
			if trimmed != "" {
				return nil, fmt.Errorf("choco package listing failed: %s", trimmed)
			}
			return nil, fmt.Errorf("choco package listing failed: %w", err)
		}
		return parseChocoListOutput(out)

	default: // "winget"
		out, err := RunWindowsPackageCommand(ctx, "winget", "list",
			"--accept-source-agreements", "--disable-interactivity")
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("winget package listing timed out")
			}
			trimmed := strings.TrimSpace(string(out))
			if trimmed != "" {
				return nil, fmt.Errorf("winget package listing failed: %s", trimmed)
			}
			return nil, fmt.Errorf("winget package listing failed: %w", err)
		}
		rows, parseErr := parseWinGetListOutput(out)
		if parseErr != nil {
			return nil, parseErr
		}
		pkgs := make([]protocol.PackageInfo, 0, len(rows))
		for _, row := range rows {
			pkgs = append(pkgs, protocol.PackageInfo{
				Name:    row.name,
				Version: row.version,
				Status:  "installed",
			})
		}
		return pkgs, nil
	}
}

// ListUpgradablePackages lists explicitly available WinGet or Chocolatey
// updates, including current and available versions.
func (b WindowsPackageBackend) ListUpgradablePackages() ([]UpgradablePackageInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), PackageInventoryCommandTimeout)
	defer cancel()

	var packages []UpgradablePackageInfo
	switch b.backend {
	case "choco":
		out, runErr := RunWindowsPackageInventoryCommand(ctx, "choco", "outdated", "--limit-output")
		// Chocolatey enhanced exit code 2 means outdated packages were found.
		if err := packageInventoryCommandError(ctx, "choco", "upgradable package listing", out, runErr, 2); err != nil {
			return nil, err
		}
		parsed, err := ParseChocoUpgradablePackages(out)
		if err != nil {
			return nil, err
		}
		packages = parsed
	default:
		out, runErr := RunWindowsPackageInventoryCommand(ctx, "winget", "upgrade",
			"--accept-source-agreements", "--disable-interactivity")
		if err := packageInventoryCommandError(ctx, "winget", "upgradable package listing", out, runErr); err != nil {
			return nil, err
		}
		rows, err := parseWinGetListOutput(out)
		if err != nil {
			return nil, err
		}
		lowerOutput := strings.ToLower(string(out))
		if len(rows) == 0 && len(bytes.TrimSpace(out)) > 0 &&
			!strings.Contains(lowerOutput, "no applicable upgrade") &&
			!strings.Contains(lowerOutput, "no installed package found") &&
			!(bytes.Contains(out, []byte("Name")) && bytes.Contains(out, []byte("Id")) && bytes.Contains(out, []byte("Version"))) {
			return nil, fmt.Errorf("unrecognized winget upgradable package output")
		}
		packages = make([]UpgradablePackageInfo, 0, len(rows))
		for _, row := range rows {
			name := strings.TrimSpace(row.id)
			if name == "" {
				name = strings.TrimSpace(row.name)
			}
			if name == "" || strings.TrimSpace(row.version) == "" || strings.TrimSpace(row.available) == "" {
				continue
			}
			packages = append(packages, UpgradablePackageInfo{
				Name:             name,
				Version:          row.version,
				AvailableVersion: row.available,
			})
		}
	}
	return normalizeUpgradablePackages(packages)
}

// PerformAction performs a package action (install, upgrade, uninstall) via WinGet or Chocolatey.
func (b WindowsPackageBackend) PerformAction(action string, packages []string) (PackageActionResult, error) {
	normalizedPackages, err := packagepolicy.NormalizeAndValidate(packages)
	if err != nil {
		return PackageActionResult{}, err
	}
	packages = normalizedPackages
	if len(packages) == 0 {
		return PackageActionResult{}, fmt.Errorf("no packages specified")
	}

	ctx, cancel := context.WithTimeout(context.Background(), PackageActionCommandTimeout)
	defer cancel()

	// A request may run one command per package. Keep the aggregate bounded
	// while continuing to drain every individual command result.
	combined := securityruntime.NewCappedRetainingWriter(MaxCommandOutputBytes + 1)

	for _, pkg := range packages {
		args, err := buildWindowsPackageActionArgs(b.backend, action, pkg)
		if err != nil {
			return PackageActionResult{}, err
		}

		var cmd string
		switch b.backend {
		case "choco":
			cmd = "choco"
		default:
			cmd = "winget"
		}

		out, runErr := RunWindowsPackageCommand(ctx, cmd, args...)
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
			RebootRequired: false,
		}
		if runErr != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return result, fmt.Errorf("package action timed out")
			}
			return result, runErr
		}
	}

	return PackageActionResult{
		Output:         TruncateCommandOutput(combined.Bytes(), MaxCommandOutputBytes),
		RebootRequired: false,
	}, nil
}

func buildWindowsPackageActionArgs(backend, action, pkg string) ([]string, error) {
	packages, err := packagepolicy.NormalizeAndValidate([]string{pkg})
	if err != nil {
		return nil, err
	}
	pkg = packages[0]

	switch backend {
	case "choco":
		switch action {
		case "install":
			return []string{"install", pkg, "-y"}, nil
		case "upgrade":
			return []string{"upgrade", pkg, "-y"}, nil
		case "uninstall", "remove":
			return []string{"uninstall", pkg, "-y"}, nil
		default:
			return nil, fmt.Errorf("unsupported package action %q for choco", action)
		}
	default: // winget
		switch action {
		case "install":
			return []string{"install", "--id", pkg,
				"--accept-package-agreements", "--accept-source-agreements", "--silent"}, nil
		case "upgrade":
			return []string{"upgrade", "--id", pkg,
				"--accept-package-agreements", "--accept-source-agreements", "--silent"}, nil
		case "uninstall", "remove":
			return []string{"uninstall", "--id", pkg, "--silent"}, nil
		default:
			return nil, fmt.Errorf("unsupported package action %q for winget", action)
		}
	}
}

// parseWinGetListOutput parses the fixed-width table output of
// `winget list --accept-source-agreements --disable-interactivity`.
//
// WinGet prints a header row, a separator row of dashes, then data rows. Each
// column is separated by two or more spaces; column widths are determined by
// the position of each header word.
func parseWinGetListOutput(raw []byte) ([]wingetPackageRow, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))

	// Find the header line that contains the column names.
	var headerLine string
	for scanner.Scan() {
		line := scanner.Text()
		// WinGet may prefix output with BOM or progress chars on some Windows
		// versions; strip leading non-ASCII noise.
		cleaned := strings.TrimLeftFunc(line, func(r rune) bool { return r > 127 })
		if strings.Contains(cleaned, "Name") && strings.Contains(cleaned, "Id") &&
			strings.Contains(cleaned, "Version") {
			headerLine = cleaned
			break
		}
	}
	if headerLine == "" {
		return nil, nil
	}

	// Derive column start positions from the header.
	nameStart, idStart, versionStart, availableStart := wingetColumnOffsets(headerLine)
	if idStart < 0 || versionStart < 0 {
		// Cannot locate required columns; return empty rather than corrupt data.
		return nil, nil
	}

	// Consume the separator line (dashes).
	if scanner.Scan() {
		sep := scanner.Text()
		if !strings.HasPrefix(strings.TrimSpace(sep), "-") {
			// Not a separator — put it back conceptually by re-checking below,
			// but since Scanner doesn't support unread we just ignore this edge case.
			_ = sep
		}
	}

	var rows []wingetPackageRow
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Pad the line so substring extractions are safe.
		row := extractWinGetRow(line, nameStart, idStart, versionStart, availableStart)
		if row.name == "" && row.id == "" {
			continue
		}
		rows = append(rows, row)
	}

	return rows, nil
}

// wingetColumnOffsets returns the byte offset of each column in the WinGet header.
// Returns -1 for columns that are not found.
func wingetColumnOffsets(header string) (nameStart, idStart, versionStart, availableStart int) {
	nameStart = strings.Index(header, "Name")
	idStart = strings.Index(header, "Id")
	versionStart = strings.Index(header, "Version")
	availableStart = strings.Index(header, "Available")
	return
}

// extractWinGetRow extracts fields from a single WinGet data row using column offsets.
func extractWinGetRow(line string, nameStart, idStart, versionStart, availableStart int) wingetPackageRow {
	safeSlice := func(s string, start, end int) string {
		if start < 0 || start >= len(s) {
			return ""
		}
		if end < 0 || end > len(s) {
			end = len(s)
		}
		return strings.TrimSpace(s[start:end])
	}

	name := safeSlice(line, nameStart, idStart)
	id := safeSlice(line, idStart, versionStart)

	var version, available string
	if availableStart >= 0 {
		version = safeSlice(line, versionStart, availableStart)
		// Everything after "Available" column start up to the "Source" column.
		// Source column is not critical; just read to end of line minus trailing
		// source token (e.g. "winget").
		rest := safeSlice(line, availableStart, -1)
		// The source token (e.g. "winget") is at the very end after whitespace.
		// Split on runs of spaces and take the non-source part.
		parts := strings.Fields(rest)
		if len(parts) >= 2 {
			// Last token is the source name; second-to-last or earlier is available.
			// WinGet sources are single-word identifiers; available version precedes it.
			available = parts[0]
		} else if len(parts) == 1 {
			// Could be just the source or just an available version — WinGet always
			// ends rows with the source name so a single token here is the source.
			available = ""
		}
	} else {
		version = safeSlice(line, versionStart, -1)
	}

	return wingetPackageRow{
		name:      name,
		id:        id,
		version:   version,
		available: available,
	}
}

// parseChocoListOutput parses the output of `choco list --local-only`.
//
// Format:
//
//	Chocolatey v1.4.0
//	<name> <version>
//	...
//	N packages installed.
func parseChocoListOutput(raw []byte) ([]protocol.PackageInfo, error) {
	var pkgs []protocol.PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Skip header/footer lines.
		if strings.HasPrefix(line, "Chocolatey v") ||
			strings.HasSuffix(line, "packages installed.") ||
			strings.HasSuffix(line, "package installed.") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkgs = append(pkgs, protocol.PackageInfo{
			Name:    fields[0],
			Version: fields[1],
			Status:  "installed",
		})
	}
	return pkgs, nil
}

// ParseChocoUpgradablePackages parses `choco outdated --limit-output` rows:
// package|current|available|pinned.
func ParseChocoUpgradablePackages(raw []byte) ([]UpgradablePackageInfo, error) {
	packages := make([]UpgradablePackageInfo, 0)
	recognized := len(bytes.TrimSpace(raw)) == 0
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)
		if line == "" || strings.HasPrefix(lower, "chocolatey ") || (strings.Contains(lower, "has determined") && strings.Contains(lower, "outdated")) {
			recognized = true
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 3 {
			return nil, fmt.Errorf("unrecognized choco outdated output")
		}
		recognized = true
		name := strings.TrimSpace(fields[0])
		current := strings.TrimSpace(fields[1])
		available := strings.TrimSpace(fields[2])
		if name == "" || current == "" || available == "" {
			return nil, fmt.Errorf("malformed choco outdated entry")
		}
		packages = append(packages, UpgradablePackageInfo{Name: name, Version: current, AvailableVersion: available})
		if len(packages) > MaxPackageInventoryItems {
			return nil, fmt.Errorf("upgradable package inventory exceeds %d entries", MaxPackageInventoryItems)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse choco outdated output: %w", err)
	}
	if !recognized {
		return nil, fmt.Errorf("unrecognized choco outdated output")
	}
	return packages, nil
}
