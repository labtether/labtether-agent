package backends

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	// RunLinuxPackageInventoryCommand is replaceable by tests. The production
	// implementation enforces both timeout and retained-output bounds.
	RunLinuxPackageInventoryCommand = RunPackageInventoryCommand
	aptUpgradeLinePattern           = regexp.MustCompile(`^Inst\s+(\S+)\s+\[([^\]]+)\]\s+\((\S+)`)
)

// ListUpgradablePackages lists updates through the detected native manager.
// Every command is read-only, time bounded, and output bounded.
func (LinuxPackageBackend) ListUpgradablePackages() ([]UpgradablePackageInfo, error) {
	manager, err := DetectLinuxPackageManagerFn()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), PackageInventoryCommandTimeout)
	defer cancel()

	var packages []UpgradablePackageInfo
	switch manager {
	case "apt-get":
		out, runErr := RunLinuxPackageInventoryCommand(ctx, manager, "--just-print", "upgrade")
		if err := packageInventoryCommandError(ctx, manager, "upgradable package listing", out, runErr); err != nil {
			return nil, err
		}
		packages, err = ParseAPTUpgradablePackages(out)
	case "dnf", "yum":
		out, runErr := RunLinuxPackageInventoryCommand(ctx, manager, "check-update", "--quiet")
		if err := packageInventoryCommandError(ctx, manager, "upgradable package listing", out, runErr, 100); err != nil {
			return nil, err
		}
		installedOut, installedErr := RunLinuxPackageInventoryCommand(ctx, "rpm", "-qa", "--queryformat", "%{NAME}.%{ARCH}\t%{VERSION}-%{RELEASE}\n")
		if err := packageInventoryCommandError(ctx, "rpm", "installed package lookup", installedOut, installedErr); err != nil {
			return nil, err
		}
		packages, err = ParseDNFUpgradablePackages(out, installedOut)
	case "zypper":
		out, runErr := RunLinuxPackageInventoryCommand(ctx, manager, "--non-interactive", "list-updates")
		if err := packageInventoryCommandError(ctx, manager, "upgradable package listing", out, runErr); err != nil {
			return nil, err
		}
		packages, err = ParseZypperUpgradablePackages(out)
	case "pacman":
		out, runErr := RunLinuxPackageInventoryCommand(ctx, manager, "-Qu")
		// pacman exits 1 when no updates are available.
		if err := packageInventoryCommandError(ctx, manager, "upgradable package listing", out, runErr, 1); err != nil {
			return nil, err
		}
		packages, err = ParsePacmanUpgradablePackages(out)
	case "apk":
		out, runErr := RunLinuxPackageInventoryCommand(ctx, manager, "version", "-l", "<")
		if err := packageInventoryCommandError(ctx, manager, "upgradable package listing", out, runErr); err != nil {
			return nil, err
		}
		packages, err = ParseAPKUpgradablePackages(out)
	default:
		return nil, fmt.Errorf("upgradable package listing is not supported for %s", manager)
	}
	if err != nil {
		return nil, err
	}
	return normalizeUpgradablePackages(packages)
}

// ParseAPTUpgradablePackages parses apt-get's simulated upgrade plan:
// "Inst package [current] (available repository ...)".
func ParseAPTUpgradablePackages(out []byte) ([]UpgradablePackageInfo, error) {
	packages := make([]UpgradablePackageInfo, 0)
	recognized := len(bytes.TrimSpace(out)) == 0
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Reading package lists") || strings.HasPrefix(line, "Calculating upgrade") || strings.Contains(line, " upgraded,") {
			recognized = true
		}
		matches := aptUpgradeLinePattern.FindStringSubmatch(line)
		if len(matches) != 4 {
			continue
		}
		recognized = true
		packages = append(packages, UpgradablePackageInfo{
			Name:             matches[1],
			Version:          matches[2],
			AvailableVersion: matches[3],
		})
		if len(packages) > MaxPackageInventoryItems {
			return nil, fmt.Errorf("upgradable package inventory exceeds %d entries", MaxPackageInventoryItems)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse apt upgradable packages: %w", err)
	}
	if !recognized {
		return nil, fmt.Errorf("unrecognized apt upgradable package output")
	}
	return packages, nil
}

// ParseDNFUpgradablePackages joins dnf/yum's available versions to a bounded
// rpm inventory so every result contains both current and available versions.
func ParseDNFUpgradablePackages(updates, installed []byte) ([]UpgradablePackageInfo, error) {
	currentByName := make(map[string]string)
	installedScanner := bufio.NewScanner(bytes.NewReader(installed))
	for installedScanner.Scan() {
		fields := strings.SplitN(strings.TrimSpace(installedScanner.Text()), "\t", 2)
		if len(fields) == 2 && fields[0] != "" && fields[1] != "" {
			currentByName[fields[0]] = fields[1]
		}
		if len(currentByName) > MaxPackageInventoryItems*4 {
			return nil, fmt.Errorf("installed rpm lookup exceeds safe entry limit")
		}
	}
	if err := installedScanner.Err(); err != nil {
		return nil, fmt.Errorf("parse installed rpm packages: %w", err)
	}
	if len(bytes.TrimSpace(installed)) > 0 && len(currentByName) == 0 {
		return nil, fmt.Errorf("unrecognized installed rpm package output")
	}

	packages := make([]UpgradablePackageInfo, 0)
	recognized := len(bytes.TrimSpace(updates)) == 0
	updatesScanner := bufio.NewScanner(bytes.NewReader(updates))
	for updatesScanner.Scan() {
		line := strings.TrimSpace(updatesScanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Last metadata expiration check:") || line == "Obsoleting Packages" {
			recognized = true
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("unrecognized dnf upgradable package output")
		}
		recognized = true
		if strings.HasPrefix(fields[0], "Last") || strings.HasPrefix(fields[0], "Obsoleting") {
			continue
		}
		current := currentByName[fields[0]]
		if current == "" {
			// DNF may omit architecture in one side of the join.
			base := fields[0]
			if dot := strings.LastIndex(base, "."); dot > 0 {
				for installedName, version := range currentByName {
					if strings.HasPrefix(installedName, base[:dot]+".") {
						current = version
						break
					}
				}
			}
		}
		if current == "" {
			continue
		}
		packages = append(packages, UpgradablePackageInfo{
			Name:             fields[0],
			Version:          current,
			AvailableVersion: fields[1],
		})
		if len(packages) > MaxPackageInventoryItems {
			return nil, fmt.Errorf("upgradable package inventory exceeds %d entries", MaxPackageInventoryItems)
		}
	}
	if err := updatesScanner.Err(); err != nil {
		return nil, fmt.Errorf("parse dnf upgradable packages: %w", err)
	}
	if !recognized {
		return nil, fmt.Errorf("unrecognized dnf upgradable package output")
	}
	return packages, nil
}

// ParseZypperUpgradablePackages parses the pipe-delimited list-updates table.
func ParseZypperUpgradablePackages(out []byte) ([]UpgradablePackageInfo, error) {
	packages := make([]UpgradablePackageInfo, 0)
	nameIndex, currentIndex, availableIndex := -1, -1, -1
	noUpdates := false
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(strings.ToLower(line), "no updates found") {
			noUpdates = true
			continue
		}
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		parts := strings.Split(line, "|")
		for index := range parts {
			parts[index] = strings.TrimSpace(parts[index])
		}
		if nameIndex < 0 {
			for index, field := range parts {
				switch strings.ToLower(field) {
				case "name":
					nameIndex = index
				case "current version":
					currentIndex = index
				case "available version":
					availableIndex = index
				}
			}
			continue
		}
		if nameIndex >= len(parts) || currentIndex >= len(parts) || availableIndex >= len(parts) {
			continue
		}
		name := parts[nameIndex]
		current := parts[currentIndex]
		available := parts[availableIndex]
		if name == "" || current == "" || available == "" {
			continue
		}
		packages = append(packages, UpgradablePackageInfo{Name: name, Version: current, AvailableVersion: available})
		if len(packages) > MaxPackageInventoryItems {
			return nil, fmt.Errorf("upgradable package inventory exceeds %d entries", MaxPackageInventoryItems)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse zypper upgradable packages: %w", err)
	}
	if nameIndex < 0 && !noUpdates && len(bytes.TrimSpace(out)) > 0 {
		return nil, fmt.Errorf("unrecognized zypper upgradable package output")
	}
	return packages, nil
}

// ParsePacmanUpgradablePackages parses `pacman -Qu` output.
func ParsePacmanUpgradablePackages(out []byte) ([]UpgradablePackageInfo, error) {
	packages := make([]UpgradablePackageInfo, 0)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) != 4 || fields[2] != "->" {
			return nil, fmt.Errorf("unrecognized pacman upgradable package output")
		}
		packages = append(packages, UpgradablePackageInfo{Name: fields[0], Version: fields[1], AvailableVersion: fields[3]})
		if len(packages) > MaxPackageInventoryItems {
			return nil, fmt.Errorf("upgradable package inventory exceeds %d entries", MaxPackageInventoryItems)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse pacman upgradable packages: %w", err)
	}
	return packages, nil
}

// ParseAPKUpgradablePackages parses `apk version -l '<'` output.
func ParseAPKUpgradablePackages(out []byte) ([]UpgradablePackageInfo, error) {
	packages := make([]UpgradablePackageInfo, 0)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 3 || fields[1] != "<" {
			return nil, fmt.Errorf("unrecognized apk upgradable package output")
		}
		matches := apkPackageVersionPattern.FindStringSubmatch(fields[0])
		if len(matches) != 3 {
			return nil, fmt.Errorf("unrecognized apk package name/version %q", fields[0])
		}
		packages = append(packages, UpgradablePackageInfo{Name: matches[1], Version: matches[2], AvailableVersion: fields[2]})
		if len(packages) > MaxPackageInventoryItems {
			return nil, fmt.Errorf("upgradable package inventory exceeds %d entries", MaxPackageInventoryItems)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse apk upgradable packages: %w", err)
	}
	return packages, nil
}
