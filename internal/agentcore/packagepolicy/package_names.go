// Package packagepolicy defines the package-name validation shared by every
// agent path that can invoke an operating-system package manager.
package packagepolicy

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// MaxPackageCount bounds the amount of work a single remote request can
	// enqueue and is checked before duplicate entries are removed.
	MaxPackageCount = 128
	// MaxPackageNameBytes bounds each package-manager argument.
	MaxPackageNameBytes = 128
)

// NormalizeAndValidate trims surrounding whitespace, validates every package
// token, and removes exact duplicates while preserving request order. An empty
// slice is valid because update/upgrade requests use it to mean "all packages".
func NormalizeAndValidate(packages []string) ([]string, error) {
	if len(packages) > MaxPackageCount {
		return nil, fmt.Errorf("package list exceeds the maximum of %d entries", MaxPackageCount)
	}

	seen := make(map[string]struct{}, len(packages))
	normalized := make([]string, 0, len(packages))
	for index, raw := range packages {
		if strings.IndexFunc(raw, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("package entry %d contains a control character", index+1)
		}

		name := strings.TrimSpace(raw)
		if name == "" {
			return nil, fmt.Errorf("package entry %d is empty", index+1)
		}
		if len(name) > MaxPackageNameBytes {
			return nil, fmt.Errorf("package entry %d exceeds %d bytes", index+1, MaxPackageNameBytes)
		}
		if name[0] == '-' {
			return nil, fmt.Errorf("package %q must not begin with a hyphen", name)
		}
		if !validPackageName(name) {
			return nil, fmt.Errorf("package %q includes unsupported characters or path segments", name)
		}

		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	return normalized, nil
}

func validPackageName(name string) bool {
	for index := 0; index < len(name); index++ {
		char := name[index]
		if index == 0 {
			if !isASCIIAlphaNumeric(char) && char != '@' {
				return false
			}
			continue
		}
		if !isASCIIAlphaNumeric(char) && !strings.ContainsRune("@+._:/=~-", rune(char)) {
			return false
		}
	}

	// Slash-delimited names are needed for Homebrew taps and scoped/npm-style
	// packages, but filesystem/URL-shaped tokens are not package identifiers.
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	if strings.Contains(name, ":/") {
		return false
	}
	return true
}

func isASCIIAlphaNumeric(char byte) bool {
	return isASCIIAlpha(char) || (char >= '0' && char <= '9')
}

func isASCIIAlpha(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}
