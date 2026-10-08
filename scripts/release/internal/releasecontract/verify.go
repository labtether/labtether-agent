package releasecontract

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func PrepareUnsignedAssets(
	stage, tag, commit, builderGoVersion string,
) (BuildRecord, error) {
	var record BuildRecord
	if err := ValidateTag(tag); err != nil {
		return record, err
	}
	if err := ValidateCommit(commit); err != nil {
		return record, err
	}
	if !goVersionPattern.MatchString(builderGoVersion) {
		return record, errors.New("builder Go version has an invalid format")
	}
	resolvedStage, err := ValidateStage(stage)
	if err != nil {
		return record, err
	}
	assetsDir, err := validateAssetDirectory(resolvedStage)
	if err != nil {
		return record, err
	}
	expectedRaw := make(map[string]Target)
	for _, target := range Targets() {
		expectedRaw[target.RawName] = target
	}
	entries, err := os.ReadDir(assetsDir)
	if err != nil {
		return record, err
	}
	if len(entries) != len(expectedRaw) {
		return record, fmt.Errorf(
			"unsigned asset directory has %d entries, want exactly %d raw binaries",
			len(entries),
			len(expectedRaw),
		)
	}
	var rawDigests []AssetDigest
	for _, entry := range entries {
		target, exists := expectedRaw[entry.Name()]
		if !exists {
			return record, fmt.Errorf("unexpected unsigned asset %q", entry.Name())
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return record, fmt.Errorf("unsigned asset %q is not a regular file", entry.Name())
		}
		rawPath := filepath.Join(assetsDir, entry.Name())
		digest, verifyErr := verifyRawBinary(rawPath, target, builderGoVersion)
		if verifyErr != nil {
			return record, fmt.Errorf("verify %s: %w", entry.Name(), verifyErr)
		}
		rawDigests = append(rawDigests, digest)
	}
	sort.Slice(rawDigests, func(i, j int) bool {
		return rawDigests[i].Name < rawDigests[j].Name
	})

	for _, target := range Targets() {
		rawPath := filepath.Join(assetsDir, target.RawName)
		rawDigest := findDigest(rawDigests, target.RawName)
		if err := writeChecksumFile(
			filepath.Join(assetsDir, target.RawName+".sha256"),
			rawDigest,
		); err != nil {
			return record, err
		}
		if !target.IsLinux {
			continue
		}
		archiveName := target.RawName + "-" + tag + ".tar.gz"
		archivePath := filepath.Join(assetsDir, archiveName)
		if err := CreateDeterministicArchive(rawPath, archivePath, target.RawName); err != nil {
			return record, fmt.Errorf("create %s: %w", archiveName, err)
		}
		archiveDigest, err := HashRegularFile(archivePath, MaxArchiveBytes)
		if err != nil {
			return record, fmt.Errorf("hash %s: %w", archiveName, err)
		}
		if err := writeChecksumFile(
			filepath.Join(assetsDir, archiveName+".sha256"),
			archiveDigest,
		); err != nil {
			return record, err
		}
	}

	controlDir, err := ensureControlDirectory(resolvedStage)
	if err != nil {
		return record, err
	}
	record = BuildRecord{
		Schema:           BuildRecordSchema,
		Tag:              tag,
		Commit:           commit,
		BuilderGoVersion: builderGoVersion,
		RawBinaries:      rawDigests,
	}
	encoded, err := MarshalDeterministic(record)
	if err != nil {
		return BuildRecord{}, err
	}
	if err := WriteNoReplace(
		filepath.Join(controlDir, "build.json"),
		encoded,
		0o600,
	); err != nil {
		return BuildRecord{}, fmt.Errorf("write build record: %w", err)
	}
	return record, nil
}

func validateExactAssetSet(assetsDir string, specs []AssetSpec) error {
	expected := make(map[string]AssetSpec, len(specs))
	for _, spec := range specs {
		expected[spec.Name] = spec
	}
	entries, err := os.ReadDir(assetsDir)
	if err != nil {
		return err
	}
	if len(entries) != len(specs) {
		return fmt.Errorf("release assets contain %d entries, want exact 20", len(entries))
	}
	for _, entry := range entries {
		spec, exists := expected[entry.Name()]
		if !exists {
			return fmt.Errorf("unexpected release asset %q", entry.Name())
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("release asset %q is not a regular file", entry.Name())
		}
		maxBytes := MaxSmallAssetBytes
		if spec.Kind == AssetRaw {
			maxBytes = MaxRawBinaryBytes
		} else if spec.Kind == AssetArchive {
			maxBytes = MaxArchiveBytes
		}
		if _, err := EnsureRegularFile(filepath.Join(assetsDir, entry.Name()), maxBytes); err != nil {
			return fmt.Errorf("inspect release asset %q: %w", entry.Name(), err)
		}
	}
	return nil
}

func writeChecksumFile(path string, digest AssetDigest) error {
	content := []byte(digest.SHA256 + "  " + digest.Name + "\n")
	if err := WriteNoReplace(path, content, 0o644); err != nil {
		return fmt.Errorf("write checksum for %s: %w", digest.Name, err)
	}
	return nil
}

func verifyChecksumFile(path string, digest AssetDigest) error {
	if _, err := EnsureRegularFile(path, MaxSmallAssetBytes); err != nil {
		return fmt.Errorf("inspect checksum for %s: %w", digest.Name, err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	expected := digest.SHA256 + "  " + digest.Name + "\n"
	if string(content) != expected {
		return fmt.Errorf("checksum for %s violates the exact filename/content contract", digest.Name)
	}
	return nil
}

func validateAssetDirectory(stage string) (string, error) {
	path := filepath.Join(stage, "assets")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect asset directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("asset directory must be a non-symlink directory")
	}
	return path, nil
}

func ensureControlDirectory(stage string) (string, error) {
	path := filepath.Join(stage, ".release-control")
	if err := os.Mkdir(path, 0o700); err != nil {
		return "", fmt.Errorf("create release control directory: %w", err)
	}
	return path, nil
}

func validateControlDirectory(stage string) (string, error) {
	path := filepath.Join(stage, ".release-control")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect release control directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("release control directory must be a non-symlink directory")
	}
	return path, nil
}
