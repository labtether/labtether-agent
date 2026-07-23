package releasecontract

import (
	"bytes"
	"crypto/ed25519"
	"debug/buildinfo"
	"debug/elf"
	"debug/pe"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var goVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+(\.[0-9]+)?([A-Za-z0-9.-]+)?$`)

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

func BuildManifest(
	stage, tag, commit string,
	publicKey ed25519.PublicKey,
) (Manifest, []byte, error) {
	var manifest Manifest
	if err := ValidateTag(tag); err != nil {
		return manifest, nil, err
	}
	if err := ValidateCommit(commit); err != nil {
		return manifest, nil, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return manifest, nil, errors.New("release verification requires the pinned Ed25519 public key")
	}
	resolvedStage, err := ValidateStage(stage)
	if err != nil {
		return manifest, nil, err
	}
	assetsDir, err := validateAssetDirectory(resolvedStage)
	if err != nil {
		return manifest, nil, err
	}
	controlDir, err := validateControlDirectory(resolvedStage)
	if err != nil {
		return manifest, nil, err
	}
	buildRecord, err := readBuildRecord(
		filepath.Join(controlDir, "build.json"),
		tag,
		commit,
	)
	if err != nil {
		return manifest, nil, err
	}

	specs, err := AssetSpecs(tag)
	if err != nil {
		return manifest, nil, err
	}
	if err := validateExactAssetSet(assetsDir, specs); err != nil {
		return manifest, nil, err
	}
	digests := make(map[string]AssetDigest, len(specs))
	for _, target := range Targets() {
		rawPath := filepath.Join(assetsDir, target.RawName)
		rawDigest, err := verifyRawBinary(
			rawPath,
			target,
			buildRecord.BuilderGoVersion,
		)
		if err != nil {
			return manifest, nil, fmt.Errorf("verify %s: %w", target.RawName, err)
		}
		recorded := findDigest(buildRecord.RawBinaries, target.RawName)
		if recorded.Name == "" ||
			recorded.SHA256 != rawDigest.SHA256 ||
			recorded.SizeBytes != rawDigest.SizeBytes {
			return manifest, nil, fmt.Errorf(
				"raw binary %s no longer matches the immutable build record",
				target.RawName,
			)
		}
		digests[target.RawName] = rawDigest
		if err := verifyChecksumFile(
			filepath.Join(assetsDir, target.RawName+".sha256"),
			rawDigest,
		); err != nil {
			return manifest, nil, err
		}
		if err := verifySignedMetadata(
			assetsDir,
			tag,
			target,
			rawDigest,
			publicKey,
		); err != nil {
			return manifest, nil, err
		}
		if target.IsLinux {
			archiveName := target.RawName + "-" + tag + ".tar.gz"
			archivePath := filepath.Join(assetsDir, archiveName)
			if err := VerifyDeterministicArchive(
				archivePath,
				rawPath,
				target.RawName,
			); err != nil {
				return manifest, nil, fmt.Errorf("verify %s: %w", archiveName, err)
			}
			archiveDigest, err := HashRegularFile(archivePath, MaxArchiveBytes)
			if err != nil {
				return manifest, nil, err
			}
			digests[archiveName] = archiveDigest
			if err := verifyChecksumFile(
				filepath.Join(assetsDir, archiveName+".sha256"),
				archiveDigest,
			); err != nil {
				return manifest, nil, err
			}
		}
	}

	var ordered []AssetDigest
	for _, spec := range specs {
		digest, exists := digests[spec.Name]
		if !exists {
			maxBytes := MaxSmallAssetBytes
			if spec.Kind == AssetRaw {
				maxBytes = MaxRawBinaryBytes
			} else if spec.Kind == AssetArchive {
				maxBytes = MaxArchiveBytes
			}
			digest, err = HashRegularFile(filepath.Join(assetsDir, spec.Name), maxBytes)
			if err != nil {
				return manifest, nil, fmt.Errorf("hash %s: %w", spec.Name, err)
			}
		}
		ordered = append(ordered, digest)
	}
	manifest = Manifest{
		Schema:           ManifestSchema,
		Tag:              tag,
		Commit:           commit,
		BuilderGoVersion: buildRecord.BuilderGoVersion,
		Assets:           ordered,
	}
	encoded, err := MarshalDeterministic(manifest)
	if err != nil {
		return Manifest{}, nil, err
	}
	return manifest, encoded, nil
}

func SealManifest(
	stage, tag, commit string,
	publicKey ed25519.PublicKey,
) (Manifest, error) {
	manifest, encoded, err := BuildManifest(stage, tag, commit, publicKey)
	if err != nil {
		return Manifest{}, err
	}
	controlDir, err := validateControlDirectory(stage)
	if err != nil {
		return Manifest{}, err
	}
	if err := WriteNoReplace(
		filepath.Join(controlDir, "release-manifest.json"),
		encoded,
		0o600,
	); err != nil {
		return Manifest{}, fmt.Errorf("seal release manifest: %w", err)
	}
	return manifest, nil
}

func VerifySealedManifest(
	stage, tag, commit string,
	publicKey ed25519.PublicKey,
) (Manifest, string, error) {
	manifest, expected, err := BuildManifest(stage, tag, commit, publicKey)
	if err != nil {
		return Manifest{}, "", err
	}
	controlDir, err := validateControlDirectory(stage)
	if err != nil {
		return Manifest{}, "", err
	}
	path := filepath.Join(controlDir, "release-manifest.json")
	if _, err := EnsureRegularFile(path, MaxSmallAssetBytes); err != nil {
		return Manifest{}, "", fmt.Errorf("inspect sealed release manifest: %w", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, "", err
	}
	if !bytes.Equal(actual, expected) {
		return Manifest{}, "", errors.New("sealed release manifest does not match current exact assets")
	}
	return manifest, DigestBytes(actual), nil
}

func verifyRawBinary(
	path string,
	target Target,
	builderGoVersion string,
) (AssetDigest, error) {
	digest, err := HashRegularFile(path, MaxRawBinaryBytes)
	if err != nil {
		return AssetDigest{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return AssetDigest{}, err
	}
	magic := make([]byte, len(target.ExeMagic))
	_, readErr := io.ReadFull(file, magic)
	_ = file.Close()
	if readErr != nil || !bytes.Equal(magic, target.ExeMagic) {
		return AssetDigest{}, errors.New("binary has the wrong executable format")
	}
	if err := verifyExecutableArchitecture(path, target); err != nil {
		return AssetDigest{}, err
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return AssetDigest{}, fmt.Errorf("read Go build info: %w", err)
	}
	if info.Path != MainPackagePath || info.Main.Path != ModulePath {
		return AssetDigest{}, errors.New("binary was not built from the expected Go main package")
	}
	if info.GoVersion != builderGoVersion {
		return AssetDigest{}, fmt.Errorf(
			"binary Go version %q does not match build record %q",
			info.GoVersion,
			builderGoVersion,
		)
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	for key, expected := range map[string]string{
		"GOOS":        target.OS,
		"GOARCH":      target.Arch,
		"CGO_ENABLED": "0",
		"-trimpath":   "true",
		"-buildmode":  "exe",
		"-compiler":   "gc",
	} {
		if settings[key] != expected {
			return AssetDigest{}, fmt.Errorf(
				"binary build setting %s=%q, want %q",
				key,
				settings[key],
				expected,
			)
		}
	}
	return digest, nil
}

func verifyExecutableArchitecture(path string, target Target) error {
	switch target.OS {
	case "linux":
		file, err := elf.Open(path)
		if err != nil {
			return fmt.Errorf("parse ELF binary: %w", err)
		}
		defer file.Close()
		expected := elf.EM_X86_64
		if target.Arch == "arm64" {
			expected = elf.EM_AARCH64
		}
		if file.FileHeader.Machine != expected {
			return fmt.Errorf(
				"ELF machine %s does not match %s",
				file.FileHeader.Machine,
				target.Arch,
			)
		}
	case "windows":
		file, err := pe.Open(path)
		if err != nil {
			return fmt.Errorf("parse PE binary: %w", err)
		}
		defer file.Close()
		expected := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
		if target.Arch == "arm64" {
			expected = pe.IMAGE_FILE_MACHINE_ARM64
		}
		if file.FileHeader.Machine != expected {
			return fmt.Errorf(
				"PE machine %#x does not match %s",
				file.FileHeader.Machine,
				target.Arch,
			)
		}
	default:
		return fmt.Errorf("unsupported release target OS %q", target.OS)
	}
	return nil
}

func verifySignedMetadata(
	assetsDir, tag string,
	target Target,
	rawDigest AssetDigest,
	publicKey ed25519.PublicKey,
) error {
	prefix := target.RawName + "-" + tag
	metadataPath := filepath.Join(assetsDir, prefix+".metadata.json")
	if _, err := EnsureRegularFile(metadataPath, MaxSmallAssetBytes); err != nil {
		return fmt.Errorf("inspect %s metadata: %w", target.RawName, err)
	}
	file, err := os.Open(metadataPath)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(file, MaxSmallAssetBytes+1))
	decoder.DisallowUnknownFields()
	var metadata SignedMetadata
	decodeErr := decoder.Decode(&metadata)
	if decodeErr == nil {
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			decodeErr = errors.New("metadata contains trailing JSON")
		}
	}
	_ = file.Close()
	if decodeErr != nil {
		return fmt.Errorf("decode %s metadata: %w", target.RawName, decodeErr)
	}
	if metadata.Version != tag || metadata.OS != target.OS ||
		metadata.Arch != target.Arch ||
		metadata.SHA256 != rawDigest.SHA256 ||
		metadata.SizeBytes != rawDigest.SizeBytes {
		return fmt.Errorf("%s metadata does not match its exact release binary", target.RawName)
	}
	if err := ValidateDigest(metadata.SHA256); err != nil {
		return fmt.Errorf("%s metadata digest: %w", target.RawName, err)
	}
	signature, err := base64.StdEncoding.DecodeString(metadata.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%s metadata has an invalid Ed25519 signature", target.RawName)
	}
	if !ed25519.Verify(publicKey, []byte(CanonicalPayload(metadata)), signature) {
		return fmt.Errorf("%s metadata signature does not verify with the pinned key", target.RawName)
	}
	sigPath := filepath.Join(assetsDir, prefix+".sig")
	if _, err := EnsureRegularFile(sigPath, MaxSmallAssetBytes); err != nil {
		return fmt.Errorf("inspect %s detached signature: %w", target.RawName, err)
	}
	detached, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	if string(detached) != metadata.Signature+"\n" {
		return fmt.Errorf("%s detached signature differs from signed metadata", target.RawName)
	}
	return nil
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

func readBuildRecord(path, tag, commit string) (BuildRecord, error) {
	var record BuildRecord
	if _, err := EnsureRegularFile(path, MaxSmallAssetBytes); err != nil {
		return record, fmt.Errorf("inspect build record: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, MaxSmallAssetBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return BuildRecord{}, fmt.Errorf("decode build record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return BuildRecord{}, errors.New("build record contains trailing JSON")
	}
	if record.Schema != BuildRecordSchema || record.Tag != tag ||
		record.Commit != commit || !goVersionPattern.MatchString(record.BuilderGoVersion) {
		return BuildRecord{}, errors.New("build record identity does not match the exact release")
	}
	if len(record.RawBinaries) != len(Targets()) {
		return BuildRecord{}, errors.New("build record does not contain exactly four raw binaries")
	}
	seen := make(map[string]struct{})
	for _, digest := range record.RawBinaries {
		if _, duplicate := seen[digest.Name]; duplicate {
			return BuildRecord{}, errors.New("build record contains duplicate raw binaries")
		}
		seen[digest.Name] = struct{}{}
		if err := ValidateDigest(digest.SHA256); err != nil || digest.SizeBytes <= 0 {
			return BuildRecord{}, errors.New("build record contains an invalid raw binary digest")
		}
	}
	return record, nil
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

func findDigest(digests []AssetDigest, name string) AssetDigest {
	for _, digest := range digests {
		if digest.Name == name {
			return digest
		}
	}
	return AssetDigest{}
}

func ManifestAsset(manifest Manifest, name string) (AssetDigest, bool) {
	for _, asset := range manifest.Assets {
		if asset.Name == name {
			return asset, true
		}
	}
	return AssetDigest{}, false
}

func ParseManifest(path string) (Manifest, []byte, error) {
	var manifest Manifest
	if _, err := EnsureRegularFile(path, MaxSmallAssetBytes); err != nil {
		return manifest, nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return manifest, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, nil, errors.New("release manifest contains trailing JSON")
	}
	if manifest.Schema != ManifestSchema {
		return Manifest{}, nil, errors.New("release manifest has an unknown schema")
	}
	specs, err := AssetSpecs(manifest.Tag)
	if err != nil {
		return Manifest{}, nil, err
	}
	if err := ValidateCommit(manifest.Commit); err != nil ||
		!goVersionPattern.MatchString(manifest.BuilderGoVersion) ||
		len(manifest.Assets) != len(specs) {
		return Manifest{}, nil, errors.New("release manifest identity is invalid")
	}
	for index, spec := range specs {
		asset := manifest.Assets[index]
		if asset.Name != spec.Name || ValidateDigest(asset.SHA256) != nil ||
			asset.SizeBytes <= 0 {
			return Manifest{}, nil, errors.New("release manifest asset contract is invalid")
		}
	}
	expected, err := MarshalDeterministic(manifest)
	if err != nil {
		return Manifest{}, nil, err
	}
	if !bytes.Equal(content, expected) {
		return Manifest{}, nil, errors.New("release manifest is not canonically encoded")
	}
	return manifest, content, nil
}

func AssetPaths(stage string, manifest Manifest) ([]string, error) {
	resolved, err := ValidateStage(stage)
	if err != nil {
		return nil, err
	}
	assetsDir, err := validateAssetDirectory(resolved)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, asset := range manifest.Assets {
		if !ValidSafeBaseName(asset.Name) {
			return nil, errors.New("manifest contains an unsafe asset filename")
		}
		paths = append(paths, filepath.Join(assetsDir, asset.Name))
	}
	return paths, nil
}

func CheckManifestDigest(path, expected string) error {
	if err := ValidateDigest(expected); err != nil {
		return err
	}
	_, content, err := ParseManifest(path)
	if err != nil {
		return err
	}
	if DigestBytes(content) != strings.ToLower(expected) {
		return errors.New("release manifest digest does not match")
	}
	return nil
}
