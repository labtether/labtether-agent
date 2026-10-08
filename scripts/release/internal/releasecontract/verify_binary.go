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
)

var goVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+(\.[0-9]+)?([A-Za-z0-9.-]+)?$`)

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
