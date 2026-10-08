package releasecontract

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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
