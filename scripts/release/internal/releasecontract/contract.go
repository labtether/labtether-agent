package releasecontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const (
	ManifestSchema       = "labtether-agent-release-manifest/v1"
	BuildRecordSchema    = "labtether-agent-release-build/v1"
	HostProofSchema      = "labtether-agent-host-proof/v1"
	InspectionSchema     = "labtether-agent-draft-inspection/v1"
	Repository           = "labtether/labtether-agent"
	ModulePath           = "github.com/labtether/labtether-agent"
	MainPackagePath      = ModulePath + "/cmd/labtether-agent"
	MaxRawBinaryBytes    = int64(100 * 1024 * 1024)
	MaxArchiveBytes      = int64(110 * 1024 * 1024)
	MaxSmallAssetBytes   = int64(1024 * 1024)
	MaxSourceArchiveSize = int64(256 * 1024 * 1024)
	MaxSourceFileSize    = int64(32 * 1024 * 1024)
	MaxSourceFiles       = 10000
)

var (
	strictTagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	commitPattern    = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	safeNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	safePathPattern  = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

type Target struct {
	OS       string
	Arch     string
	Suffix   string
	RawName  string
	IsLinux  bool
	ExeMagic []byte
}

type AssetKind string

const (
	AssetRaw      AssetKind = "raw"
	AssetChecksum AssetKind = "checksum"
	AssetSig      AssetKind = "signature"
	AssetMetadata AssetKind = "metadata"
	AssetArchive  AssetKind = "archive"
)

type AssetSpec struct {
	Name       string
	Kind       AssetKind
	Target     Target
	SourceName string
}

type AssetDigest struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type Manifest struct {
	Schema           string        `json:"schema"`
	Tag              string        `json:"tag"`
	Commit           string        `json:"commit"`
	BuilderGoVersion string        `json:"builder_go_version"`
	Assets           []AssetDigest `json:"assets"`
}

type BuildRecord struct {
	Schema           string        `json:"schema"`
	Tag              string        `json:"tag"`
	Commit           string        `json:"commit"`
	BuilderGoVersion string        `json:"builder_go_version"`
	RawBinaries      []AssetDigest `json:"raw_binaries"`
}

type SignedMetadata struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Signature string `json:"signature"`
}

func Targets() []Target {
	return []Target{
		{
			OS: "linux", Arch: "amd64", Suffix: "linux-amd64",
			RawName: "labtether-agent-linux-amd64", IsLinux: true,
			ExeMagic: []byte{0x7f, 'E', 'L', 'F'},
		},
		{
			OS: "linux", Arch: "arm64", Suffix: "linux-arm64",
			RawName: "labtether-agent-linux-arm64", IsLinux: true,
			ExeMagic: []byte{0x7f, 'E', 'L', 'F'},
		},
		{
			OS: "windows", Arch: "amd64", Suffix: "windows-amd64.exe",
			RawName:  "labtether-agent-windows-amd64.exe",
			ExeMagic: []byte{'M', 'Z'},
		},
		{
			OS: "windows", Arch: "arm64", Suffix: "windows-arm64.exe",
			RawName:  "labtether-agent-windows-arm64.exe",
			ExeMagic: []byte{'M', 'Z'},
		},
	}
}

func AssetSpecs(tag string) ([]AssetSpec, error) {
	if err := ValidateTag(tag); err != nil {
		return nil, err
	}
	var specs []AssetSpec
	for _, target := range Targets() {
		raw := target.RawName
		specs = append(specs,
			AssetSpec{Name: raw, Kind: AssetRaw, Target: target},
			AssetSpec{Name: raw + ".sha256", Kind: AssetChecksum, Target: target, SourceName: raw},
			AssetSpec{
				Name: raw + "-" + tag + ".sig", Kind: AssetSig,
				Target: target, SourceName: raw,
			},
			AssetSpec{
				Name: raw + "-" + tag + ".metadata.json", Kind: AssetMetadata,
				Target: target, SourceName: raw,
			},
		)
		if target.IsLinux {
			archive := raw + "-" + tag + ".tar.gz"
			specs = append(specs,
				AssetSpec{Name: archive, Kind: AssetArchive, Target: target, SourceName: raw},
				AssetSpec{
					Name: archive + ".sha256", Kind: AssetChecksum,
					Target: target, SourceName: archive,
				},
			)
		}
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	if len(specs) != 20 {
		return nil, fmt.Errorf("internal release contract has %d assets, want 20", len(specs))
	}
	return specs, nil
}

func ValidateTag(tag string) error {
	if !strictTagPattern.MatchString(tag) {
		return errors.New("release tag must use strict vX.Y.Z form")
	}
	return nil
}

func ValidateCommit(commit string) error {
	if !commitPattern.MatchString(commit) {
		return errors.New("release commit must be a lowercase 40- or 64-character Git object ID")
	}
	return nil
}

func ValidateDigest(digest string) error {
	if !digestPattern.MatchString(digest) {
		return errors.New("SHA-256 digest must be 64 lowercase hexadecimal characters")
	}
	return nil
}

func DecodePinnedPublicKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect pinned public key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("pinned public key must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > 512 {
		return nil, errors.New("pinned public key has an invalid size")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pinned public key: %w", err)
	}
	if strings.Count(string(encoded), "\n") > 1 {
		return nil, errors.New("pinned public key must contain exactly one line")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("pinned public key must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func CanonicalPayload(metadata SignedMetadata) string {
	return strings.Join([]string{
		metadata.Version,
		metadata.OS,
		metadata.Arch,
		strings.ToLower(metadata.SHA256),
		fmt.Sprintf("%d", metadata.SizeBytes),
	}, "\n")
}

func MarshalDeterministic(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func DigestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func ValidSafeBaseName(name string) bool {
	return len(name) > 0 && len(name) <= 240 &&
		safeNamePattern.MatchString(name) &&
		filepath.Base(name) == name &&
		name != "." && name != ".."
}

func ValidSafeSourcePath(name string) bool {
	if len(name) == 0 || len(name) > 1024 || !safePathPattern.MatchString(name) {
		return false
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") ||
		strings.Contains(name, `\`) || strings.Contains(name, "//") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	return clean == name && clean != "." && clean != ".." &&
		!strings.HasPrefix(clean, "../") && !strings.Contains(clean, "/../")
}

func RuntimePlatform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}
