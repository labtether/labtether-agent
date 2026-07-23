package releasecontract

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type HostProof struct {
	Schema         string        `json:"schema"`
	Tag            string        `json:"tag"`
	Commit         string        `json:"commit"`
	ManifestSHA256 string        `json:"manifest_sha256"`
	Platform       string        `json:"platform"`
	HostArch       string        `json:"host_arch"`
	VerifiedAssets []AssetDigest `json:"verified_assets"`
	RuntimeAsset   string        `json:"runtime_asset"`
	RuntimeOutput  string        `json:"runtime_output"`
	ExitCode       int           `json:"exit_code"`
	VerifiedAt     string        `json:"verified_at"`
}

type ProofHashes struct {
	LinuxSHA256   string
	WindowsSHA256 string
}

func CreateHostProof(
	stage, manifestPath, platform, outputPath string,
	publicKey ed25519.PublicKey,
	now time.Time,
) (HostProof, error) {
	var proof HostProof
	if platform != "linux" && platform != "windows" {
		return proof, errors.New("host proof platform must be linux or windows")
	}
	if runtime.GOOS != platform {
		return proof, fmt.Errorf(
			"host proof for %s must run on %s, current platform is %s",
			platform,
			platform,
			runtime.GOOS,
		)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return proof, fmt.Errorf("unsupported host proof architecture %q", runtime.GOARCH)
	}
	identity, _, err := ParseManifest(manifestPath)
	if err != nil {
		return proof, err
	}
	manifest, manifestDigest, err := VerifySealedManifest(
		stage,
		identity.Tag,
		identity.Commit,
		publicKey,
	)
	if err != nil {
		return proof, err
	}
	if filepath.Clean(manifestPath) != filepath.Join(stage, ".release-control", "release-manifest.json") {
		return proof, errors.New("host proof must use the stage's sealed release manifest")
	}

	var verified []AssetDigest
	specs, err := AssetSpecs(manifest.Tag)
	if err != nil {
		return proof, err
	}
	for _, spec := range specs {
		if spec.Target.OS != platform {
			continue
		}
		asset, ok := ManifestAsset(manifest, spec.Name)
		if !ok {
			return proof, fmt.Errorf("manifest is missing proof asset %q", spec.Name)
		}
		verified = append(verified, asset)
	}
	sort.Slice(verified, func(i, j int) bool {
		return verified[i].Name < verified[j].Name
	})

	runtimeName := ""
	for _, target := range Targets() {
		if target.OS == platform && target.Arch == runtime.GOARCH {
			runtimeName = target.RawName
			break
		}
	}
	if runtimeName == "" {
		return proof, errors.New("no release binary matches the proof host")
	}
	binaryPath := filepath.Join(stage, "assets", runtimeName)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath, "--version")
	command.Env = []string{}
	var output bytes.Buffer
	command.Stdout = &limitedWriter{destination: &output, remaining: 4096}
	command.Stderr = &limitedWriter{destination: &output, remaining: 4096}
	runErr := command.Run()
	if ctx.Err() != nil {
		return proof, errors.New("native release binary version check timed out")
	}
	if runErr != nil {
		return proof, fmt.Errorf("native release binary version check failed: %w", runErr)
	}
	expectedOutput := "labtether-agent " + manifest.Tag + "\n"
	if output.String() != expectedOutput {
		return proof, fmt.Errorf(
			"native release binary output %q, want %q",
			output.String(),
			expectedOutput,
		)
	}

	proof = HostProof{
		Schema:         HostProofSchema,
		Tag:            manifest.Tag,
		Commit:         manifest.Commit,
		ManifestSHA256: manifestDigest,
		Platform:       platform,
		HostArch:       runtime.GOARCH,
		VerifiedAssets: verified,
		RuntimeAsset:   runtimeName,
		RuntimeOutput:  expectedOutput,
		ExitCode:       0,
		VerifiedAt:     now.UTC().Format(time.RFC3339),
	}
	encoded, err := MarshalDeterministic(proof)
	if err != nil {
		return HostProof{}, err
	}
	if err := WriteNoReplace(outputPath, encoded, 0o600); err != nil {
		return HostProof{}, fmt.Errorf("write host proof: %w", err)
	}
	return proof, nil
}

func VerifyHostProofs(
	manifestPath, linuxProofPath, windowsProofPath string,
) (ProofHashes, error) {
	var hashes ProofHashes
	manifest, manifestBytes, err := ParseManifest(manifestPath)
	if err != nil {
		return hashes, err
	}
	manifestDigest := DigestBytes(manifestBytes)
	linuxProof, linuxBytes, err := parseHostProof(
		linuxProofPath,
		"linux",
		manifest,
		manifestDigest,
	)
	if err != nil {
		return hashes, err
	}
	windowsProof, windowsBytes, err := parseHostProof(
		windowsProofPath,
		"windows",
		manifest,
		manifestDigest,
	)
	if err != nil {
		return hashes, err
	}
	if linuxProof.VerifiedAt == windowsProof.VerifiedAt &&
		linuxProof.HostArch == windowsProof.HostArch {
		// Equal timestamps/architectures are valid, but the full canonical
		// records must still be distinct platform evidence.
		if bytes.Equal(linuxBytes, windowsBytes) {
			return hashes, errors.New("Linux and Windows proof files are identical")
		}
	}
	hashes.LinuxSHA256 = DigestBytes(linuxBytes)
	hashes.WindowsSHA256 = DigestBytes(windowsBytes)
	return hashes, nil
}

func parseHostProof(
	path, platform string,
	manifest Manifest,
	manifestDigest string,
) (HostProof, []byte, error) {
	var proof HostProof
	if _, err := EnsureRegularFile(path, MaxSmallAssetBytes); err != nil {
		return proof, nil, fmt.Errorf("inspect %s host proof: %w", platform, err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return proof, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return HostProof{}, nil, fmt.Errorf("decode %s host proof: %w", platform, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return HostProof{}, nil, fmt.Errorf("%s host proof has trailing JSON", platform)
	}
	if proof.Schema != HostProofSchema || proof.Platform != platform ||
		proof.Tag != manifest.Tag || proof.Commit != manifest.Commit ||
		proof.ManifestSHA256 != manifestDigest || proof.ExitCode != 0 ||
		(proof.HostArch != "amd64" && proof.HostArch != "arm64") {
		return HostProof{}, nil, fmt.Errorf("%s host proof identity is invalid", platform)
	}
	if _, err := time.Parse(time.RFC3339, proof.VerifiedAt); err != nil {
		return HostProof{}, nil, fmt.Errorf("%s host proof timestamp is invalid", platform)
	}
	specs, err := AssetSpecs(manifest.Tag)
	if err != nil {
		return HostProof{}, nil, err
	}
	var expected []AssetDigest
	for _, spec := range specs {
		if spec.Target.OS == platform {
			asset, ok := ManifestAsset(manifest, spec.Name)
			if !ok {
				return HostProof{}, nil, errors.New("manifest proof set is incomplete")
			}
			expected = append(expected, asset)
		}
	}
	if len(proof.VerifiedAssets) != len(expected) {
		return HostProof{}, nil, fmt.Errorf("%s host proof asset set is incomplete", platform)
	}
	for index := range expected {
		if proof.VerifiedAssets[index] != expected[index] {
			return HostProof{}, nil, fmt.Errorf("%s host proof asset digest mismatch", platform)
		}
	}
	expectedRuntime := "labtether-agent-" + platform + "-" + proof.HostArch
	if platform == "windows" {
		expectedRuntime += ".exe"
	}
	if proof.RuntimeAsset != expectedRuntime ||
		proof.RuntimeOutput != "labtether-agent "+manifest.Tag+"\n" {
		return HostProof{}, nil, fmt.Errorf("%s host proof runtime evidence is invalid", platform)
	}
	expectedBytes, err := MarshalDeterministic(proof)
	if err != nil {
		return HostProof{}, nil, err
	}
	if !bytes.Equal(content, expectedBytes) {
		return HostProof{}, nil, fmt.Errorf("%s host proof is not canonically encoded", platform)
	}
	return proof, content, nil
}

type limitedWriter struct {
	destination io.Writer
	remaining   int64
}

func (writer *limitedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > writer.remaining {
		return 0, errors.New("native proof output exceeded limit")
	}
	written, err := writer.destination.Write(value)
	writer.remaining -= int64(written)
	return written, err
}

func ProofPlatformFromPath(path string) string {
	name := strings.ToLower(filepath.Base(path))
	if strings.Contains(name, "windows") {
		return "windows"
	}
	return "linux"
}
