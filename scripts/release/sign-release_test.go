package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSigningKey(t *testing.T) (ed25519.PrivateKey, string, string) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	privateEncoded := base64.StdEncoding.EncodeToString(privateKey)
	publicEncoded := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	return privateKey, privateEncoded, publicEncoded
}

func TestSignReleaseProducesCanonicalVerifiableArtifacts(t *testing.T) {
	privateKey, privateEncoded, publicEncoded := testSigningKey(t)
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "labtether-agent-linux-amd64")
	binaryData := []byte("bounded release artifact")
	if err := os.WriteFile(binaryPath, binaryData, 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	result, err := signRelease(releaseSigningConfig{
		Version:           "  v1.2.3  ",
		GOOS:              " LINUX ",
		Arch:              " AMD64 ",
		BinaryPath:        binaryPath,
		OutputPrefix:      filepath.Join(directory, "labtether-agent-linux-amd64-v1.2.3"),
		ExpectedPublicKey: publicEncoded,
	}, strings.NewReader(privateEncoded))
	if err != nil {
		t.Fatalf("sign release: %v", err)
	}

	wantSum := sha256.Sum256(binaryData)
	wantSHA := hex.EncodeToString(wantSum[:])
	if result.SHA256 != wantSHA || result.SizeBytes != int64(len(binaryData)) {
		t.Fatalf("result digest/size = %s/%d, want %s/%d", result.SHA256, result.SizeBytes, wantSHA, len(binaryData))
	}

	metadataRaw, err := os.ReadFile(result.MetadataPath)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var metadata releaseMetadata
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if metadata.Version != "v1.2.3" || metadata.OS != "linux" || metadata.Arch != "amd64" {
		t.Fatalf("metadata identity = %q/%q/%q", metadata.Version, metadata.OS, metadata.Arch)
	}
	if metadata.SHA256 != wantSHA || metadata.SizeBytes != int64(len(binaryData)) || metadata.Signature != result.Signature {
		t.Fatal("metadata does not match the signed artifact result")
	}

	signatureRaw, err := base64.StdEncoding.DecodeString(metadata.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	payload := canonicalReleasePayload(metadata.Version, metadata.OS, metadata.Arch, metadata.SHA256, metadata.SizeBytes)
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), []byte(payload), signatureRaw) {
		t.Fatal("release signature did not verify against canonical metadata")
	}

	detachedRaw, err := os.ReadFile(result.SigPath)
	if err != nil {
		t.Fatalf("read detached signature: %v", err)
	}
	if strings.TrimSpace(string(detachedRaw)) != metadata.Signature {
		t.Fatal("detached and embedded signatures differ")
	}
	for _, path := range []string{result.SigPath, result.MetadataPath} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat output: %v", statErr)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Fatalf("output mode = %#o, want 0644", got)
		}
	}
}

func TestReadSigningKeyRejectsOversizedInput(t *testing.T) {
	_, err := readSigningKey(strings.NewReader(strings.Repeat("A", maxEncodedSigningKeyBytes+1)))
	if err == nil {
		t.Fatal("expected oversized signing-key input to be rejected")
	}
}

func TestDecodePrivateKeyRejectsInconsistentExpandedKey(t *testing.T) {
	privateKey, _, _ := testSigningKey(t)
	inconsistent := append([]byte(nil), privateKey...)
	inconsistent[len(inconsistent)-1] ^= 0xff
	encoded := []byte(base64.StdEncoding.EncodeToString(inconsistent))
	if _, err := decodePrivateKey(encoded); err == nil {
		t.Fatal("expected inconsistent expanded private key to be rejected")
	}
}

func TestDecodeExpectedPublicKeyAcceptsHex(t *testing.T) {
	privateKey, _, _ := testSigningKey(t)
	want := privateKey.Public().(ed25519.PublicKey)
	got, err := decodeExpectedPublicKey(hex.EncodeToString(want))
	if err != nil {
		t.Fatalf("decode hex public key: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("decoded hex public key differs")
	}
}

func TestHashReleaseBinaryRejectsOversizeAndSymlink(t *testing.T) {
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "agent")
	if err := os.WriteFile(binaryPath, []byte("12345"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	if _, _, err := hashReleaseBinary(binaryPath, 4); err == nil {
		t.Fatal("expected oversized release binary to be rejected")
	}

	symlinkPath := filepath.Join(directory, "agent-link")
	if err := os.Symlink(binaryPath, symlinkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := hashReleaseBinary(symlinkPath, 1024); err == nil {
		t.Fatal("expected release binary symlink to be rejected")
	}
}

func TestSignReleaseRejectsUnexpectedPublicKey(t *testing.T) {
	_, privateEncoded, _ := testSigningKey(t)
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	otherPublic := base64.StdEncoding.EncodeToString(otherKey.Public().(ed25519.PublicKey))
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "agent")
	if err := os.WriteFile(binaryPath, []byte("agent"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	_, err := signRelease(releaseSigningConfig{
		Version:           "v1.0.0",
		GOOS:              "linux",
		Arch:              "amd64",
		BinaryPath:        binaryPath,
		OutputPrefix:      filepath.Join(directory, "release"),
		ExpectedPublicKey: otherPublic,
	}, strings.NewReader(privateEncoded))
	if err == nil {
		t.Fatal("expected signing key/public key mismatch to be rejected")
	}
	if _, statErr := os.Stat(filepath.Join(directory, "release.sig")); !os.IsNotExist(statErr) {
		t.Fatal("signature output exists after public-key mismatch")
	}
}

func TestSignReleaseRefusesExistingOutputWithoutMutation(t *testing.T) {
	_, privateEncoded, publicEncoded := testSigningKey(t)
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "agent")
	if err := os.WriteFile(binaryPath, []byte("agent"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	prefix := filepath.Join(directory, "release")
	sigPath := prefix + ".sig"
	original := []byte("existing signature must remain")
	if err := os.WriteFile(sigPath, original, 0o600); err != nil {
		t.Fatalf("write existing output: %v", err)
	}

	_, err := signRelease(releaseSigningConfig{
		Version:           "v1.0.0",
		GOOS:              "linux",
		Arch:              "amd64",
		BinaryPath:        binaryPath,
		OutputPrefix:      prefix,
		ExpectedPublicKey: publicEncoded,
	}, strings.NewReader(privateEncoded))
	if err == nil {
		t.Fatal("expected existing release output to be rejected")
	}
	after, readErr := os.ReadFile(sigPath)
	if readErr != nil {
		t.Fatalf("read existing output: %v", readErr)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("existing release output was modified")
	}
}

func TestSignReleaseRefusesSymlinkOutputWithoutTouchingTarget(t *testing.T) {
	_, privateEncoded, publicEncoded := testSigningKey(t)
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "agent")
	if err := os.WriteFile(binaryPath, []byte("agent"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	victimPath := filepath.Join(directory, "victim")
	victimData := []byte("do not overwrite")
	if err := os.WriteFile(victimPath, victimData, 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	prefix := filepath.Join(directory, "release")
	if err := os.Symlink(victimPath, prefix+".sig"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err := signRelease(releaseSigningConfig{
		Version:           "v1.0.0",
		GOOS:              "linux",
		Arch:              "amd64",
		BinaryPath:        binaryPath,
		OutputPrefix:      prefix,
		ExpectedPublicKey: publicEncoded,
	}, strings.NewReader(privateEncoded))
	if err == nil {
		t.Fatal("expected symlink release output to be rejected")
	}
	after, readErr := os.ReadFile(victimPath)
	if readErr != nil {
		t.Fatalf("read victim: %v", readErr)
	}
	if !bytes.Equal(after, victimData) {
		t.Fatal("symlink target was modified")
	}
}

func TestSignReleaseRejectsInputOutputCollision(t *testing.T) {
	_, privateEncoded, publicEncoded := testSigningKey(t)
	directory := t.TempDir()
	prefix := filepath.Join(directory, "release")
	binaryPath := prefix + ".sig"
	original := []byte("binary must remain")
	if err := os.WriteFile(binaryPath, original, 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	_, err := signRelease(releaseSigningConfig{
		Version:           "v1.0.0",
		GOOS:              "linux",
		Arch:              "amd64",
		BinaryPath:        binaryPath,
		OutputPrefix:      prefix,
		ExpectedPublicKey: publicEncoded,
	}, strings.NewReader(privateEncoded))
	if err == nil {
		t.Fatal("expected input/output collision to be rejected")
	}
	after, readErr := os.ReadFile(binaryPath)
	if readErr != nil {
		t.Fatalf("read binary: %v", readErr)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("input binary was modified")
	}
}

func TestSignReleaseRejectsMetadataDelimiterInjection(t *testing.T) {
	_, privateEncoded, publicEncoded := testSigningKey(t)
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "agent")
	if err := os.WriteFile(binaryPath, []byte("agent"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	_, err := signRelease(releaseSigningConfig{
		Version:           "v1.0.0\nlinux",
		GOOS:              "linux",
		Arch:              "amd64",
		BinaryPath:        binaryPath,
		OutputPrefix:      filepath.Join(directory, "release"),
		ExpectedPublicKey: publicEncoded,
	}, strings.NewReader(privateEncoded))
	if err == nil {
		t.Fatal("expected metadata delimiter injection to be rejected")
	}
}

func TestRollbackCommittedOutputsDoesNotRemoveReplacement(t *testing.T) {
	directory := t.TempDir()
	destinationPath := filepath.Join(directory, "release.sig")
	output := pendingOutput{path: destinationPath, data: []byte("staged"), mode: 0o644}
	staged, err := stageOutput(output)
	if err != nil {
		t.Fatalf("stage output: %v", err)
	}
	t.Cleanup(func() { cleanupStagedOutput(staged) })

	if err := commitStagedOutput(output, staged); err != nil {
		t.Fatalf("commit staged output: %v", err)
	}
	if err := os.Remove(destinationPath); err != nil {
		t.Fatalf("remove committed output: %v", err)
	}
	replacement := []byte("unrelated replacement")
	if err := os.WriteFile(destinationPath, replacement, 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}

	if err := rollbackCommittedOutputs([]pendingOutput{output}, []stagedOutput{staged}); err != nil {
		t.Fatalf("rollback output: %v", err)
	}
	after, err := os.ReadFile(destinationPath)
	if err != nil {
		t.Fatalf("read replacement after rollback: %v", err)
	}
	if !bytes.Equal(after, replacement) {
		t.Fatal("rollback removed or modified an unrelated replacement")
	}
}

func TestRollbackCommittedOutputsRemovesOriginalCommit(t *testing.T) {
	directory := t.TempDir()
	destinationPath := filepath.Join(directory, "release.sig")
	output := pendingOutput{path: destinationPath, data: []byte("staged"), mode: 0o644}
	staged, err := stageOutput(output)
	if err != nil {
		t.Fatalf("stage output: %v", err)
	}
	t.Cleanup(func() { cleanupStagedOutput(staged) })
	if err := commitStagedOutput(output, staged); err != nil {
		t.Fatalf("commit staged output: %v", err)
	}

	if err := rollbackCommittedOutputs([]pendingOutput{output}, []stagedOutput{staged}); err != nil {
		t.Fatalf("rollback output: %v", err)
	}
	if _, err := os.Lstat(destinationPath); !os.IsNotExist(err) {
		t.Fatal("rollback left the original committed output in place")
	}
}

func TestCommitStagedOutputRejectsSourceReplacement(t *testing.T) {
	directory := t.TempDir()
	destinationPath := filepath.Join(directory, "release.sig")
	output := pendingOutput{path: destinationPath, data: []byte("staged"), mode: 0o644}
	staged, err := stageOutput(output)
	if err != nil {
		t.Fatalf("stage output: %v", err)
	}
	t.Cleanup(func() { cleanupStagedOutput(staged) })

	if err := os.Remove(staged.path); err != nil {
		t.Fatalf("remove staged path: %v", err)
	}
	if err := os.WriteFile(staged.path, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("replace staged path: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(staged.path) })

	if err := commitStagedOutput(output, staged); err == nil {
		t.Fatal("expected replaced staged source to be rejected")
	}
	if _, err := os.Lstat(destinationPath); !os.IsNotExist(err) {
		t.Fatal("destination was created from a replaced staged source")
	}
}
