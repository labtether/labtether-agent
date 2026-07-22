// sign-release signs agent release metadata with an ed25519 key from CI.
//
// Payload format (must match internal/agentcore/self_update.go
// selfUpdateSignaturePayload): version\nos\narch\nsha256\nsize, joined by
// single newlines, with sha256 lowercased.
//
// The private key is read from stdin as a base64-encoded ed25519 seed
// (32 bytes) or full private key (64 bytes). The resulting signature is
// written as base64 to <out-prefix>.sig and a signed metadata JSON is
// written to <out-prefix>.metadata.json.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	maxEncodedSigningKeyBytes = 4096
	maxExpectedPublicKeyBytes = 512
	// Keep release metadata within the self-updater's accepted download limit.
	maxReleaseBinaryBytes = 100 * 1024 * 1024
	maxMetadataFieldBytes = 128
	maxReleasePathBytes   = 4096
)

type releaseSigningConfig struct {
	Version           string
	GOOS              string
	Arch              string
	BinaryPath        string
	OutputPrefix      string
	ExpectedPublicKey string
}

type releaseMetadata struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Signature string `json:"signature"`
}

type signingResult struct {
	SHA256       string
	SizeBytes    int64
	Signature    string
	SigPath      string
	MetadataPath string
}

type pendingOutput struct {
	path string
	data []byte
	mode os.FileMode
}

type stagedOutput struct {
	path string
	file *os.File
}

func main() {
	version := flag.String("version", "", "release version (e.g. v1.2.3)")
	goos := flag.String("os", "", "target GOOS")
	arch := flag.String("arch", "", "target GOARCH")
	binary := flag.String("binary", "", "path to the built binary to hash")
	outPrefix := flag.String("out-prefix", "", "output filename prefix (no extension)")
	expectedPublicKey := flag.String("expected-public-key", "", "expected base64/hex ed25519 public key")
	flag.Parse()

	result, err := signRelease(releaseSigningConfig{
		Version:           *version,
		GOOS:              *goos,
		Arch:              *arch,
		BinaryPath:        *binary,
		OutputPrefix:      *outPrefix,
		ExpectedPublicKey: *expectedPublicKey,
	}, os.Stdin)
	if err != nil {
		fail("%v", err)
	}

	fmt.Printf(
		"signed release artifact\n  sha256: %s\n  size:   %d\n  sig:    %s\n  meta:   %s\n",
		result.SHA256,
		result.SizeBytes,
		result.SigPath,
		result.MetadataPath,
	)
}

func signRelease(cfg releaseSigningConfig, keyReader io.Reader) (signingResult, error) {
	var result signingResult
	if keyReader == nil {
		return result, errors.New("signing key input is required")
	}

	version, err := normalizeMetadataField("version", cfg.Version, false)
	if err != nil {
		return result, err
	}
	goos, err := normalizeMetadataField("os", cfg.GOOS, true)
	if err != nil {
		return result, err
	}
	arch, err := normalizeMetadataField("arch", cfg.Arch, true)
	if err != nil {
		return result, err
	}
	binaryPath, err := normalizeReleasePath("binary", cfg.BinaryPath)
	if err != nil {
		return result, err
	}
	outputPrefix, err := normalizeReleasePath("out-prefix", cfg.OutputPrefix)
	if err != nil {
		return result, err
	}

	privateKey, err := readSigningKey(keyReader)
	if err != nil {
		return result, err
	}
	defer zeroBytes(privateKey)

	if expected := strings.TrimSpace(cfg.ExpectedPublicKey); expected != "" {
		publicKey, decodeErr := decodeExpectedPublicKey(expected)
		if decodeErr != nil {
			return result, decodeErr
		}
		derived := privateKey.Public().(ed25519.PublicKey)
		if subtle.ConstantTimeCompare(publicKey, derived) != 1 {
			return result, errors.New("signing private key does not match the expected public key")
		}
	}

	shaHex, size, err := hashReleaseBinary(binaryPath, maxReleaseBinaryBytes)
	if err != nil {
		return result, err
	}
	payload := canonicalReleasePayload(version, goos, arch, shaHex, size)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(payload)))

	metadata := releaseMetadata{
		Version:   version,
		OS:        goos,
		Arch:      arch,
		SHA256:    shaHex,
		SizeBytes: size,
		Signature: signature,
	}
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return result, fmt.Errorf("marshal release metadata: %w", err)
	}
	metadataJSON = append(metadataJSON, '\n')

	sigPath, err := resolveOutputPath(outputPrefix + ".sig")
	if err != nil {
		return result, fmt.Errorf("resolve signature output: %w", err)
	}
	metadataPath, err := resolveOutputPath(outputPrefix + ".metadata.json")
	if err != nil {
		return result, fmt.Errorf("resolve metadata output: %w", err)
	}
	resolvedBinaryPath, err := filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return result, fmt.Errorf("resolve binary path: %w", err)
	}
	resolvedBinaryPath, err = filepath.Abs(resolvedBinaryPath)
	if err != nil {
		return result, fmt.Errorf("resolve absolute binary path: %w", err)
	}
	if samePath(resolvedBinaryPath, sigPath) || samePath(resolvedBinaryPath, metadataPath) {
		return result, errors.New("release output path collides with the input binary")
	}

	outputs := []pendingOutput{
		{path: sigPath, data: []byte(signature + "\n"), mode: 0o644},
		{path: metadataPath, data: metadataJSON, mode: 0o644},
	}
	if err := writeOutputsAtomically(outputs); err != nil {
		return result, err
	}

	return signingResult{
		SHA256:       shaHex,
		SizeBytes:    size,
		Signature:    signature,
		SigPath:      sigPath,
		MetadataPath: metadataPath,
	}, nil
}

func normalizeMetadataField(name, raw string, targetComponent bool) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("--%s is required", name)
	}
	if len(value) > maxMetadataFieldBytes {
		return "", fmt.Errorf("--%s exceeds %d bytes", name, maxMetadataFieldBytes)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("--%s contains control characters", name)
	}
	if targetComponent {
		value = strings.ToLower(value)
		for i, r := range value {
			valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || (i > 0 && (r == '.' || r == '_' || r == '-'))
			if !valid {
				return "", fmt.Errorf("--%s contains unsupported characters", name)
			}
		}
	}
	return value, nil
}

func normalizeReleasePath(name, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("--%s is required", name)
	}
	if len(value) > maxReleasePathBytes {
		return "", fmt.Errorf("--%s exceeds %d bytes", name, maxReleasePathBytes)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("--%s contains control characters", name)
	}
	return filepath.Clean(value), nil
}

func readSigningKey(reader io.Reader) (ed25519.PrivateKey, error) {
	encoded, err := io.ReadAll(io.LimitReader(reader, maxEncodedSigningKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	defer zeroBytes(encoded)
	if len(encoded) > maxEncodedSigningKeyBytes {
		return nil, fmt.Errorf("encoded signing key exceeds %d bytes", maxEncodedSigningKeyBytes)
	}
	return decodePrivateKey(bytes.TrimSpace(encoded))
}

func decodePrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	raw, err := decodeBase64(encoded)
	if err != nil {
		return nil, errors.New("decode signing key: expected base64")
	}
	defer zeroBytes(raw)

	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if subtle.ConstantTimeCompare(raw[ed25519.SeedSize:], derived[ed25519.SeedSize:]) != 1 {
			zeroBytes(derived)
			return nil, errors.New("expanded signing key has an inconsistent public half")
		}
		privateKey := append(ed25519.PrivateKey(nil), raw...)
		zeroBytes(derived)
		return privateKey, nil
	default:
		return nil, fmt.Errorf("signing key must decode to %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func decodeExpectedPublicKey(encoded string) (ed25519.PublicKey, error) {
	if len(encoded) > maxExpectedPublicKeyBytes {
		return nil, fmt.Errorf("expected public key exceeds %d bytes", maxExpectedPublicKeyBytes)
	}
	if raw, err := decodeBase64([]byte(encoded)); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	if raw, err := hex.DecodeString(encoded); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("expected public key must be %d-byte base64 or hex", ed25519.PublicKeySize)
}

func decodeBase64(encoded []byte) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded := make([]byte, encoding.DecodedLen(len(encoded)))
		n, err := encoding.Decode(decoded, encoded)
		if err == nil {
			return decoded[:n], nil
		}
		zeroBytes(decoded)
	}
	return nil, errors.New("invalid base64")
}

func hashReleaseBinary(path string, maxBytes int64) (string, int64, error) {
	if maxBytes <= 0 {
		return "", 0, errors.New("release binary size limit must be positive")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return "", 0, fmt.Errorf("inspect release binary: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return "", 0, errors.New("release binary must be a regular non-symlink file")
	}
	if pathInfo.Size() <= 0 {
		return "", 0, errors.New("release binary must not be empty")
	}
	if pathInfo.Size() > maxBytes {
		return "", 0, fmt.Errorf("release binary exceeds %d bytes", maxBytes)
	}

	// #nosec G304 -- the caller-selected release artifact is validated with
	// Lstat, SameFile, regular-file, size, and before/after stability checks.
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open release binary: %w", err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat opened release binary: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return "", 0, errors.New("release binary changed while it was opened")
	}

	hasher := sha256.New()
	size, err := copyBoundedHash(hasher, file, maxBytes)
	if err != nil {
		return "", 0, err
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("restat release binary: %w", err)
	}
	if size != openedInfo.Size() || afterInfo.Size() != openedInfo.Size() || !afterInfo.ModTime().Equal(openedInfo.ModTime()) {
		return "", 0, errors.New("release binary changed while it was hashed")
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func copyBoundedHash(destination hash.Hash, source io.Reader, maxBytes int64) (int64, error) {
	written, err := io.Copy(destination, io.LimitReader(source, maxBytes+1))
	if err != nil {
		return 0, fmt.Errorf("hash release binary: %w", err)
	}
	if written > maxBytes {
		return 0, fmt.Errorf("release binary exceeds %d bytes", maxBytes)
	}
	return written, nil
}

func canonicalReleasePayload(version, goos, arch, shaHex string, size int64) string {
	return strings.Join([]string{version, goos, arch, strings.ToLower(shaHex), fmt.Sprintf("%d", size)}, "\n")
}

func resolveOutputPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolvedDirectory, err := filepath.EvalSymlinks(filepath.Dir(absPath))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolvedDirectory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("output parent is not a directory")
	}
	return filepath.Join(resolvedDirectory, filepath.Base(absPath)), nil
}

func writeOutputsAtomically(outputs []pendingOutput) error {
	if len(outputs) == 0 {
		return errors.New("no release outputs were provided")
	}
	seen := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		if _, duplicate := seen[output.path]; duplicate {
			return errors.New("duplicate release output path")
		}
		seen[output.path] = struct{}{}
		if _, err := os.Lstat(output.path); err == nil {
			return fmt.Errorf("refusing to replace existing release output %q", filepath.Base(output.path))
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect release output %q: %w", filepath.Base(output.path), err)
		}
	}

	stagedOutputs := make([]stagedOutput, len(outputs))
	defer func() { cleanupStagedOutputs(stagedOutputs) }()
	for index, output := range outputs {
		staged, err := stageOutput(output)
		if err != nil {
			return err
		}
		stagedOutputs[index] = staged
	}

	for index, output := range outputs {
		// Link is an atomic, no-replace directory-entry operation on the release
		// runner filesystem. A raced symlink or file makes Link fail with EEXIST;
		// the destination is never followed or partially written. The staged file
		// remains open so its identity can be checked before and after the link.
		if err := commitStagedOutput(output, stagedOutputs[index]); err != nil {
			commitErr := fmt.Errorf("commit release output %q: %w", filepath.Base(output.path), err)
			rollbackErr := rollbackCommittedOutputs(outputs[:index], stagedOutputs[:index])
			return errors.Join(commitErr, rollbackErr)
		}
	}
	if err := verifyCommittedOutputs(outputs, stagedOutputs); err != nil {
		rollbackErr := rollbackCommittedOutputs(outputs, stagedOutputs)
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func commitStagedOutput(output pendingOutput, staged stagedOutput) error {
	expectedInfo, err := staged.file.Stat()
	if err != nil {
		return fmt.Errorf("stat staged release output: %w", err)
	}
	sourceInfo, err := os.Lstat(staged.path)
	if err != nil {
		return fmt.Errorf("inspect staged release output: %w", err)
	}
	if !sourceInfo.Mode().IsRegular() || !os.SameFile(expectedInfo, sourceInfo) {
		return errors.New("staged release output changed before commit")
	}
	if err := os.Link(staged.path, output.path); err != nil {
		return err
	}
	destinationInfo, err := os.Lstat(output.path)
	if err != nil {
		return fmt.Errorf("inspect committed release output: %w", err)
	}
	if !destinationInfo.Mode().IsRegular() || !os.SameFile(expectedInfo, destinationInfo) {
		return errors.New("staged release output changed during commit")
	}
	return nil
}

func verifyCommittedOutputs(outputs []pendingOutput, stagedOutputs []stagedOutput) error {
	if len(outputs) != len(stagedOutputs) {
		return errors.New("release output verification state is inconsistent")
	}
	for index, output := range outputs {
		expectedInfo, err := stagedOutputs[index].file.Stat()
		if err != nil {
			return fmt.Errorf("stat staged output after commit: %w", err)
		}
		destinationInfo, err := os.Lstat(output.path)
		if err != nil {
			return fmt.Errorf("inspect release output after commit: %w", err)
		}
		if !destinationInfo.Mode().IsRegular() || !os.SameFile(expectedInfo, destinationInfo) {
			return fmt.Errorf("release output %q changed during commit", filepath.Base(output.path))
		}
	}
	return nil
}

// rollbackCommittedOutputs only removes a destination while it is still the
// same inode as its staged file. If another process replaces the destination,
// rollback leaves that replacement untouched instead of deleting an unrelated
// file from a shared output directory.
func rollbackCommittedOutputs(outputs []pendingOutput, stagedOutputs []stagedOutput) error {
	if len(outputs) != len(stagedOutputs) {
		return errors.New("release output rollback state is inconsistent")
	}

	var rollbackErrors []error
	for index, output := range outputs {
		stagedInfo, err := stagedOutputs[index].file.Stat()
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("inspect staged output during rollback: %w", err))
			continue
		}
		destinationInfo, err := os.Lstat(output.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("inspect committed output during rollback: %w", err))
			continue
		}
		if stagedInfo.Mode().IsRegular() && destinationInfo.Mode().IsRegular() && os.SameFile(stagedInfo, destinationInfo) {
			if err := os.Remove(output.path); err != nil && !os.IsNotExist(err) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("remove committed output during rollback: %w", err))
			}
		}
	}
	return errors.Join(rollbackErrors...)
}

func stageOutput(output pendingOutput) (stagedOutput, error) {
	file, err := os.CreateTemp(filepath.Dir(output.path), ".sign-release-*")
	if err != nil {
		return stagedOutput{}, fmt.Errorf("create staged release output: %w", err)
	}
	staged := stagedOutput{path: file.Name(), file: file}
	ok := false
	defer func() {
		if !ok {
			cleanupStagedOutput(staged)
		}
	}()
	if _, err := file.Write(output.data); err != nil {
		return stagedOutput{}, fmt.Errorf("write staged release output: %w", err)
	}
	if err := file.Chmod(output.mode); err != nil {
		return stagedOutput{}, fmt.Errorf("set staged release output mode: %w", err)
	}
	if err := file.Sync(); err != nil {
		return stagedOutput{}, fmt.Errorf("sync staged release output: %w", err)
	}
	ok = true
	return staged, nil
}

func samePath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func cleanupStagedOutputs(outputs []stagedOutput) {
	for _, output := range outputs {
		cleanupStagedOutput(output)
	}
}

func cleanupStagedOutput(output stagedOutput) {
	if output.file == nil {
		return
	}
	expectedInfo, expectedErr := output.file.Stat()
	actualInfo, actualErr := os.Lstat(output.path)
	if expectedErr == nil && actualErr == nil && actualInfo.Mode().IsRegular() && os.SameFile(expectedInfo, actualInfo) {
		_ = os.Remove(output.path)
	}
	_ = output.file.Close()
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sign-release: "+format+"\n", args...)
	os.Exit(1)
}
