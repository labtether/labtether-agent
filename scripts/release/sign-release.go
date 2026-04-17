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
//
// Usage:
//
//	go run ./scripts/release/sign-release.go \
//	    --version v1.2.3 --os linux --arch amd64 \
//	    --binary labtether-agent-linux-amd64 \
//	    --out-prefix labtether-agent-linux-amd64-v1.2.3 \
//	    < key.b64
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	version := flag.String("version", "", "release version (e.g. v1.2.3)")
	goos := flag.String("os", "", "target GOOS")
	arch := flag.String("arch", "", "target GOARCH")
	binary := flag.String("binary", "", "path to the built binary to hash")
	outPrefix := flag.String("out-prefix", "", "output filename prefix (no extension)")
	flag.Parse()

	for name, val := range map[string]*string{"version": version, "os": goos, "arch": arch, "binary": binary, "out-prefix": outPrefix} {
		if strings.TrimSpace(*val) == "" {
			fmt.Fprintf(os.Stderr, "sign-release: --%s is required\n", name)
			os.Exit(2)
		}
	}

	keyRaw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("read key from stdin: %v", err)
	}
	priv := decodeKey(strings.TrimSpace(string(keyRaw)))

	data, err := os.ReadFile(*binary)
	if err != nil {
		fail("read binary %s: %v", *binary, err)
	}
	sum := sha256.Sum256(data)
	shaHex := fmt.Sprintf("%x", sum[:])
	size := int64(len(data))

	payload := strings.Join([]string{
		strings.TrimSpace(*version),
		strings.TrimSpace(*goos),
		strings.TrimSpace(*arch),
		strings.ToLower(shaHex),
		fmt.Sprintf("%d", size),
	}, "\n")

	sig := ed25519.Sign(priv, []byte(payload))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	sigPath := *outPrefix + ".sig"
	if err := os.WriteFile(sigPath, []byte(sigB64+"\n"), 0o644); err != nil {
		fail("write %s: %v", sigPath, err)
	}

	meta := map[string]any{
		"version":    *version,
		"os":         *goos,
		"arch":       *arch,
		"sha256":     strings.ToLower(shaHex),
		"size_bytes": size,
		"signature":  sigB64,
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		fail("marshal metadata: %v", err)
	}
	metaPath := *outPrefix + ".metadata.json"
	if err := os.WriteFile(metaPath, append(metaJSON, '\n'), 0o644); err != nil {
		fail("write %s: %v", metaPath, err)
	}

	fmt.Printf("signed %s\n  sha256: %s\n  size:   %d\n  sig:    %s\n  meta:   %s\n", *binary, shaHex, size, sigPath, metaPath)
}

func decodeKey(s string) ed25519.PrivateKey {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if rawURL, urlErr := base64.RawURLEncoding.DecodeString(s); urlErr == nil {
			raw = rawURL
		} else {
			fail("decode signing key (expected base64): %v", err)
		}
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw)
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw)
	default:
		fail("signing key must be %d or %d bytes after base64 decode, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
		return nil
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sign-release: "+format+"\n", args...)
	os.Exit(1)
}
