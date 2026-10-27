package agentcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// Agents installed without the key in their environment (manual, Docker and
// pre-1.7 installs) verify updates with the key linked into the release
// binary, and the unsigned opt-in cannot bypass it.
func TestBuiltinUpdateKeyVerifiesWithoutEnvironmentKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	original := builtinSelfUpdatePublicKey
	SetBuiltinSelfUpdatePublicKey(base64.StdEncoding.EncodeToString(publicKey))
	t.Cleanup(func() { builtinSelfUpdatePublicKey = original })
	t.Setenv(envSelfUpdateTrustedPublicKey, "")
	t.Setenv(envSelfUpdateAcceptUnsigned, "true")

	downloadURL := "https://hub.example.com/api/v1/agent/binary?os=linux&arch=amd64"
	release := agentReleaseMetadata{
		Version: "v2.0.0", OS: "linux", Arch: "amd64",
		SHA256: strings.Repeat("a", 64), URL: downloadURL, SizeBytes: 123,
	}
	signed := release
	signed.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(selfUpdateSignaturePayload(release))))
	if err := verifyReleaseMetadataSignature(signed, downloadURL); err != nil {
		t.Fatalf("release signed with the built-in key was refused: %v", err)
	}
	if err := verifyReleaseMetadataSignature(release, downloadURL); err == nil {
		t.Fatal("unsigned release was accepted although a built-in key is present")
	}
}
