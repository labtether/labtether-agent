package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/labtether/labtether-agent/scripts/release/internal/releasecontract"
)

func main() {
	if len(os.Args) < 2 {
		fail("a release-contract command is required")
	}
	switch os.Args[1] {
	case "extract-source":
		extractSource(os.Args[2:])
	case "prepare":
		prepare(os.Args[2:])
	case "seal":
		seal(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "host-proof":
		hostProof(os.Args[2:])
	case "verify-proofs":
		verifyProofs(os.Args[2:])
	case "plan-draft":
		planDraft(os.Args[2:])
	case "inspect-draft":
		inspectDraft(os.Args[2:])
	case "verify-inspection":
		verifyInspection(os.Args[2:])
	case "inspect-public":
		inspectPublic(os.Args[2:])
	case "asset-paths":
		assetPaths(os.Args[2:])
	default:
		fail("unknown release-contract command %q", os.Args[1])
	}
}

func extractSource(args []string) {
	set := newFlagSet("extract-source")
	destination := set.String("destination", "", "fresh absolute source export path")
	parse(set, args)
	if err := releasecontract.ExtractSourceArchive(os.Stdin, *destination); err != nil {
		fail("%v", err)
	}
}

func prepare(args []string) {
	set := newFlagSet("prepare")
	stage := set.String("stage", "", "absolute release stage")
	tag := set.String("tag", "", "exact release tag")
	commit := set.String("commit", "", "exact release commit")
	goVersion := set.String("go-version", "", "builder Go version")
	parse(set, args)
	if _, err := releasecontract.PrepareUnsignedAssets(
		*stage,
		*tag,
		*commit,
		*goVersion,
	); err != nil {
		fail("%v", err)
	}
}

func seal(args []string) {
	set := newFlagSet("seal")
	stage := set.String("stage", "", "absolute release stage")
	tag := set.String("tag", "", "exact release tag")
	commit := set.String("commit", "", "exact release commit")
	repositoryRoot := set.String("repository-root", "", "exact source repository root")
	parse(set, args)
	publicKey := pinnedKey(*repositoryRoot)
	if _, err := releasecontract.SealManifest(
		*stage,
		*tag,
		*commit,
		publicKey,
	); err != nil {
		fail("%v", err)
	}
}

func verify(args []string) {
	set := newFlagSet("verify")
	stage := set.String("stage", "", "absolute release stage")
	tag := set.String("tag", "", "exact release tag")
	commit := set.String("commit", "", "exact release commit")
	repositoryRoot := set.String("repository-root", "", "exact source repository root")
	parse(set, args)
	publicKey := pinnedKey(*repositoryRoot)
	if _, _, err := releasecontract.VerifySealedManifest(
		*stage,
		*tag,
		*commit,
		publicKey,
	); err != nil {
		fail("%v", err)
	}
}

func hostProof(args []string) {
	set := newFlagSet("host-proof")
	stage := set.String("stage", "", "absolute release stage")
	manifest := set.String("manifest", "", "sealed release manifest")
	platform := set.String("platform", "", "linux or windows")
	output := set.String("output", "", "fresh proof output path")
	repositoryRoot := set.String("repository-root", "", "exact source repository root")
	parse(set, args)
	publicKey := pinnedKey(*repositoryRoot)
	if _, err := releasecontract.CreateHostProof(
		*stage,
		*manifest,
		*platform,
		*output,
		publicKey,
		time.Now().UTC(),
	); err != nil {
		fail("%v", err)
	}
}

func verifyProofs(args []string) {
	set := newFlagSet("verify-proofs")
	manifest := set.String("manifest", "", "sealed release manifest")
	linuxProof := set.String("linux-proof", "", "Linux host proof")
	windowsProof := set.String("windows-proof", "", "Windows host proof")
	parse(set, args)
	hashes, err := releasecontract.VerifyHostProofs(
		*manifest,
		*linuxProof,
		*windowsProof,
	)
	if err != nil {
		fail("%v", err)
	}
	fmt.Printf("%s %s\n", hashes.LinuxSHA256, hashes.WindowsSHA256)
}

func planDraft(args []string) {
	set := newFlagSet("plan-draft")
	manifestPath := set.String("manifest", "", "sealed release manifest")
	releaseJSON := set.String("release-json", "", "GitHub draft API response")
	parse(set, args)
	manifest, _, err := releasecontract.ParseManifest(*manifestPath)
	if err != nil {
		fail("%v", err)
	}
	release, err := releasecontract.ParseGitHubRelease(*releaseJSON)
	if err != nil {
		fail("%v", err)
	}
	missing, err := releasecontract.PlanDraftUpload(manifest, release)
	if err != nil {
		fail("%v", err)
	}
	for _, name := range missing {
		fmt.Println(name)
	}
}

func inspectDraft(args []string) {
	set := newFlagSet("inspect-draft")
	manifest := set.String("manifest", "", "sealed release manifest")
	releaseJSON := set.String("release-json", "", "fresh GitHub draft API response")
	linuxProof := set.String("linux-proof", "", "Linux host proof")
	windowsProof := set.String("windows-proof", "", "Windows host proof")
	output := set.String("output", "", "fresh inspection receipt path")
	parse(set, args)
	if _, err := releasecontract.WriteInspectionReceipt(
		*manifest,
		*releaseJSON,
		*linuxProof,
		*windowsProof,
		*output,
		time.Now().UTC(),
	); err != nil {
		fail("%v", err)
	}
}

func verifyInspection(args []string) {
	set := newFlagSet("verify-inspection")
	receipt := set.String("receipt", "", "separate draft inspection receipt")
	manifest := set.String("manifest", "", "sealed release manifest")
	releaseJSON := set.String("release-json", "", "fresh current GitHub draft API response")
	linuxProof := set.String("linux-proof", "", "Linux host proof")
	windowsProof := set.String("windows-proof", "", "Windows host proof")
	parse(set, args)
	verified, err := releasecontract.VerifyFreshInspection(
		*receipt,
		*manifest,
		*releaseJSON,
		*linuxProof,
		*windowsProof,
		time.Now().UTC(),
		15*time.Minute,
	)
	if err != nil {
		fail("%v", err)
	}
	fmt.Println(verified.ReleaseID)
}

func inspectPublic(args []string) {
	set := newFlagSet("inspect-public")
	manifestPath := set.String("manifest", "", "sealed release manifest")
	releaseJSON := set.String("release-json", "", "fresh public GitHub release API response")
	parse(set, args)
	manifest, _, err := releasecontract.ParseManifest(*manifestPath)
	if err != nil {
		fail("%v", err)
	}
	release, err := releasecontract.ParseGitHubRelease(*releaseJSON)
	if err != nil {
		fail("%v", err)
	}
	if _, err := releasecontract.ValidateExactRelease(
		manifest,
		release,
		false,
		true,
	); err != nil {
		fail("%v", err)
	}
}

func assetPaths(args []string) {
	set := newFlagSet("asset-paths")
	stage := set.String("stage", "", "absolute release stage")
	manifestPath := set.String("manifest", "", "sealed release manifest")
	parse(set, args)
	manifest, _, err := releasecontract.ParseManifest(*manifestPath)
	if err != nil {
		fail("%v", err)
	}
	paths, err := releasecontract.AssetPaths(*stage, manifest)
	if err != nil {
		fail("%v", err)
	}
	for _, path := range paths {
		fmt.Println(path)
	}
}

func pinnedKey(repositoryRoot string) ed25519.PublicKey {
	if repositoryRoot == "" || !filepath.IsAbs(repositoryRoot) {
		fail("repository-root must be an absolute path")
	}
	path := filepath.Join(
		repositoryRoot,
		"scripts",
		"release",
		"agent-release-public-key.b64",
	)
	publicKey, err := releasecontract.DecodePinnedPublicKey(path)
	if err != nil {
		fail("%v", err)
	}
	return publicKey
}

func newFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	return set
}

func parse(set *flag.FlagSet, args []string) {
	if err := set.Parse(args); err != nil {
		fail("%v", err)
	}
	if set.NArg() != 0 {
		fail("%s received unexpected positional arguments", set.Name())
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "release-contract: "+format+"\n", args...)
	os.Exit(1)
}
