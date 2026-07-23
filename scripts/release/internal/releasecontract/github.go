package releasecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type GitHubRelease struct {
	ID         int64                `json:"id"`
	TagName    string               `json:"tag_name"`
	Draft      bool                 `json:"draft"`
	Prerelease bool                 `json:"prerelease"`
	Immutable  bool                 `json:"immutable"`
	Assets     []GitHubReleaseAsset `json:"assets"`
}

type GitHubReleaseAsset struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	State              string `json:"state"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type InspectedAsset struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	URL       string `json:"url"`
}

type InspectionReceipt struct {
	Schema             string           `json:"schema"`
	ReleaseID          int64            `json:"release_id"`
	Tag                string           `json:"tag"`
	Commit             string           `json:"commit"`
	ManifestSHA256     string           `json:"manifest_sha256"`
	LinuxProofSHA256   string           `json:"linux_proof_sha256"`
	WindowsProofSHA256 string           `json:"windows_proof_sha256"`
	InspectedAt        string           `json:"inspected_at"`
	Assets             []InspectedAsset `json:"assets"`
}

func ParseGitHubRelease(path string) (GitHubRelease, error) {
	var release GitHubRelease
	if _, err := EnsureRegularFile(path, 10*MaxSmallAssetBytes); err != nil {
		return release, fmt.Errorf("inspect GitHub release response: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return release, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 10*MaxSmallAssetBytes+1))
	if err := decoder.Decode(&release); err != nil {
		return GitHubRelease{}, fmt.Errorf("decode GitHub release response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return GitHubRelease{}, errors.New("GitHub release response contains trailing JSON")
	}
	if release.ID <= 0 || release.TagName == "" || release.Assets == nil {
		return GitHubRelease{}, errors.New("GitHub release response is missing required fields")
	}
	return release, nil
}

func ValidateExactRelease(
	manifest Manifest,
	release GitHubRelease,
	expectDraft bool,
	requireImmutable bool,
) ([]InspectedAsset, error) {
	if release.TagName != manifest.Tag || release.Draft != expectDraft ||
		release.Prerelease {
		return nil, errors.New("GitHub release identity/state does not match the requested release")
	}
	if requireImmutable && !release.Immutable {
		return nil, errors.New("public GitHub release is not immutable")
	}
	if len(release.Assets) != len(manifest.Assets) {
		return nil, fmt.Errorf(
			"GitHub release has %d assets, want exact 20",
			len(release.Assets),
		)
	}
	return validateReleaseAssetSubset(manifest, release.Assets, true)
}

func PlanDraftUpload(
	manifest Manifest,
	release GitHubRelease,
) ([]string, error) {
	if release.TagName != manifest.Tag || !release.Draft || release.Prerelease {
		return nil, errors.New("existing release is not the expected draft")
	}
	if _, err := validateReleaseAssetSubset(manifest, release.Assets, false); err != nil {
		return nil, err
	}
	present := make(map[string]struct{}, len(release.Assets))
	for _, asset := range release.Assets {
		present[asset.Name] = struct{}{}
	}
	var missing []string
	for _, asset := range manifest.Assets {
		if _, exists := present[asset.Name]; !exists {
			missing = append(missing, asset.Name)
		}
	}
	return missing, nil
}

func WriteInspectionReceipt(
	manifestPath, releaseJSONPath, linuxProofPath, windowsProofPath, outputPath string,
	now time.Time,
) (InspectionReceipt, error) {
	var receipt InspectionReceipt
	manifest, manifestBytes, err := ParseManifest(manifestPath)
	if err != nil {
		return receipt, err
	}
	release, err := ParseGitHubRelease(releaseJSONPath)
	if err != nil {
		return receipt, err
	}
	assets, err := ValidateExactRelease(manifest, release, true, false)
	if err != nil {
		return receipt, err
	}
	proofHashes, err := VerifyHostProofs(
		manifestPath,
		linuxProofPath,
		windowsProofPath,
	)
	if err != nil {
		return receipt, err
	}
	receipt = InspectionReceipt{
		Schema:             InspectionSchema,
		ReleaseID:          release.ID,
		Tag:                manifest.Tag,
		Commit:             manifest.Commit,
		ManifestSHA256:     DigestBytes(manifestBytes),
		LinuxProofSHA256:   proofHashes.LinuxSHA256,
		WindowsProofSHA256: proofHashes.WindowsSHA256,
		InspectedAt:        now.UTC().Format(time.RFC3339),
		Assets:             assets,
	}
	encoded, err := MarshalDeterministic(receipt)
	if err != nil {
		return InspectionReceipt{}, err
	}
	if err := WriteNoReplace(outputPath, encoded, 0o600); err != nil {
		return InspectionReceipt{}, fmt.Errorf("write draft inspection receipt: %w", err)
	}
	return receipt, nil
}

func VerifyFreshInspection(
	receiptPath, manifestPath, currentReleaseJSONPath, linuxProofPath, windowsProofPath string,
	now time.Time,
	maxAge time.Duration,
) (InspectionReceipt, error) {
	receipt, receiptBytes, err := parseInspectionReceipt(receiptPath)
	if err != nil {
		return InspectionReceipt{}, err
	}
	manifest, manifestBytes, err := ParseManifest(manifestPath)
	if err != nil {
		return InspectionReceipt{}, err
	}
	if receipt.Tag != manifest.Tag || receipt.Commit != manifest.Commit ||
		receipt.ManifestSHA256 != DigestBytes(manifestBytes) {
		return InspectionReceipt{}, errors.New("inspection receipt is not bound to this release manifest")
	}
	inspectedAt, err := time.Parse(time.RFC3339, receipt.InspectedAt)
	if err != nil {
		return InspectionReceipt{}, errors.New("inspection receipt timestamp is invalid")
	}
	age := now.UTC().Sub(inspectedAt)
	if maxAge <= 0 || age < 0 || age > maxAge {
		return InspectionReceipt{}, errors.New("draft inspection receipt is stale or from the future")
	}
	proofHashes, err := VerifyHostProofs(
		manifestPath,
		linuxProofPath,
		windowsProofPath,
	)
	if err != nil {
		return InspectionReceipt{}, err
	}
	if receipt.LinuxProofSHA256 != proofHashes.LinuxSHA256 ||
		receipt.WindowsProofSHA256 != proofHashes.WindowsSHA256 {
		return InspectionReceipt{}, errors.New("inspection receipt proof hashes do not match current proof files")
	}
	release, err := ParseGitHubRelease(currentReleaseJSONPath)
	if err != nil {
		return InspectionReceipt{}, err
	}
	assets, err := ValidateExactRelease(manifest, release, true, false)
	if err != nil {
		return InspectionReceipt{}, err
	}
	if receipt.ReleaseID != release.ID || !equalInspectedAssets(receipt.Assets, assets) {
		return InspectionReceipt{}, errors.New("GitHub draft changed after the separate inspection")
	}
	canonical, err := MarshalDeterministic(receipt)
	if err != nil {
		return InspectionReceipt{}, err
	}
	if !bytes.Equal(receiptBytes, canonical) {
		return InspectionReceipt{}, errors.New("inspection receipt is not canonically encoded")
	}
	return receipt, nil
}

func validateReleaseAssetSubset(
	manifest Manifest,
	assets []GitHubReleaseAsset,
	requireExact bool,
) ([]InspectedAsset, error) {
	expected := make(map[string]AssetDigest, len(manifest.Assets))
	for _, asset := range manifest.Assets {
		expected[asset.Name] = asset
	}
	if requireExact && len(assets) != len(expected) {
		return nil, errors.New("GitHub release does not have the exact asset count")
	}
	seenNames := make(map[string]struct{}, len(assets))
	seenIDs := make(map[int64]struct{}, len(assets))
	var inspected []InspectedAsset
	for _, remote := range assets {
		local, exists := expected[remote.Name]
		if !exists {
			return nil, fmt.Errorf("GitHub release has unexpected asset %q", remote.Name)
		}
		if _, duplicate := seenNames[remote.Name]; duplicate {
			return nil, fmt.Errorf("GitHub release has duplicate asset %q", remote.Name)
		}
		if remote.ID <= 0 {
			return nil, fmt.Errorf("GitHub release asset %q has an invalid ID", remote.Name)
		}
		if _, duplicate := seenIDs[remote.ID]; duplicate {
			return nil, errors.New("GitHub release has duplicate asset IDs")
		}
		seenNames[remote.Name] = struct{}{}
		seenIDs[remote.ID] = struct{}{}
		expectedURL := "https://github.com/" + Repository + "/releases/download/" +
			manifest.Tag + "/" + remote.Name
		expectedDigest := "sha256:" + local.SHA256
		if remote.State != "uploaded" || remote.Size != local.SizeBytes ||
			remote.Digest == "" || remote.Digest != expectedDigest ||
			remote.BrowserDownloadURL != expectedURL {
			return nil, fmt.Errorf(
				"GitHub release asset %q failed exact state/size/digest/URL inspection",
				remote.Name,
			)
		}
		inspected = append(inspected, InspectedAsset{
			ID:        remote.ID,
			Name:      remote.Name,
			State:     remote.State,
			SizeBytes: remote.Size,
			SHA256:    strings.TrimPrefix(remote.Digest, "sha256:"),
			URL:       remote.BrowserDownloadURL,
		})
	}
	sort.Slice(inspected, func(i, j int) bool {
		return inspected[i].Name < inspected[j].Name
	})
	return inspected, nil
}

func parseInspectionReceipt(path string) (InspectionReceipt, []byte, error) {
	var receipt InspectionReceipt
	if _, err := EnsureRegularFile(path, MaxSmallAssetBytes); err != nil {
		return receipt, nil, fmt.Errorf("inspect draft receipt: %w", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return receipt, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return InspectionReceipt{}, nil, fmt.Errorf("decode draft receipt: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return InspectionReceipt{}, nil, errors.New("draft receipt contains trailing JSON")
	}
	if receipt.Schema != InspectionSchema || receipt.ReleaseID <= 0 ||
		ValidateTag(receipt.Tag) != nil || ValidateCommit(receipt.Commit) != nil ||
		ValidateDigest(receipt.ManifestSHA256) != nil ||
		ValidateDigest(receipt.LinuxProofSHA256) != nil ||
		ValidateDigest(receipt.WindowsProofSHA256) != nil ||
		len(receipt.Assets) != 20 {
		return InspectionReceipt{}, nil, errors.New("draft receipt identity is invalid")
	}
	return receipt, content, nil
}

func equalInspectedAssets(left, right []InspectedAsset) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
