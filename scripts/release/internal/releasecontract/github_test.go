package releasecontract

import (
	"fmt"
	"strings"
	"testing"
)

// Risk: plan-draft, inspect-draft and verify-inspection must accept a real
// GitHub draft. Until publication a draft serves its assets under a temporary
// untagged-<hex> path, not the tag, and the checker once refused every draft
// with uploaded assets. A published release must still serve every asset under
// its tag, and one release may not mix download paths.
func TestReleaseAssetDownloadPaths(t *testing.T) {
	const tag = "v0.0.1"
	specs, err := AssetSpecs(tag)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Tag: tag}
	for index, spec := range specs {
		manifest.Assets = append(manifest.Assets, AssetDigest{
			Name:      spec.Name,
			SHA256:    fmt.Sprintf("%064x", index+1),
			SizeBytes: int64(index + 1),
		})
	}
	release := func(draft bool, path func(index int) string) GitHubRelease {
		result := GitHubRelease{ID: 7, TagName: tag, Draft: draft, Immutable: !draft}
		for index, asset := range manifest.Assets {
			result.Assets = append(result.Assets, GitHubReleaseAsset{
				ID:     int64(index + 1),
				Name:   asset.Name,
				State:  "uploaded",
				Size:   asset.SizeBytes,
				Digest: "sha256:" + asset.SHA256,
				BrowserDownloadURL: "https://github.com/" + Repository +
					"/releases/download/" + path(index) + "/" + asset.Name,
			})
		}
		return result
	}
	untagged := func(int) string { return "untagged-cbfec337b0da2157d416" }
	tagged := func(int) string { return tag }
	mixed := func(index int) string {
		if index == 0 {
			return tag
		}
		return untagged(index)
	}

	if _, err := ValidateExactRelease(manifest, release(true, untagged), true, false); err != nil {
		t.Fatalf("draft under its untagged path: %v", err)
	}
	if missing, err := PlanDraftUpload(manifest, release(true, untagged)); err != nil || len(missing) != 0 {
		t.Fatalf("plan for a fully uploaded draft: missing %v, error %v", missing, err)
	}
	if _, err := ValidateExactRelease(manifest, release(false, tagged), false, true); err != nil {
		t.Fatalf("published release under its tag: %v", err)
	}
	for name, bad := range map[string]GitHubRelease{
		"published release under an untagged path": release(false, untagged),
		"draft mixing download paths":              release(true, mixed),
	} {
		_, err := ValidateExactRelease(manifest, bad, bad.Draft, !bad.Draft)
		if err == nil || !strings.Contains(err.Error(), "URL inspection") {
			t.Fatalf("%s: got %v, want URL rejection", name, err)
		}
	}
}
