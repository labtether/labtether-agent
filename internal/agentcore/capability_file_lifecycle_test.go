package agentcore

import (
	"encoding/json"
	"github.com/labtether/labtether-agent/internal/agentcore/files"
	"github.com/labtether/protocol"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileManagerLifecycleCoversListMkdirRenameAndCopy(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	root := resolvedTempDir(t)
	fm := &files.Manager{
		BaseDir: root,
	}

	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("source-data"), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	mkdirRaw, err := json.Marshal(protocol.FileMkdirData{
		RequestID: "req-mkdir",
		Path:      "nested",
	})
	if err != nil {
		t.Fatalf("marshal file mkdir request: %v", err)
	}
	fm.HandleFileMkdir(transport, protocol.Message{Data: mkdirRaw})

	mkdirMsg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileResult, 2*time.Second)
	var mkdirResult protocol.FileResultData
	if err := json.Unmarshal(mkdirMsg.Data, &mkdirResult); err != nil {
		t.Fatalf("decode mkdir result payload: %v", err)
	}
	if !mkdirResult.OK || mkdirResult.Error != "" {
		t.Fatalf("expected mkdir success, got %+v", mkdirResult)
	}
	if _, err := os.Stat(filepath.Join(root, "nested")); err != nil {
		t.Fatalf("expected created directory: %v", err)
	}

	renameRaw, err := json.Marshal(protocol.FileRenameData{
		RequestID: "req-rename",
		OldPath:   "source.txt",
		NewPath:   "nested/renamed.txt",
	})
	if err != nil {
		t.Fatalf("marshal file rename request: %v", err)
	}
	fm.HandleFileRename(transport, protocol.Message{Data: renameRaw})

	renameMsg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileResult, 2*time.Second)
	var renameResult protocol.FileResultData
	if err := json.Unmarshal(renameMsg.Data, &renameResult); err != nil {
		t.Fatalf("decode rename result payload: %v", err)
	}
	if !renameResult.OK || renameResult.Error != "" {
		t.Fatalf("expected rename success, got %+v", renameResult)
	}
	if _, err := os.Stat(filepath.Join(root, "source.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected source.txt to be moved, stat err=%v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "nested", ".secret.txt"), []byte("hidden"), 0o644); err != nil {
		t.Fatalf("write hidden file: %v", err)
	}

	copyRaw, err := json.Marshal(protocol.FileCopyData{
		RequestID: "req-copy",
		SrcPath:   "nested/renamed.txt",
		DstPath:   "nested/copied.txt",
	})
	if err != nil {
		t.Fatalf("marshal file copy request: %v", err)
	}
	fm.HandleFileCopy(transport, protocol.Message{Data: copyRaw})

	copyMsg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileResult, 2*time.Second)
	var copyResult protocol.FileResultData
	if err := json.Unmarshal(copyMsg.Data, &copyResult); err != nil {
		t.Fatalf("decode copy result payload: %v", err)
	}
	if !copyResult.OK || copyResult.Error != "" {
		t.Fatalf("expected copy success, got %+v", copyResult)
	}

	renamedBytes, err := os.ReadFile(filepath.Join(root, "nested", "renamed.txt"))
	if err != nil {
		t.Fatalf("read renamed file: %v", err)
	}
	copiedBytes, err := os.ReadFile(filepath.Join(root, "nested", "copied.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(renamedBytes) != "source-data" || string(copiedBytes) != "source-data" {
		t.Fatalf("unexpected copied contents renamed=%q copied=%q", string(renamedBytes), string(copiedBytes))
	}

	listRaw, err := json.Marshal(protocol.FileListData{
		RequestID: "req-list",
		Path:      "nested",
	})
	if err != nil {
		t.Fatalf("marshal file list request: %v", err)
	}
	fm.HandleFileList(transport, protocol.Message{Data: listRaw})

	listMsg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileListed, 2*time.Second)
	var listed protocol.FileListedData
	if err := json.Unmarshal(listMsg.Data, &listed); err != nil {
		t.Fatalf("decode file listed payload: %v", err)
	}
	if listed.Error != "" {
		t.Fatalf("expected successful list, got error %q", listed.Error)
	}
	if listed.Path != filepath.Join(root, "nested") {
		t.Fatalf("listed path=%q, want %q", listed.Path, filepath.Join(root, "nested"))
	}
	if len(listed.Entries) != 2 {
		t.Fatalf("expected 2 visible entries, got %d", len(listed.Entries))
	}
	visibleNames := map[string]bool{}
	for _, entry := range listed.Entries {
		visibleNames[entry.Name] = true
		if strings.HasPrefix(entry.Name, ".") {
			t.Fatalf("unexpected hidden entry in visible list: %q", entry.Name)
		}
	}
	if !visibleNames["renamed.txt"] || !visibleNames["copied.txt"] {
		t.Fatalf("unexpected visible entries: %+v", listed.Entries)
	}

	showHiddenRaw, err := json.Marshal(protocol.FileListData{
		RequestID:  "req-list-hidden",
		Path:       "nested",
		ShowHidden: true,
	})
	if err != nil {
		t.Fatalf("marshal file list hidden request: %v", err)
	}
	fm.HandleFileList(transport, protocol.Message{Data: showHiddenRaw})

	hiddenMsg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileListed, 2*time.Second)
	var listedHidden protocol.FileListedData
	if err := json.Unmarshal(hiddenMsg.Data, &listedHidden); err != nil {
		t.Fatalf("decode hidden file listed payload: %v", err)
	}
	if listedHidden.Error != "" {
		t.Fatalf("expected successful hidden list, got error %q", listedHidden.Error)
	}
	if len(listedHidden.Entries) != 3 {
		t.Fatalf("expected 3 entries with hidden files shown, got %d", len(listedHidden.Entries))
	}
	hiddenNames := map[string]bool{}
	for _, entry := range listedHidden.Entries {
		hiddenNames[entry.Name] = true
	}
	if !hiddenNames[".secret.txt"] || !hiddenNames["renamed.txt"] || !hiddenNames["copied.txt"] {
		t.Fatalf("unexpected hidden-visible entries: %+v", listedHidden.Entries)
	}
}

func TestFileManagerDeleteRejectsBaseDirectory(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	root := resolvedTempDir(t)
	fm := &files.Manager{
		BaseDir: root,
	}

	raw, err := json.Marshal(protocol.FileDeleteData{
		RequestID: "req-delete",
		Path:      "",
	})
	if err != nil {
		t.Fatalf("marshal file delete request: %v", err)
	}
	fm.HandleFileDelete(transport, protocol.Message{Data: raw})

	msg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileResult, 2*time.Second)
	var result protocol.FileResultData
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("decode file result payload: %v", err)
	}
	if result.OK {
		t.Fatal("expected delete of base directory to be rejected")
	}
	if !strings.Contains(result.Error, "cannot delete base directory") {
		t.Fatalf("expected base-dir rejection, got %q", result.Error)
	}
}

func TestFileManagerSearchTruncatesAtMaxResults(t *testing.T) {
	transport, messages, cleanup := newAgentcoreCapturedTransport(t)
	defer cleanup()

	root := resolvedTempDir(t)
	for _, name := range []string{"alpha.txt", "beta.txt", "gamma.txt", "ignore.log"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o644); err != nil {
			t.Fatalf("write search fixture %s: %v", name, err)
		}
	}

	fm := &files.Manager{
		BaseDir: root,
	}

	raw, err := json.Marshal(protocol.FileSearchData{
		RequestID:  "req-search",
		Path:       "",
		Pattern:    "*.txt",
		MaxResults: 2,
	})
	if err != nil {
		t.Fatalf("marshal file search request: %v", err)
	}
	fm.HandleFileSearch(transport, protocol.Message{Data: raw})

	msg := waitForCapturedAgentMessage(t, messages, protocol.MsgFileSearchResult, 2*time.Second)
	var result protocol.FileSearchResultData
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("decode file search payload: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("expected successful search, got error %q", result.Error)
	}
	if len(result.Matches) != 2 {
		t.Fatalf("expected 2 capped matches, got %d", len(result.Matches))
	}
	if !result.Truncated {
		t.Fatal("expected search result to be marked truncated")
	}
	for _, match := range result.Matches {
		if !strings.HasSuffix(match.Name, ".txt") {
			t.Fatalf("unexpected non-txt match %q", match.Name)
		}
		if !strings.HasPrefix(match.Path, root) {
			t.Fatalf("expected absolute path under base dir, got %q", match.Path)
		}
	}
}
