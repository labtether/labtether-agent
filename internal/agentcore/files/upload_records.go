package files

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// An upload writes to a temporary file beside its destination. When the agent
// stops before the upload ends, that file stays behind. Each temporary file
// is therefore recorded in the agent's own state folder: one small file per
// upload, named after the temporary file and holding its full path. On start
// the agent removes the files the records name. It never searches the shared
// folders for leftovers.
const (
	uploadTempPrefix      = ".lt-upload-"
	uploadTempIDLen       = 32
	uploadRecordDirName   = "upload-temp"
	maxUploadRecordBytes  = 8 * 1024
	maxUploadRecordsStart = 1024
)

// isUploadTempID reports whether id is the random part of a temporary upload
// file name: 32 lowercase hex digits.
func isUploadTempID(id string) bool {
	if len(id) != uploadTempIDLen {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (fm *Manager) uploadRecordPath(tmpPath string) string {
	id := strings.TrimPrefix(filepath.Base(tmpPath), uploadTempPrefix)
	if fm.uploadRecordDir == "" || !isUploadTempID(id) {
		return ""
	}
	return filepath.Join(fm.uploadRecordDir, id)
}

// recordUploadTemp notes where a new temporary upload file is. A state folder
// that cannot be written leaves the upload unrecorded; the upload goes on.
func (fm *Manager) recordUploadTemp(tmpPath string) {
	recordPath := fm.uploadRecordPath(tmpPath)
	if recordPath == "" || os.MkdirAll(fm.uploadRecordDir, 0o700) != nil {
		return
	}
	if err := os.WriteFile(recordPath, []byte(tmpPath), 0o600); err != nil {
		_ = os.Remove(recordPath)
	}
}

// forgetUploadTemp drops the record of a temporary file that is gone.
func (fm *Manager) forgetUploadTemp(tmpPath string) {
	if recordPath := fm.uploadRecordPath(tmpPath); recordPath != "" {
		_ = os.Remove(recordPath)
	}
}

// uploadRecordIDs lists the records present now. It reads only the record
// folder.
func (fm *Manager) uploadRecordIDs() []string {
	if fm.uploadRecordDir == "" {
		return nil
	}
	dir, err := os.Open(fm.uploadRecordDir) // #nosec G304 -- The agent's own state folder.
	if err != nil {
		return nil
	}
	defer dir.Close()
	names, _ := dir.Readdirnames(maxUploadRecordsStart)
	ids := names[:0]
	for _, name := range names {
		if isUploadTempID(name) {
			ids = append(ids, name)
		}
	}
	return ids
}

// removeRecordedUploadLeftovers removes the temporary files that the given
// records name. It opens each recorded path directly and lists no folder.
func (fm *Manager) removeRecordedUploadLeftovers(scope fileScope, ids []string) {
	for _, id := range ids {
		recordPath := filepath.Join(fm.uploadRecordDir, id)
		tmpPath, ok := readUploadRecord(recordPath, id)
		if ok && removeUploadLeftover(scope, tmpPath) {
			_ = os.Remove(recordPath)
		}
	}
}

// readUploadRecord returns the path a record holds. The record counts only
// when it is a small regular file holding a clean absolute path whose file
// name is the temporary name the record is filed under. Anything else is left
// where it is, so a planted file is neither followed nor removed.
func readUploadRecord(recordPath, id string) (string, bool) {
	info, err := os.Lstat(recordPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxUploadRecordBytes {
		return "", false
	}
	file, err := os.Open(recordPath) // #nosec G304 -- Record folder plus a 32-digit hex name.
	if err != nil {
		return "", false
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxUploadRecordBytes+1))
	if err != nil || len(raw) > maxUploadRecordBytes {
		return "", false
	}
	tmpPath := string(raw)
	if !filepath.IsAbs(tmpPath) || filepath.Clean(tmpPath) != tmpPath || filepath.Base(tmpPath) != uploadTempPrefix+id {
		return "", false
	}
	return tmpPath, true
}

// removeUploadLeftover removes one recorded temporary file through the same
// root check an upload passes, and only when it is a regular file. It reports
// whether the record is finished with. A path outside the folders shared now,
// or one that cannot be removed, keeps its record for a later start.
func removeUploadLeftover(scope fileScope, tmpPath string) bool {
	target, err := scope.open(tmpPath)
	if err != nil {
		return false
	}
	defer target.root.Close()
	info, err := target.root.Lstat(target.rel)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	if !info.Mode().IsRegular() {
		return true
	}
	if err := target.root.Remove(target.rel); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("file: could not remove leftover upload file %s: %v", tmpPath, err)
		return false
	}
	log.Printf("file: removed leftover upload file %s", tmpPath)
	return true
}
