package releasecontract

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ExtractSourceArchive(reader io.Reader, destination string) error {
	if reader == nil {
		return errors.New("source archive input is required")
	}
	if !filepath.IsAbs(destination) {
		return errors.New("source export destination must be absolute")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("source export destination already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect source export destination: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return fmt.Errorf("resolve source export parent: %w", err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return fmt.Errorf("create source export destination: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(destination)
		}
	}()
	resolvedDestination := filepath.Join(parent, filepath.Base(destination))

	limited := &io.LimitedReader{R: reader, N: MaxSourceArchiveSize + 1}
	archive := tar.NewReader(limited)
	seen := make(map[string]struct{})
	fileCount := 0
	var totalBytes int64
	for {
		header, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read source archive: %w", nextErr)
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !ValidSafeSourcePath(name) {
			return fmt.Errorf("source archive contains unsafe path %q", header.Name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("source archive contains duplicate path %q", name)
		}
		seen[name] = struct{}{}
		fileCount++
		if fileCount > MaxSourceFiles {
			return fmt.Errorf("source archive exceeds %d entries", MaxSourceFiles)
		}

		destinationPath := filepath.Join(resolvedDestination, filepath.FromSlash(name))
		relative, relErr := filepath.Rel(resolvedDestination, destinationPath)
		if relErr != nil || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("source archive path escapes destination: %q", name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return fmt.Errorf("source directory %q has nonzero size", name)
			}
			if err := os.MkdirAll(destinationPath, 0o700); err != nil {
				return fmt.Errorf("create source directory %q: %w", name, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > MaxSourceFileSize {
				return fmt.Errorf("source file %q has invalid size", name)
			}
			totalBytes += header.Size
			if totalBytes > MaxSourceArchiveSize {
				return fmt.Errorf("source archive expands beyond %d bytes", MaxSourceArchiveSize)
			}
			if err := os.MkdirAll(filepath.Dir(destinationPath), 0o700); err != nil {
				return fmt.Errorf("create source parent for %q: %w", name, err)
			}
			mode := os.FileMode(0o600)
			if header.FileInfo().Mode()&0o111 != 0 {
				mode = 0o700
			}
			file, openErr := os.OpenFile(
				destinationPath,
				os.O_WRONLY|os.O_CREATE|os.O_EXCL,
				mode,
			)
			if openErr != nil {
				return fmt.Errorf("create source file %q: %w", name, openErr)
			}
			written, copyErr := io.CopyN(file, archive, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return fmt.Errorf("extract source file %q: %w", name, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close source file %q: %w", name, closeErr)
			}
			if written != header.Size {
				return fmt.Errorf("source file %q was truncated", name)
			}
		default:
			return fmt.Errorf(
				"source archive path %q has forbidden type %d",
				name,
				header.Typeflag,
			)
		}
	}
	if limited.N <= 0 {
		return fmt.Errorf("source archive exceeds %d bytes", MaxSourceArchiveSize)
	}
	for _, required := range []string{"go.mod", "go.sum", "cmd/labtether-agent/main.go"} {
		if _, exists := seen[required]; !exists {
			return fmt.Errorf("source archive is missing required file %q", required)
		}
		info, statErr := os.Lstat(filepath.Join(resolvedDestination, filepath.FromSlash(required)))
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("required source path %q is not a regular file", required)
		}
	}
	if err := validateExportedGoMod(filepath.Join(resolvedDestination, "go.mod")); err != nil {
		return err
	}
	ok = true
	return nil
}

func validateExportedGoMod(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read exported go.mod: %w", err)
	}
	lines := strings.Split(string(content), "\n")
	moduleFound := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "module" {
			if len(fields) != 2 || fields[1] != ModulePath {
				return errors.New("exported go.mod has an unexpected module path")
			}
			moduleFound = true
		}
		if fields[0] == "replace" {
			return errors.New("release source go.mod must not contain replace directives")
		}
	}
	if !moduleFound {
		return errors.New("exported go.mod is missing the expected module declaration")
	}
	return nil
}

func CreateDeterministicArchive(binaryPath, archivePath, entryName string) error {
	if !ValidSafeBaseName(entryName) {
		return errors.New("archive entry name is unsafe")
	}
	binaryInfo, err := EnsureRegularFile(binaryPath, MaxRawBinaryBytes)
	if err != nil {
		return fmt.Errorf("inspect archive source: %w", err)
	}
	if filepath.Base(binaryPath) != entryName {
		return errors.New("archive entry name must exactly match the raw binary filename")
	}
	if _, err := os.Lstat(archivePath); err == nil {
		return errors.New("archive output already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect archive output: %w", err)
	}

	source, err := os.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("open archive source: %w", err)
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil || !os.SameFile(binaryInfo, openedInfo) {
		return errors.New("archive source changed while it was opened")
	}

	output, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create archive output: %w", err)
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(archivePath)
		}
	}()

	gzipWriter, err := gzip.NewWriterLevel(output, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	header := &tar.Header{
		Name:     entryName,
		Mode:     0o755,
		Uid:      0,
		Gid:      0,
		Size:     openedInfo.Size(),
		ModTime:  time.Unix(0, 0).UTC(),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatUSTAR,
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("write archive header: %w", err)
	}
	written, err := io.Copy(tarWriter, source)
	if err != nil || written != openedInfo.Size() {
		return fmt.Errorf("write archive payload: %w", err)
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("close tar stream: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close gzip stream: %w", err)
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync archive output: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close archive output: %w", err)
	}
	after, err := source.Stat()
	if err != nil || !os.SameFile(openedInfo, after) ||
		after.Size() != openedInfo.Size() ||
		!after.ModTime().Equal(openedInfo.ModTime()) {
		return errors.New("archive source changed while it was packaged")
	}
	ok = true
	return nil
}

func VerifyDeterministicArchive(archivePath, binaryPath, expectedName string) error {
	if !ValidSafeBaseName(expectedName) {
		return errors.New("expected archive entry name is unsafe")
	}
	if _, err := EnsureRegularFile(archivePath, MaxArchiveBytes); err != nil {
		return fmt.Errorf("inspect release archive: %w", err)
	}
	binaryDigest, err := HashRegularFile(binaryPath, MaxRawBinaryBytes)
	if err != nil {
		return fmt.Errorf("hash archive source: %w", err)
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open release archive: %w", err)
	}
	defer archive.Close()
	buffered := bufio.NewReader(archive)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return fmt.Errorf("open release gzip stream: %w", err)
	}
	gzipReader.Multistream(false)
	if !gzipReader.Header.ModTime.Equal(time.Unix(0, 0).UTC()) ||
		gzipReader.Header.Name != "" || gzipReader.Header.Comment != "" ||
		gzipReader.Header.OS != 255 {
		return errors.New("release gzip header is not deterministic")
	}
	tarReader := tar.NewReader(io.LimitReader(gzipReader, MaxRawBinaryBytes+4096))
	header, err := tarReader.Next()
	if err != nil {
		return fmt.Errorf("read release archive member: %w", err)
	}
	if header.Name != expectedName || header.Typeflag != tar.TypeReg ||
		header.Format != tar.FormatUSTAR || header.Mode != 0o755 ||
		header.Uid != 0 || header.Gid != 0 ||
		!header.ModTime.Equal(time.Unix(0, 0).UTC()) ||
		header.Size != binaryDigest.SizeBytes {
		return errors.New("release archive member metadata violates the deterministic contract")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(tarReader, MaxRawBinaryBytes+1))
	if err != nil {
		return fmt.Errorf("hash release archive member: %w", err)
	}
	if written != binaryDigest.SizeBytes ||
		fmt.Sprintf("%x", hasher.Sum(nil)) != binaryDigest.SHA256 {
		return errors.New("release archive member bytes do not match the raw binary")
	}
	if _, err := tarReader.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("release archive contains unexpected extra members")
		}
		return fmt.Errorf("finish release tar stream: %w", err)
	}
	if err := gzipReader.Close(); err != nil {
		return fmt.Errorf("close release gzip stream: %w", err)
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("release archive contains trailing or concatenated data")
		}
		return fmt.Errorf("inspect release archive trailer: %w", err)
	}
	return nil
}
