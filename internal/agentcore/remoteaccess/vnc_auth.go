package remoteaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// x11vnc must never run without a password, and the password must never be
// on a command line where ps(1) shows it. The agent writes it to a 0600 file
// in a fresh 0700 directory and passes "-passwdfile rm:<file>", so x11vnc
// deletes the file as soon as it has read it. The directory is removed when
// the session stops or fails to start.

const (
	x11vncAuthDirPattern   = "labtether-x11vnc-auth-*"
	x11vncPasswordFileName = "passwd"
)

var errVNCPasswordRequired = errors.New("refusing to start VNC without a session password")

// validateX11VNCPassword rejects passwords that are empty or that x11vnc's
// password-file parser would treat as syntax (comments, markers, extra lines).
func validateX11VNCPassword(password string) error {
	if password == "" {
		return errVNCPasswordRequired
	}
	if strings.HasPrefix(password, "#") || strings.Contains(password, "__") {
		return fmt.Errorf("VNC password uses reserved x11vnc password-file syntax")
	}
	for _, r := range password {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("VNC password must not contain whitespace or control characters")
		}
	}
	return nil
}

// CreateX11VNCPasswordFile writes the session password to a private file. It
// returns the private directory, which the caller owns and must remove with
// RemoveVNCAuthDir, and the password file inside it.
func CreateX11VNCPasswordFile(password string) (string, string, error) {
	password = strings.TrimSpace(password)
	if err := validateX11VNCPassword(password); err != nil {
		return "", "", err
	}
	dir, err := os.MkdirTemp("", x11vncAuthDirPattern)
	if err != nil {
		return "", "", fmt.Errorf("failed to create x11vnc auth directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G703 -- dir was just created by MkdirTemp.
		RemoveVNCAuthDir(dir)
		return "", "", fmt.Errorf("failed to secure x11vnc auth directory: %w", err)
	}
	path := filepath.Join(dir, x11vncPasswordFileName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed name inside a fresh private directory.
	if err != nil {
		RemoveVNCAuthDir(dir)
		return "", "", fmt.Errorf("failed to create x11vnc password file: %w", err)
	}
	_, writeErr := file.WriteString(password + "\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		RemoveVNCAuthDir(dir)
		return "", "", fmt.Errorf("failed to write x11vnc password file: %w", errors.Join(writeErr, closeErr))
	}
	return dir, path, nil
}

// prepareX11VNCLaunch creates the password file and the matching x11vnc
// arguments. On success the caller owns the returned auth directory.
func prepareX11VNCLaunch(display string, port int, quality, password, xauthPath, clip string) ([]string, string, error) {
	authDir, passwordFile, err := CreateX11VNCPasswordFile(password)
	if err != nil {
		return nil, "", err
	}
	args, err := buildX11VNCArgsWithClip(display, port, quality, passwordFile, xauthPath, clip)
	if err != nil {
		RemoveVNCAuthDir(authDir)
		return nil, "", err
	}
	return args, authDir, nil
}

// RemoveVNCAuthDir removes a private x11vnc auth directory created by
// CreateX11VNCPasswordFile. Any other path is removed only if it is a file or
// an empty directory.
func RemoveVNCAuthDir(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	prefix := strings.TrimSuffix(x11vncAuthDirPattern, "*")
	if filepath.Dir(path) == filepath.Clean(os.TempDir()) && strings.HasPrefix(filepath.Base(path), prefix) {
		_ = os.RemoveAll(path) // #nosec G703 -- package-created private auth directory under the temp root.
		return
	}
	RemoveProcessLog(path)
}
