//go:build darwin

package sysconfig

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const darwinClipboardFixture = "  Grüße — 文件 😀\r\n\n"

func TestDarwinClipboardKeepsUTF8WithoutTerminalLocale(t *testing.T) {
	// Launchd can start an agent with no locale, or with a non-UTF-8 locale.
	// Run the real read/write owner against an isolated child, never pbcopy.
	for _, locale := range []string{"", "C", "en_US.ISO8859-1"} {
		t.Run("locale="+locale, func(t *testing.T) {
			t.Setenv("LANG", locale)
			t.Setenv("LC_ALL", locale)
			t.Setenv("LC_CTYPE", locale)
			t.Setenv("LABTETHER_CLIPBOARD_TEST_SECRET", "must-not-reach-child")
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "clipboard-bytes")
			original := ClipboardNewCommand
			t.Cleanup(func() { ClipboardNewCommand = original })
			ClipboardNewCommand = func(name string, args ...string) (*exec.Cmd, error) {
				if (name != "pbcopy" && name != "pbpaste") || len(args) != 0 {
					t.Fatalf("unexpected clipboard helper: %q %q", name, args)
				}
				return exec.Command(executable, "-test.run=^TestDarwinClipboardHelperProcess$",
					"--", "--darwin-clipboard-helper", name, target), nil
			}
			text, image, err := PlatformClipboardRead("text")
			if err != nil || text != darwinClipboardFixture || image != "" {
				t.Fatalf("read = %q, image=%q, err=%v", text, image, err)
			}
			for _, text := range []string{darwinClipboardFixture, ""} {
				if err := PlatformClipboardWriteText(text); err != nil {
					t.Fatal(err)
				}
				actual, err := os.ReadFile(target)
				if err != nil || string(actual) != text {
					t.Fatalf("write = %q, err=%v; want %q", actual, err, text)
				}
			}
		})
	}
}

func TestDarwinClipboardHelperProcess(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "--darwin-clipboard-helper" {
		return
	}
	for _, key := range []string{"LANG", "LC_ALL", "LC_CTYPE"} {
		if os.Getenv(key) != "en_US.UTF-8" {
			os.Exit(2)
		}
	}
	if os.Getenv("LABTETHER_CLIPBOARD_TEST_SECRET") != "" {
		os.Exit(2)
	}
	switch os.Args[len(os.Args)-2] {
	case "pbpaste":
		if _, err := io.WriteString(os.Stdout, darwinClipboardFixture); err != nil {
			os.Exit(2)
		}
	case "pbcopy":
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
		if err != nil || os.WriteFile(os.Args[len(os.Args)-1], data, 0600) != nil {
			os.Exit(2)
		}
	default:
		os.Exit(2)
	}
	os.Exit(0)
}
