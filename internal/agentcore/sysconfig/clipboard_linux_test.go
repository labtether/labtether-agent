//go:build linux

package sysconfig

import (
	"encoding/base64"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func preserveLinuxClipboardHooks(t *testing.T) {
	t.Helper()
	originalDetectSession := DetectLinuxDesktopSessionFn
	originalAppendDisplays := AppendDetectedActiveDisplaysFn
	originalLookPath := ClipboardLookPath
	originalNewCommand := ClipboardNewCommand
	originalBuildX11Env := BuildX11ClientEnvFn
	t.Cleanup(func() {
		DetectLinuxDesktopSessionFn = originalDetectSession
		AppendDetectedActiveDisplaysFn = originalAppendDisplays
		ClipboardLookPath = originalLookPath
		ClipboardNewCommand = originalNewCommand
		BuildX11ClientEnvFn = originalBuildX11Env
	})
}

func TestPlatformClipboardReadUsesWaylandNativeToolAndSessionEnv(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	t.Setenv("DISPLAY", ":99")
	t.Setenv("XAUTHORITY", "/tmp/ambient-xauthority")

	DetectLinuxDesktopSessionFn = func() LinuxDesktopSessionInfo {
		return LinuxDesktopSessionInfo{
			Type:           DesktopSessionTypeWayland,
			WaylandDisplay: "wayland-1",
			XDGRuntimeDir:  "/run/user/1000",
		}
	}
	ClipboardLookPath = func(name string) (string, error) {
		if name != "wl-paste" {
			t.Fatalf("looked up unexpected clipboard tool %q", name)
		}
		return "/usr/bin/wl-paste", nil
	}
	var gotName string
	var gotArgs []string
	ClipboardNewCommand = func(name string, args ...string) (*exec.Cmd, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.Command("/bin/sh", "-c", `
			test "$XDG_RUNTIME_DIR" = "/run/user/1000" &&
			test "$WAYLAND_DISPLAY" = "wayland-1" &&
			test -z "$DISPLAY" &&
			test -z "$XAUTHORITY" &&
			printf 'wayland text'
		`), nil
	}

	text, image, err := PlatformClipboardRead("text")
	if err != nil {
		t.Fatalf("PlatformClipboardRead: %v", err)
	}
	if text != "wayland text" || image != "" {
		t.Fatalf("clipboard result = %q, %q", text, image)
	}
	if gotName != "wl-paste" || !reflect.DeepEqual(gotArgs, []string{"--no-newline"}) {
		t.Fatalf("command = %q %#v, want wl-paste --no-newline", gotName, gotArgs)
	}
}

func TestPlatformClipboardWriteUsesWaylandNativeToolAndSessionEnv(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	DetectLinuxDesktopSessionFn = func() LinuxDesktopSessionInfo {
		return LinuxDesktopSessionInfo{
			Type:           DesktopSessionTypeWayland,
			WaylandDisplay: "wayland-2",
			XDGRuntimeDir:  "/run/user/1001",
		}
	}
	ClipboardLookPath = func(name string) (string, error) {
		if name != "wl-copy" {
			t.Fatalf("looked up unexpected clipboard tool %q", name)
		}
		return "/usr/bin/wl-copy", nil
	}
	var gotName string
	ClipboardNewCommand = func(name string, args ...string) (*exec.Cmd, error) {
		gotName = name
		return exec.Command("/bin/sh", "-c", `
			test "$XDG_RUNTIME_DIR" = "/run/user/1001" &&
			test "$WAYLAND_DISPLAY" = "wayland-2" &&
			IFS= read -r value || test -n "$value"
			test "$value" = "hello wayland"
		`), nil
	}

	if err := PlatformClipboardWriteText("hello wayland"); err != nil {
		t.Fatalf("PlatformClipboardWriteText: %v", err)
	}
	if gotName != "wl-copy" {
		t.Fatalf("command = %q, want wl-copy", gotName)
	}
}

func TestPlatformClipboardWaylandDoesNotFallBackToX11Tools(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	DetectLinuxDesktopSessionFn = func() LinuxDesktopSessionInfo {
		return LinuxDesktopSessionInfo{Type: DesktopSessionTypeWayland}
	}
	ClipboardLookPath = func(name string) (string, error) {
		if name == "xclip" || name == "xsel" {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}

	if _, _, err := PlatformClipboardRead("text"); err == nil || !strings.Contains(err.Error(), "wl-paste") {
		t.Fatalf("read error = %v, want explicit wl-paste requirement", err)
	}
	if err := PlatformClipboardWriteText("test"); err == nil || !strings.Contains(err.Error(), "wl-copy") {
		t.Fatalf("write error = %v, want explicit wl-copy requirement", err)
	}
}

func TestPlatformClipboardReadKeepsX11ToolAndEnv(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	DetectLinuxDesktopSessionFn = func() LinuxDesktopSessionInfo {
		return LinuxDesktopSessionInfo{Type: DesktopSessionTypeX11, Display: ":8"}
	}
	ClipboardLookPath = func(name string) (string, error) {
		if name == "xclip" {
			return "/usr/bin/xclip", nil
		}
		return "", errors.New("not found")
	}
	BuildX11ClientEnvFn = func(display, xauthPath string) []string {
		if display != ":8" || xauthPath != "" {
			t.Fatalf("BuildX11ClientEnvFn(%q, %q)", display, xauthPath)
		}
		return []string{"PATH=/usr/bin:/bin", "DISPLAY=:8", "XAUTHORITY=/tmp/xauth"}
	}
	ClipboardNewCommand = func(name string, args ...string) (*exec.Cmd, error) {
		if name != "xclip" || !reflect.DeepEqual(args, []string{"-selection", "clipboard", "-o"}) {
			t.Fatalf("command = %q %#v", name, args)
		}
		return exec.Command("/bin/sh", "-c", `
			test "$DISPLAY" = ":8" &&
			test "$XAUTHORITY" = "/tmp/xauth" &&
			printf 'x11 text\n'
		`), nil
	}

	text, _, err := PlatformClipboardRead("text")
	if err != nil {
		t.Fatalf("PlatformClipboardRead: %v", err)
	}
	if text != "x11 text" {
		t.Fatalf("text = %q, want x11 text", text)
	}
}

func TestPlatformClipboardReadImageUsesXclipPNGTarget(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	DetectLinuxDesktopSessionFn = func() LinuxDesktopSessionInfo {
		return LinuxDesktopSessionInfo{Type: DesktopSessionTypeX11, Display: ":8"}
	}
	ClipboardLookPath = func(name string) (string, error) {
		if name == "xclip" {
			return "/usr/bin/xclip", nil
		}
		return "", errors.New("not found")
	}
	ClipboardNewCommand = func(name string, args ...string) (*exec.Cmd, error) {
		if name != "xclip" || !reflect.DeepEqual(args, []string{"-selection", "clipboard", "-t", "image/png", "-o"}) {
			t.Fatalf("command = %q %#v", name, args)
		}
		return exec.Command("/bin/sh", "-c", `printf 'PNGDATA'`), nil
	}

	text, image, err := PlatformClipboardRead("image/png")
	if err != nil {
		t.Fatalf("PlatformClipboardRead(image/png): %v", err)
	}
	if text != "" || image != "UE5HREFUQQ==" {
		t.Fatalf("image clipboard result = %q, %q", text, image)
	}
}

func TestPlatformClipboardWriteImageUsesXclipPNGTarget(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	DetectLinuxDesktopSessionFn = func() LinuxDesktopSessionInfo {
		return LinuxDesktopSessionInfo{Type: DesktopSessionTypeX11, Display: ":8"}
	}
	ClipboardLookPath = func(name string) (string, error) {
		if name == "xclip" {
			return "/usr/bin/xclip", nil
		}
		return "", errors.New("not found")
	}
	ClipboardNewCommand = func(name string, args ...string) (*exec.Cmd, error) {
		if name != "xclip" || !reflect.DeepEqual(args, []string{"-selection", "clipboard", "-t", "image/png"}) {
			t.Fatalf("command = %q %#v", name, args)
		}
		return exec.Command("/bin/sh", "-c", `test "$(od -An -tx1 | tr -d ' \n')" = "89504e470d0a1a0a504e4744415441"`), nil
	}

	png := append(append([]byte(nil), pngSignature...), []byte("PNGDATA")...)
	if err := PlatformClipboardWriteImage(base64.StdEncoding.EncodeToString(png)); err != nil {
		t.Fatalf("PlatformClipboardWriteImage: %v", err)
	}
}

func TestPlatformClipboardReadImageUsesWaylandPNGType(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	DetectLinuxDesktopSessionFn = func() LinuxDesktopSessionInfo {
		return LinuxDesktopSessionInfo{Type: DesktopSessionTypeWayland, WaylandDisplay: "wayland-3", XDGRuntimeDir: "/run/user/1002"}
	}
	ClipboardLookPath = func(name string) (string, error) {
		if name != "wl-paste" {
			t.Fatalf("looked up unexpected clipboard tool %q", name)
		}
		return "/usr/bin/wl-paste", nil
	}
	ClipboardNewCommand = func(name string, args ...string) (*exec.Cmd, error) {
		if name != "wl-paste" || !reflect.DeepEqual(args, []string{"--type", "image/png"}) {
			t.Fatalf("command = %q %#v", name, args)
		}
		return exec.Command("/bin/sh", "-c", `printf '\211PNG\r\n\032\nPNGDATA'`), nil
	}

	_, image, err := PlatformClipboardRead("image/png")
	if err != nil {
		t.Fatalf("PlatformClipboardRead(image/png): %v", err)
	}
	want := base64.StdEncoding.EncodeToString(append(append([]byte(nil), pngSignature...), []byte("PNGDATA")...))
	if image != want {
		t.Fatalf("image clipboard result = %q, want %q", image, want)
	}
}

func TestPlatformClipboardWriteImageUsesWaylandPNGType(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	DetectLinuxDesktopSessionFn = func() LinuxDesktopSessionInfo {
		return LinuxDesktopSessionInfo{Type: DesktopSessionTypeWayland, WaylandDisplay: "wayland-4", XDGRuntimeDir: "/run/user/1003"}
	}
	ClipboardLookPath = func(name string) (string, error) {
		if name != "wl-copy" {
			t.Fatalf("looked up unexpected clipboard tool %q", name)
		}
		return "/usr/bin/wl-copy", nil
	}
	ClipboardNewCommand = func(name string, args ...string) (*exec.Cmd, error) {
		if name != "wl-copy" || !reflect.DeepEqual(args, []string{"--type", "image/png"}) {
			t.Fatalf("command = %q %#v", name, args)
		}
		return exec.Command("/bin/sh", "-c", `test "$(od -An -tx1 | tr -d ' \n')" = "89504e470d0a1a0a504e4744415441"`), nil
	}

	png := append(append([]byte(nil), pngSignature...), []byte("PNGDATA")...)
	if err := PlatformClipboardWriteImage(base64.StdEncoding.EncodeToString(png)); err != nil {
		t.Fatalf("PlatformClipboardWriteImage: %v", err)
	}
}

func TestPlatformClipboardWriteImageRejectsInvalidBase64(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	if err := PlatformClipboardWriteImage("not-base64!"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid image encoding error = %v", err)
	}
}

func TestPlatformClipboardWriteImageRejectsNonPNGBytes(t *testing.T) {
	preserveLinuxClipboardHooks(t)
	if err := PlatformClipboardWriteImage(base64.StdEncoding.EncodeToString([]byte("not a png"))); err == nil || !strings.Contains(err.Error(), "not a PNG") {
		t.Fatalf("non-PNG image error = %v", err)
	}
}
