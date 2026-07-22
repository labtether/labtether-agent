package remoteaccess

import (
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestShellCandidatesForWindowsPreferNativeShells(t *testing.T) {
	got := shellCandidatesForOS("windows")
	want := []string{"pwsh.exe", "powershell.exe", "cmd.exe"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates = %#v, want %#v", got, want)
		}
	}
}

func TestShellCandidatesForUnixRemainPortable(t *testing.T) {
	got := shellCandidatesForOS("linux")
	want := []string{"zsh", "bash", "sh"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates = %#v, want %#v", got, want)
		}
	}
}

func TestPipeBackedTerminalBridgesInputAndOutput(t *testing.T) {
	cmd := exec.Command("sh", "-c", "read line; printf 'pipe:%s\\n' \"$line\"")
	input, output, err := startPipeBackedTerminal(cmd)
	if err != nil {
		t.Fatalf("startPipeBackedTerminal: %v", err)
	}
	defer input.Close()
	defer output.Close()

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	if _, err := io.WriteString(input, "LTQA-WINDOWS-PIPE\\n"); err != nil {
		t.Fatalf("write terminal input: %v", err)
	}
	_ = input.Close()

	raw, err := io.ReadAll(output)
	if err != nil {
		t.Fatalf("read terminal output: %v", err)
	}
	if !strings.Contains(string(raw), "pipe:LTQA-WINDOWS-PIPE") {
		t.Fatalf("output = %q", raw)
	}
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pipe-backed terminal process did not exit")
	}
}
