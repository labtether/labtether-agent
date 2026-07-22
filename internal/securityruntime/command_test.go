package securityruntime

import "testing"

func TestValidateExecBinaryAllowsUnknownWhenAllowlistDisabled(t *testing.T) {
	t.Setenv(envExecAllowlistMode, "false")
	t.Setenv(envExecAllowlistAcceptRisk, "true")
	t.Setenv(envExecAllowedBinaries, "")
	if err := ValidateExecBinary("custom-binary"); err != nil {
		t.Fatalf("expected command to be allowed when allowlist mode is disabled, got %v", err)
	}
}

func TestValidateExecBinaryBlocksWhenAllowlistDisabledWithoutAcceptRisk(t *testing.T) {
	t.Setenv(envExecAllowlistMode, "false")
	t.Setenv(envExecAllowlistAcceptRisk, "")
	if err := ValidateExecBinary("custom-binary"); err == nil {
		t.Fatalf("expected command to be blocked when allowlist is disabled without accept-risk flag")
	}
}

func TestValidateShellCommandBlocksWhenAllowlistDisabledWithoutAcceptRisk(t *testing.T) {
	t.Setenv(envShellAllowlistMode, "false")
	t.Setenv(envShellAllowlistAcceptRisk, "")
	if err := ValidateShellCommand("whoami"); err == nil {
		t.Fatalf("expected shell command to be blocked when allowlist is disabled without accept-risk flag")
	}
}

func TestValidateExecBinaryBlocksUnknownByDefault(t *testing.T) {
	t.Setenv(envExecAllowlistMode, "")
	t.Setenv(envExecAllowedBinaries, "")
	if err := ValidateExecBinary("custom-binary"); err == nil {
		t.Fatalf("expected unknown command to be blocked by default")
	}
}

func TestValidateExecBinaryBlocksWhenAllowlistEnabled(t *testing.T) {
	t.Setenv(envExecAllowlistMode, "true")
	t.Setenv(envExecAllowedBinaries, "sh,systemctl")
	if err := ValidateExecBinary("custom-binary"); err == nil {
		t.Fatalf("expected command to be blocked")
	}
}

func TestValidateExecBinaryAllowsDefaultDesktopUtilities(t *testing.T) {
	t.Setenv(envExecAllowlistMode, "")
	t.Setenv(envExecAllowedBinaries, "")
	for _, name := range []string{"wl-copy", "wl-paste", "xauth", "xclip", "xdotool", "xsel", "xset", "ydotool"} {
		if err := ValidateExecBinary(name); err != nil {
			t.Fatalf("expected %q to be allowlisted, got %v", name, err)
		}
	}
}

func TestValidateExecBinaryNormalizesWindowsExecutableExtension(t *testing.T) {
	t.Setenv(envExecAllowlistMode, "")
	t.Setenv(envExecAllowedBinaries, "")
	for _, name := range []string{
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\netsh.exe`,
		`C:\Windows\System32\sc.exe`,
		`C:\Windows\System32\schtasks.exe`,
		`C:\Windows\System32\wevtutil.exe`,
		`C:\Users\operator\AppData\Local\Microsoft\WindowsApps\winget.exe`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE`,
	} {
		if err := ValidateExecBinary(name); err != nil {
			t.Fatalf("expected Windows executable %q to match the extensionless allowlist: %v", name, err)
		}
	}
}

func TestValidateShellCommandBlocksKnownDangerousToken(t *testing.T) {
	t.Setenv(envShellBlockedSubstrings, "rm -rf /")
	if err := ValidateShellCommand("echo ok && rm -rf /tmp"); err == nil {
		t.Fatalf("expected blocked shell command")
	}
}

func TestValidateShellCommandAllowlist(t *testing.T) {
	t.Setenv(envShellAllowlistMode, "true")
	t.Setenv(envShellAllowlistPrefixes, "uname,uptime")
	if err := ValidateShellCommand("uptime"); err != nil {
		t.Fatalf("expected allowed command, got %v", err)
	}
	if err := ValidateShellCommand("ls -la"); err == nil {
		t.Fatalf("expected non-allowlisted command to be blocked")
	}
}

func TestValidateShellCommandRejectsPrefixAndShellOperatorBypasses(t *testing.T) {
	t.Setenv(envShellAllowlistMode, "true")
	t.Setenv(envShellAllowlistPrefixes, "uptime,systemctl status")

	for _, command := range []string{
		"uptime-now",
		"uptime; id",
		"uptime && id",
		"uptime | id",
		"systemctl statusx sshd",
		"systemctl status sshd > /tmp/output",
		"uptime\nid",
	} {
		if err := ValidateShellCommand(command); err == nil {
			t.Fatalf("expected bypass attempt %q to be rejected", command)
		}
	}
}

func TestParseCommandLinePreservesLiteralQuotedArguments(t *testing.T) {
	args, err := ParseCommandLine(`grep "hello world" '/tmp/a file'`)
	if err != nil {
		t.Fatalf("ParseCommandLine: %v", err)
	}
	want := []string{"grep", "hello world", "/tmp/a file"}
	if len(args) != len(want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %#v, want %#v", args, want)
		}
	}
}

func TestValidateShellCommandAllowlistEnabledByDefault(t *testing.T) {
	t.Setenv(envShellAllowlistMode, "")
	if err := ValidateShellCommand("uptime"); err != nil {
		t.Fatalf("expected uptime to be allowlisted by default, got %v", err)
	}
	if err := ValidateShellCommand("echo hello"); err == nil {
		t.Fatalf("expected non-allowlisted command to be blocked by default")
	}
}

func TestValidateShellCommandBlocksShutdownVariants(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{"shutdown now", "shutdown now"},
		{"shutdown -h now (original blocked form)", "shutdown -h now"},
		{"shutdown with flags -P", "shutdown -P now"},
		{"shutdown with mixed case", "SHUTDOWN -h now"},
		{"sudo shutdown", "sudo shutdown -h now"},
		{"chained shutdown", "echo hi && shutdown -r now"},
		{"reboot command", "reboot"},
		{"reboot with sudo", "sudo reboot"},
		{"halt command", "halt"},
		{"poweroff command", "poweroff"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateShellCommand(tc.command); err == nil {
				t.Fatalf("expected %q to be blocked, but it was allowed", tc.command)
			}
		})
	}
}

func TestValidateShellCommandDoesNotBlockShutdownSubstring(t *testing.T) {
	// "shutdown" embedded inside another word (e.g. a filename with a dot)
	// should not be blocked, because the dot makes it a distinct token.
	cases := []struct {
		name    string
		command string
	}{
		{"cat file with shutdown in name via dot", "cat shutdown.log"},
		{"ls shutdown config file", "ls /etc/shutdown.conf"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateShellCommand(tc.command); err != nil {
				t.Fatalf("expected %q to be allowed, but it was blocked: %v", tc.command, err)
			}
		})
	}
}
