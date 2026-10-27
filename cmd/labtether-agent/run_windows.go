//go:build windows

package main

import (
	"fmt"
	"os"

	"github.com/labtether/labtether-agent/internal/agentcore"
	"github.com/labtether/labtether-agent/internal/agentplatform/windows"
)

func handleWindowsServiceArgs(args []string) (handled bool) {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "install":
		if err := windows.InstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		return true
	case "uninstall":
		if err := windows.UninstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		// Remove the Hub SSH key line the service added, so the Hub's key
		// does not keep administrator access after uninstall.
		changed, err := agentcore.RemoveRecordedHubSSHKey(agentcore.TokenFilePath())
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not remove the Hub SSH key: %v\n", err)
			os.Exit(1)
		}
		if changed != "" {
			fmt.Printf("Removed the Hub SSH key from %s.\n", changed)
		}
		return true
	}
	return false
}

func isWindowsService() bool {
	return windows.IsWindowsService()
}

func runAsWindowsService(cfg agentcore.RuntimeConfig, provider agentcore.TelemetryProvider) error {
	return windows.RunAsService(cfg, provider)
}
