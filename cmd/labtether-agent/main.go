package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/labtether/labtether-agent/internal/agentcore"
	"github.com/labtether/labtether-agent/internal/agentplatform"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version string

func main() {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("LABTETHER_ALLOW_INSECURE_TRANSPORT")), "true") {
		log.Printf("labtether-agent: WARNING: insecure transport mode is enabled (LABTETHER_ALLOW_INSECURE_TRANSPORT=true)")
	}
	logSecurityModeBanner()

	// Handle Windows-specific service install/uninstall commands before
	// any agent runtime setup (these exit on their own).
	if handleWindowsServiceArgs(os.Args[1:]) {
		return
	}

	cfg := applyLinkedVersion(
		agentcore.LoadConfig("labtether-agent", "8090", agentplatform.DefaultSource()),
		version,
	)
	cliArgs, forceConsole := splitRuntimeArgs(os.Args[1:])
	if handled, exitCode := agentcore.HandleCLICommand(cfg, cliArgs); handled {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return
	}
	provider := agentplatform.NewProvider(cfg.AssetID, cfg.Source)

	// Determine whether to run as a Windows Service or in interactive mode.
	// The --console flag forces interactive mode even when launched by the SCM.
	if !forceConsole && isWindowsService() {
		log.Printf("labtether-agent: starting as Windows Service")
		if err := runAsWindowsService(cfg, provider); err != nil {
			log.Fatalf("%s service exited with error: %v", cfg.Name, err)
		}
		return
	}

	// Interactive (foreground) mode — signal-based lifecycle.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, stopParentMonitor, err := contextWithConfiguredParent(
		ctx,
		os.Getenv(envParentPID),
	)
	if err != nil {
		// A configured parent is a containment boundary for native wrappers.
		// If it is invalid or already unavailable, do not start an orphan.
		log.Fatalf("labtether-agent: parent lifecycle unavailable: %v", err)
	}
	defer stopParentMonitor()

	if err := agentcore.Run(ctx, cfg, provider); err != nil {
		log.Fatalf("%s exited with error: %v", cfg.Name, err)
	}
}

// splitRuntimeArgs removes flags consumed by the process host before handing
// remaining arguments to the settings/identity/update CLI dispatcher.
func splitRuntimeArgs(args []string) (cliArgs []string, forceConsole bool) {
	cliArgs = make([]string, 0, len(args))
	for _, arg := range args {
		if strings.EqualFold(strings.TrimSpace(arg), "--console") {
			forceConsole = true
			continue
		}
		cliArgs = append(cliArgs, arg)
	}
	return cliArgs, forceConsole
}

// applyLinkedVersion makes the release version injected with -ldflags visible
// to the runtime, CLI help, hub handshake, and local status API. Development
// builds retain the version derived from Go build metadata.
func applyLinkedVersion(cfg agentcore.RuntimeConfig, linkedVersion string) agentcore.RuntimeConfig {
	if linkedVersion = strings.TrimSpace(linkedVersion); linkedVersion != "" {
		cfg.Version = linkedVersion
	}
	return cfg
}
