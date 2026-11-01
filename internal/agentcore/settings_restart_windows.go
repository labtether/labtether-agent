//go:build windows

package agentcore

import "golang.org/x/sys/windows/svc"

// settingsRestartExitCode is the exit code of a restart for new settings.
const settingsRestartExitCode = 12

// serviceManagerRestart returns a restart through the Service Control
// Manager when the agent runs as a Windows service, or nil. The agent exits
// with an error code and the service's recovery actions start it again; both
// `labtether-agent.exe install` and the Hub's install script set them.
func serviceManagerRestart() func() error {
	if nativeAppManaged() {
		return nil
	}
	if isService, err := svc.IsWindowsService(); err != nil || !isService {
		return nil
	}
	return func() error {
		agentExitFn(settingsRestartExitCode)
		return nil
	}
}
