//go:build !linux && !windows

package agentcore

// serviceManagerRestart returns nil: on macOS the native app owns the agent,
// and other systems have no supported service manager restart yet.
func serviceManagerRestart() func() error { return nil }
