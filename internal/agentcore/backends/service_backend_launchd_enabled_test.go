package backends

import (
	"context"
	"errors"
	"testing"

	"github.com/labtether/protocol"
)

// Every macOS launchd job showed "unknown" in the Services page's enabled
// column; launchctl list has no enabled state.
func TestApplyLaunchdEnabledReadsOverrides(t *testing.T) {
	original := RunLaunchctlPrintDisabled
	t.Cleanup(func() { RunLaunchctlPrintDisabled = original })
	RunLaunchctlPrintDisabled = func(_ context.Context, domain string) ([]byte, error) {
		if domain == "system" || domain[:4] == "gui/" {
			return []byte("\n\tdisabled services = {\n\t\t\"com.example.off\" => disabled\n\t\t\"com.example.on\" => enabled\n" +
				"\t\t\"com.example.legacy\" => true\n\t}\n\n\tlogin item associations = {\n\t\t\"com.example.on\" => x\n\t}\n"), nil
		}
		return nil, errors.New("no such domain")
	}
	services := ParseLaunchctlListOutput("PID\tStatus\tLabel\n123\t0\tcom.example.on\n-\t0\tcom.example.off\n-\t0\tcom.example.legacy\n-\t0\tcom.example.plain\n")
	applyLaunchdEnabled(context.Background(), services)
	want := map[string]string{"com.example.on": "enabled", "com.example.off": "disabled", "com.example.legacy": "disabled", "com.example.plain": "enabled"}
	for _, svc := range services {
		if svc.Enabled != want[svc.Name] {
			t.Errorf("%s enabled = %q, want %q", svc.Name, svc.Enabled, want[svc.Name])
		}
	}
}

func TestApplyLaunchdEnabledKeepsUnknownWithoutLaunchd(t *testing.T) {
	original := RunLaunchctlPrintDisabled
	t.Cleanup(func() { RunLaunchctlPrintDisabled = original })
	RunLaunchctlPrintDisabled = func(context.Context, string) ([]byte, error) { return nil, errors.New("launchctl failed") }
	services := []protocol.ServiceInfo{{Name: "com.example.on", Enabled: "unknown"}}
	applyLaunchdEnabled(context.Background(), services)
	if services[0].Enabled != "unknown" {
		t.Fatalf("enabled = %q, want unknown", services[0].Enabled)
	}
}
