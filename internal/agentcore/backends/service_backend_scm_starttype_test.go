package backends

import (
	"context"
	"errors"
	"testing"

	"github.com/labtether/protocol"
)

// Every Windows service used to show "unknown" in the Services page's enabled
// column, because sc.exe query does not report start types.
func TestApplyServiceStartTypesFillsEnabled(t *testing.T) {
	services := []protocol.ServiceInfo{{Name: "EventLog", Enabled: "unknown"}, {Name: "Fax", Enabled: "unknown"},
		{Name: "RemoteRegistry", Enabled: "unknown"}, {Name: "NotReadable", Enabled: "unknown"}}
	applyServiceStartTypes(services, func(names []string) map[string]string {
		if len(names) != 4 {
			t.Fatalf("lookup names = %v", names)
		}
		return map[string]string{"eventlog": scStartTypeWord(scStartAuto), "fax": scStartTypeWord(scStartDemand),
			"remoteregistry": scStartTypeWord(scStartDisabled)}
	})
	want := []string{"enabled", "manual", "disabled", "unknown"}
	for i, svc := range services {
		if svc.Enabled != want[i] {
			t.Errorf("%s enabled = %q, want %q", svc.Name, svc.Enabled, want[i])
		}
	}
}

// sc.exe puts the meaning of a failure code after a blank line; the person
// must see both on the one line the Hub shows.
func TestWindowsServiceActionErrorKeepsMeaning(t *testing.T) {
	original := RunWindowsServiceCommand
	t.Cleanup(func() { RunWindowsServiceCommand = original })
	RunWindowsServiceCommand = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("[SC] StartService: OpenService FAILED 1060:\r\n\r\nThe specified service does not exist as an installed service.\r\n\r\n"), errors.New("exit status 1060")
	}
	output, err := (WindowsServiceBackend{}).PerformAction("start", "ltqa-no-such")
	if err == nil {
		t.Fatal("PerformAction returned no error")
	}
	want := "[SC] StartService: OpenService FAILED 1060: The specified service does not exist as an installed service."
	if output != want {
		t.Fatalf("output = %q, want %q", output, want)
	}
}
