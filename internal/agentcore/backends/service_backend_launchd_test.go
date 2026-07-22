package backends

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseLaunchctlListOutput(t *testing.T) {
	raw := `PID	Status	Label
123	0	com.example.running
-	0	com.example.stopped
-	78	com.example.failed
`

	services := ParseLaunchctlListOutput(raw)
	if len(services) != 3 {
		t.Fatalf("len(services)=%d, want 3", len(services))
	}

	if services[0].Name != "com.example.running" || services[0].ActiveState != "active" || services[0].SubState != "running" {
		t.Fatalf("unexpected running service parse: %+v", services[0])
	}
	if services[1].Name != "com.example.stopped" || services[1].ActiveState != "inactive" || services[1].SubState != "stopped" {
		t.Fatalf("unexpected stopped service parse: %+v", services[1])
	}
	if services[2].Name != "com.example.failed" || services[2].SubState != "failed" {
		t.Fatalf("unexpected failed service parse: %+v", services[2])
	}
}

func TestBuildLaunchctlActionCandidates(t *testing.T) {
	candidates := BuildLaunchctlActionCandidates("start", "com.example.job")
	if len(candidates) < 2 {
		t.Fatalf("expected multiple launchctl candidates, got %d", len(candidates))
	}

	last := candidates[len(candidates)-1]
	if len(last) != 1 || !slices.Equal(last[0], []string{"start", "com.example.job"}) {
		t.Fatalf("unexpected fallback start candidate: %v", last)
	}
}

func TestRunLaunchctlRestartFallbackRunsStopThenStart(t *testing.T) {
	var calls [][]string
	runner := func(args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		switch args[0] {
		case "kickstart":
			return "", errors.New("target not found")
		case "stop":
			return "stopped", nil
		case "start":
			return "started", nil
		default:
			return "", errors.New("unexpected command")
		}
	}

	output, err := runLaunchctlActionCandidatesWithRunner(
		BuildLaunchctlActionCandidates("restart", "com.example.job"),
		runner,
	)
	if err != nil {
		t.Fatalf("restart fallback: %v", err)
	}
	if output != "started" {
		t.Fatalf("output=%q, want started", output)
	}
	if len(calls) < 2 ||
		!slices.Equal(calls[len(calls)-2], []string{"stop", "com.example.job"}) ||
		!slices.Equal(calls[len(calls)-1], []string{"start", "com.example.job"}) {
		t.Fatalf("restart fallback calls=%v", calls)
	}
}

func TestRunLaunchctlRestartFallbackReportsStartFailure(t *testing.T) {
	var calls [][]string
	runner := func(args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		switch args[0] {
		case "kickstart":
			return "", errors.New("target not found")
		case "stop":
			return "stopped", nil
		case "start":
			return "permission denied", errors.New("exit status 1")
		default:
			return "", errors.New("unexpected command")
		}
	}

	output, err := runLaunchctlActionCandidatesWithRunner(
		BuildLaunchctlActionCandidates("restart", "com.example.job"),
		runner,
	)
	if err == nil {
		t.Fatal("expected restart fallback to report start failure")
	}
	if !strings.Contains(err.Error(), "launchctl start com.example.job") {
		t.Fatalf("error=%q, want start failure", err)
	}
	if output != "permission denied" {
		t.Fatalf("output=%q, want failing start output", output)
	}
	if len(calls) < 2 ||
		!slices.Equal(calls[len(calls)-2], []string{"stop", "com.example.job"}) ||
		!slices.Equal(calls[len(calls)-1], []string{"start", "com.example.job"}) {
		t.Fatalf("restart fallback calls=%v", calls)
	}
}
