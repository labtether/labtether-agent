package backends

import (
	"context"
	"errors"
	"testing"
)

func TestBuildLaunchdSchedule(t *testing.T) {
	payload := map[string]any{
		"StartInterval": float64(300),
		"RunAtLoad":     true,
	}

	schedule := BuildLaunchdSchedule(payload)
	if schedule != "every 300s | @reboot" {
		t.Fatalf("schedule=%q, want %q", schedule, "every 300s | @reboot")
	}
}

func TestBuildLaunchdScheduleCalendar(t *testing.T) {
	payload := map[string]any{
		"StartCalendarInterval": map[string]any{
			"Minute":  float64(15),
			"Hour":    float64(3),
			"Weekday": float64(1),
		},
	}

	schedule := BuildLaunchdSchedule(payload)
	if schedule != "15 3 * * 1" {
		t.Fatalf("schedule=%q, want %q", schedule, "15 3 * * 1")
	}
}

func TestBuildLaunchdCronEntry(t *testing.T) {
	payload := map[string]any{
		"Label": "com.labtether.test-job",
		"ProgramArguments": []any{
			"/usr/bin/env",
			"bash",
			"-lc",
			"echo test",
		},
		"StartInterval": float64(60),
	}

	entry, ok := BuildLaunchdCronEntry(payload, "demo")
	if !ok {
		t.Fatal("expected launchd entry to be built")
	}
	if entry.Source != "launchd" {
		t.Fatalf("source=%q, want launchd", entry.Source)
	}
	if entry.User != "demo" {
		t.Fatalf("user=%q, want demo", entry.User)
	}
	if entry.Command != "/usr/bin/env bash -lc echo test" {
		t.Fatalf("command=%q", entry.Command)
	}
	if entry.Schedule != "every 60s" {
		t.Fatalf("schedule=%q, want every 60s", entry.Schedule)
	}
}

// macOS has no /var/spool/cron or /etc/cron.d: the Cron / Timers tab of every
// Mac device answered "no configured crontab source is readable" and showed no
// launchd jobs either.
func TestDarwinCrontabWithoutACrontabIsNoError(t *testing.T) {
	original := RunDarwinCrontabList
	t.Cleanup(func() { RunDarwinCrontabList = original })
	RunDarwinCrontabList = func(context.Context) ([]byte, error) {
		return []byte("crontab: no crontab for demo\n"), errors.New("exit status 1")
	}
	entries, err := collectDarwinCrontab()
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v, want none and no error", entries, err)
	}

	RunDarwinCrontabList = func(context.Context) ([]byte, error) {
		return []byte("# backups\n30 2 * * * /usr/local/bin/backup.sh\n"), nil
	}
	entries, err = collectDarwinCrontab()
	if err != nil || len(entries) != 1 || entries[0].Schedule != "30 2 * * *" || entries[0].Command != "/usr/local/bin/backup.sh" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}
