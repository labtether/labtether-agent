//go:build linux

package linux

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Fault: guest and guest_nice time, which the kernel already counts in user
// and nice, was added to the CPU total a second time, so a host that runs
// VMs (a Proxmox node, for example) reported CPU use higher than it was.
func TestCollectCountsGuestTimeOnce(t *testing.T) {
	restore := swapProviderTelemetryFixtures(t)
	defer restore()
	dir := t.TempDir()
	procStatPath = filepath.Join(dir, "stat")
	procMeminfoPath = filepath.Join(dir, "missing")
	procNetDevPath = filepath.Join(dir, "missing")
	statfsFunc = func(string, *syscall.Statfs_t) error { return nil }
	provider := &Provider{readTemperature: func() (*float64, error) { return nil, nil }}

	// Ten seconds on a 4-core host (4000 ticks at 100 Hz). Deltas:
	// user +1800 (guest +1600 of it), nice +100 (guest_nice +100 of it),
	// system +200, idle +1800, iowait +20, softirq +80.
	// Total of the first eight columns: 1800+100+200+1800+20+0+80+0 = 4000.
	// Idle (idle+iowait): 1820. Busy: (4000-1820)/4000 = 54.5 %.
	// Adding guest and guest_nice again gives (5700-1820)/5700 = 68.07 %.
	writeFixture(t, procStatPath, "cpu  4705 120 1503 89012 312 0 85 0 2400 30\n")
	start := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	if _, err := provider.Collect(start); err != nil {
		t.Fatalf("first collect: %v", err)
	}
	writeFixture(t, procStatPath, "cpu  6505 220 1703 90812 332 0 165 0 4000 130\n")
	second, err := provider.Collect(start.Add(10 * time.Second))
	if err != nil {
		t.Fatalf("second collect: %v", err)
	}
	assertFloat(t, second.CPUPercent, 54.5, 0.001, "cpu percent with guest time")

	// A kernel with only seven columns still adds all of them.
	writeFixture(t, procStatPath, "cpu  10 0 5 80 5 0 0\n")
	sample, err := readCPUSample()
	if err != nil || sample.total != 100 || sample.idle != 85 {
		t.Fatalf("seven-column line: sample=%+v err=%v, want total 100 idle 85", sample, err)
	}
}

// Fault: a kernel without a MemAvailable line (before 3.14) read as zero
// memory available, so the host showed 100 % memory used.
func TestMemoryWithoutMemAvailableIsEstimated(t *testing.T) {
	restore := swapProviderTelemetryFixtures(t)
	defer restore()
	procMeminfoPath = filepath.Join(t.TempDir(), "meminfo")

	// Available = MemFree + Buffers + Cached = 512344+301220+4211532 = 5025096 kB.
	// Used = (8058888-5025096)/8058888 = 37.645 %.
	writeFixture(t, procMeminfoPath, "MemTotal:        8058888 kB\n"+
		"MemFree:          512344 kB\n"+
		"Buffers:          301220 kB\n"+
		"Cached:          4211532 kB\n"+
		"SwapCached:         1024 kB\n"+
		"Active:          4102332 kB\n"+
		"Inactive:        2733000 kB\n"+
		"SwapTotal:       2097148 kB\n"+
		"SwapFree:        2090000 kB\n")
	assertFloat(t, readMemoryUsagePercent(), 37.645, 0.001, "memory percent without MemAvailable")

	// A MemAvailable line that says 0 is used as it is.
	writeFixture(t, procMeminfoPath, "MemTotal:        8058888 kB\n"+
		"MemFree:          512344 kB\n"+
		"MemAvailable:          0 kB\n"+
		"Buffers:          301220 kB\n"+
		"Cached:          4211532 kB\n")
	assertFloat(t, readMemoryUsagePercent(), 100, 0.001, "memory percent with MemAvailable 0")
}
