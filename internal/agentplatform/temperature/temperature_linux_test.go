//go:build linux

package temperature

import (
	"os"
	"path/filepath"
	"testing"
)

// Fault: when one sensor could not be read, gopsutil's readings were thrown
// away and the agent reported the hottest sensor of any kind, so a hot disk
// was shown as the host temperature in place of the CPU's.
func TestReadCelsiusKeepsCPUPriorityWhenOneSensorFails(t *testing.T) {
	sys := t.TempDir()
	write := func(rel, text string) {
		path := filepath.Join(sys, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("class/hwmon/hwmon0/name", "nvme\n")
	write("class/hwmon/hwmon0/temp1_input", "70850\n")
	write("class/hwmon/hwmon0/temp1_label", "Composite\n")
	write("class/hwmon/hwmon1/name", "coretemp\n")
	write("class/hwmon/hwmon1/temp1_input", "52000\n")
	write("class/hwmon/hwmon1/temp1_label", "Package id 0\n")
	// A sensor that cannot be read: its input is a directory, so the read
	// fails with "is a directory" even for root.
	write("class/hwmon/hwmon2/name", "acpitz\n")
	if err := os.MkdirAll(filepath.Join(sys, "class/hwmon/hwmon2/temp1_input"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOST_SYS", sys)
	oldGlobs := linuxTemperatureGlobs
	t.Cleanup(func() { linuxTemperatureGlobs = oldGlobs })
	linuxTemperatureGlobs = []string{filepath.Join(sys, "class/hwmon/hwmon*/temp*_input")}

	value, err := ReadCelsius()
	if err != nil {
		t.Fatalf("ReadCelsius error: %v", err)
	}
	if value == nil {
		t.Fatal("no temperature, want the CPU sensor's 52")
	}
	if *value != 52 {
		t.Fatalf("temperature=%v, want the CPU sensor's 52 (the disk is 70.85)", *value)
	}
}
