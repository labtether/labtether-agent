package sysconfig

import (
	"errors"
	"strings"
	"testing"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
)

func TestReadIfaceStatsPortableWithUsesPerInterfaceCounters(t *testing.T) {
	called := false
	collector := func(pernic bool) ([]gopsutilnet.IOCountersStat, error) {
		called = true
		if !pernic {
			t.Fatal("portable interface stats must request per-interface counters")
		}
		return []gopsutilnet.IOCountersStat{
			{Name: "Ethernet", BytesRecv: 10, BytesSent: 20, PacketsRecv: 1, PacketsSent: 2},
			{Name: "em0", BytesRecv: 100, BytesSent: 200, PacketsRecv: 11, PacketsSent: 22},
		}, nil
	}

	rxBytes, txBytes, rxPackets, txPackets, err := readIfaceStatsPortableWith("em0", collector)
	if err != nil {
		t.Fatalf("read portable interface stats: %v", err)
	}
	if !called {
		t.Fatal("injected counter collector was not called")
	}
	if rxBytes != 100 || txBytes != 200 || rxPackets != 11 || txPackets != 22 {
		t.Fatalf("unexpected counters: rxBytes=%d txBytes=%d rxPackets=%d txPackets=%d", rxBytes, txBytes, rxPackets, txPackets)
	}
}

func TestReadIfaceStatsBatchPortableWithTakesOneSnapshotForMultipleInterfaces(t *testing.T) {
	calls := 0
	collector := func(pernic bool) ([]gopsutilnet.IOCountersStat, error) {
		calls++
		if !pernic {
			t.Fatal("portable interface stats must request per-interface counters")
		}
		return []gopsutilnet.IOCountersStat{
			{Name: "Ethernet", BytesRecv: 10, BytesSent: 20},
			{Name: "em0", BytesRecv: 30, BytesSent: 40},
		}, nil
	}

	stats, err := readIfaceStatsBatchPortableWith([]string{"Ethernet", "em0"}, collector)
	if err != nil {
		t.Fatalf("read portable interface snapshot: %v", err)
	}
	if calls != 1 {
		t.Fatalf("counter snapshots=%d, want exactly one", calls)
	}
	if stats["Ethernet"].RXBytes != 10 || stats["em0"].TXBytes != 40 {
		t.Fatalf("unexpected batched counters: %+v", stats)
	}
}

func TestReadIfaceStatsBatchPortableWithPreservesPartialCountersAndReportsMissing(t *testing.T) {
	collector := func(bool) ([]gopsutilnet.IOCountersStat, error) {
		return []gopsutilnet.IOCountersStat{{Name: "em0", BytesRecv: 30}}, nil
	}

	stats, err := readIfaceStatsBatchPortableWith([]string{"em0", "em1"}, collector)
	if err == nil || !strings.Contains(err.Error(), "em1") {
		t.Fatalf("error=%v, want missing em1 counter error", err)
	}
	if stats["em0"].RXBytes != 30 {
		t.Fatalf("available interface counter was not preserved: %+v", stats)
	}
}

func TestReadIfaceStatsPortableWithMatchesWindowsNameCaseInsensitively(t *testing.T) {
	collector := func(bool) ([]gopsutilnet.IOCountersStat, error) {
		return []gopsutilnet.IOCountersStat{{
			Name:        "Ethernet 2",
			BytesRecv:   7,
			BytesSent:   8,
			PacketsRecv: 9,
			PacketsSent: 10,
		}}, nil
	}

	rxBytes, txBytes, rxPackets, txPackets, err := readIfaceStatsPortableWith("ethernet 2", collector)
	if err != nil {
		t.Fatalf("case-insensitive Windows interface match: %v", err)
	}
	if rxBytes != 7 || txBytes != 8 || rxPackets != 9 || txPackets != 10 {
		t.Fatalf("unexpected counters: %d %d %d %d", rxBytes, txBytes, rxPackets, txPackets)
	}
}

func TestReadIfaceStatsPortableWithPropagatesCollectorFailure(t *testing.T) {
	wantErr := errors.New("counter backend unavailable")
	collector := func(bool) ([]gopsutilnet.IOCountersStat, error) {
		return nil, wantErr
	}

	_, _, _, _, err := readIfaceStatsPortableWith("em0", collector)
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("error=%v, want wrapped collector failure", err)
	}
}

func TestReadIfaceStatsPortableWithRejectsMissingInterface(t *testing.T) {
	collector := func(bool) ([]gopsutilnet.IOCountersStat, error) {
		return []gopsutilnet.IOCountersStat{{Name: "em0"}}, nil
	}

	_, _, _, _, err := readIfaceStatsPortableWith("em1", collector)
	if err == nil || !strings.Contains(err.Error(), "em1") {
		t.Fatalf("error=%v, want missing-interface failure", err)
	}
}
