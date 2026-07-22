package sysconfig

import (
	"fmt"
	"strings"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
)

type portableIOCountersFunc func(pernic bool) ([]gopsutilnet.IOCountersStat, error)

func readIfaceStatsPortableWith(
	name string,
	readCounters portableIOCountersFunc,
) (rxBytes, txBytes, rxPackets, txPackets uint64, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, 0, 0, 0, fmt.Errorf("network interface name is required")
	}
	stats, err := readIfaceStatsBatchPortableWith([]string{name}, readCounters)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	stat, ok := stats[name]
	if !ok {
		return 0, 0, 0, 0, fmt.Errorf("network interface %q was not present in per-interface counters", name)
	}
	return stat.RXBytes, stat.TXBytes, stat.RXPackets, stat.TXPackets, nil
}

func readIfaceStatsBatchPortableWith(
	names []string,
	readCounters portableIOCountersFunc,
) (map[string]IfaceStats, error) {
	stats := make(map[string]IfaceStats, len(names))
	if len(names) == 0 {
		return stats, nil
	}

	counters, err := readCounters(true)
	if err != nil {
		return nil, fmt.Errorf("read per-interface network counters: %w", err)
	}

	exact := make(map[string]IfaceStats, len(counters))
	folded := make(map[string]IfaceStats, len(counters))
	for _, counter := range counters {
		stat := IfaceStats{
			RXBytes:   counter.BytesRecv,
			TXBytes:   counter.BytesSent,
			RXPackets: counter.PacketsRecv,
			TXPackets: counter.PacketsSent,
		}
		exact[counter.Name] = stat
		folded[strings.ToLower(counter.Name)] = stat
	}

	// Prefer exact matches. The folded lookup is a bounded fallback for Windows
	// where interface-name casing can vary between APIs.
	missing := make([]string, 0)
	for _, rawName := range names {
		name := strings.TrimSpace(rawName)
		if name == "" {
			missing = append(missing, rawName)
			continue
		}
		if stat, ok := exact[name]; ok {
			stats[rawName] = stat
			continue
		}
		if stat, ok := folded[strings.ToLower(name)]; ok {
			stats[rawName] = stat
			continue
		}
		missing = append(missing, name)
	}
	if len(missing) > 0 {
		return stats, fmt.Errorf("network interfaces missing from per-interface counters: %s", strings.Join(missing, ", "))
	}
	return stats, nil
}
