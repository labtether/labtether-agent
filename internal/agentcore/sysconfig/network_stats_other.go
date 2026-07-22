//go:build !linux && !darwin

package sysconfig

import gopsutilnet "github.com/shirou/gopsutil/v4/net"

// ReadIfaceStats reads real per-interface counters through gopsutil on Windows,
// FreeBSD, and other platforms without the Linux sysfs or Darwin netstat
// implementations. The legacy signature cannot expose collection errors, so an
// unavailable counter source remains a bounded zero-value fallback.
func ReadIfaceStats(name string) (rxBytes, txBytes, rxPackets, txPackets uint64) {
	rxBytes, txBytes, rxPackets, txPackets, err := readIfaceStatsPortableWith(name, gopsutilnet.IOCounters)
	if err != nil {
		return 0, 0, 0, 0
	}
	return rxBytes, txBytes, rxPackets, txPackets
}

// ReadIfaceStatsBatch takes one OS counter snapshot and resolves every
// requested interface from it, avoiding one full gopsutil query per interface.
func ReadIfaceStatsBatch(names []string) (map[string]IfaceStats, error) {
	stats, err := readIfaceStatsBatchPortableWith(names, gopsutilnet.IOCounters)
	if err != nil {
		return stats, err
	}
	return stats, nil
}
