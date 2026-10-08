package docker

import (
	"context"
	"github.com/labtether/protocol"
	"log"
	"sort"
	"strings"
	"time"
)

type dockerStatsSchedule struct {
	interval   time.Duration
	nextSample time.Time
	lastStats  protocol.DockerContainerStats
	hasSample  bool
}

func deriveDockerStatsPollInterval(base time.Duration) time.Duration {
	poll := base / 2
	if poll < dockerStatsPollMinInterval {
		poll = dockerStatsPollMinInterval
	}
	if poll > dockerStatsPollMaxInterval {
		poll = dockerStatsPollMaxInterval
	}
	return poll
}

func (dc *DockerCollector) queueStatsTrigger() {
	if dc == nil || dc.statsTriggerCh == nil {
		return
	}
	select {
	case dc.statsTriggerCh <- struct{}{}:
	default:
	}
}

// runStats periodically collects per-container stats and sends them to the hub.
func (dc *DockerCollector) runStats(ctx context.Context) {
	ticker := time.NewTicker(deriveDockerStatsPollInterval(dc.interval))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dc.collectAndSendStats(ctx)
		case <-dc.statsTriggerCh:
			dc.collectAndSendStats(ctx)
		}
	}
}

func (dc *DockerCollector) collectAndSendStats(ctx context.Context) {
	if !dc.transportConnected() {
		return
	}

	now := time.Now()
	runningIDs := dc.currentRunningContainerIDs()
	runningHash := strings.Join(runningIDs, ",")
	runningSet := make(map[string]struct{}, len(runningIDs))
	for _, containerID := range runningIDs {
		runningSet[containerID] = struct{}{}
	}

	dc.statsMu.Lock()
	for id := range dc.statsSchedule {
		if _, ok := runningSet[id]; !ok {
			delete(dc.statsSchedule, id)
		}
	}
	for _, id := range runningIDs {
		if _, ok := dc.statsSchedule[id]; !ok {
			base := dc.defaultStatsInterval()
			dc.statsSchedule[id] = &dockerStatsSchedule{interval: base, nextSample: now}
		}
	}
	var due []string
	for _, id := range runningIDs {
		schedule := dc.statsSchedule[id]
		if schedule == nil {
			continue
		}
		if !schedule.hasSample || !now.Before(schedule.nextSample) {
			due = append(due, id)
		}
	}
	if len(due) > dockerStatsMaxSamplesTick {
		due = due[:dockerStatsMaxSamplesTick]
	}
	dc.statsMu.Unlock()

	sampled := 0
	for _, containerID := range due {
		raw, err := dc.client.containerStats(ctx, containerID)
		now = time.Now()
		dc.statsMu.Lock()
		schedule := dc.statsSchedule[containerID]
		if schedule == nil {
			dc.statsMu.Unlock()
			continue
		}
		if err != nil {
			schedule.interval = dc.nextStatsInterval(schedule.interval, protocol.DockerContainerStats{}, true)
			schedule.nextSample = now.Add(schedule.interval)
			dc.statsMu.Unlock()
			continue
		}
		stats := calculateStats(containerID, raw)
		schedule.lastStats = stats
		schedule.hasSample = true
		schedule.interval = dc.nextStatsInterval(schedule.interval, stats, false)
		schedule.nextSample = now.Add(schedule.interval)
		dc.statsMu.Unlock()
		sampled++
	}

	dc.statsMu.Lock()
	payloadStats := make([]protocol.DockerContainerStats, 0, len(runningIDs))
	for _, containerID := range runningIDs {
		schedule := dc.statsSchedule[containerID]
		if schedule != nil && schedule.hasSample {
			payloadStats = append(payloadStats, schedule.lastStats)
		}
	}
	sort.Slice(payloadStats, func(i, j int) bool {
		return payloadStats[i].ID < payloadStats[j].ID
	})
	shouldSend := sampled > 0 || runningHash != dc.lastRunningSetHash || (len(runningIDs) > 0 && now.Sub(dc.lastStatsPublish) >= dc.interval)
	dc.statsMu.Unlock()

	if !shouldSend {
		return
	}

	payload := protocol.DockerStatsData{HostID: dc.currentAssetID(), Containers: payloadStats}
	if err := dc.sendDockerMessage(protocol.MsgDockerStats, payload); err != nil {
		log.Printf("docker: failed to send stats: %v", err)
		return
	}

	dc.statsMu.Lock()
	dc.lastRunningSetHash = runningHash
	dc.lastStatsPublish = time.Now()
	dc.statsMu.Unlock()
}

func (dc *DockerCollector) defaultStatsInterval() time.Duration {
	base := dc.interval
	if base <= 0 {
		base = defaultDockerDiscoveryInterval
	}
	if base < dockerStatsPollMinInterval {
		base = dockerStatsPollMinInterval
	}
	return base
}

func (dc *DockerCollector) minStatsInterval() time.Duration {
	interval := dc.interval / 2
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	if dc.interval > 0 && interval > dc.interval {
		interval = dc.interval
	}
	if interval < dockerStatsPollMinInterval {
		interval = dockerStatsPollMinInterval
	}
	return interval
}

func (dc *DockerCollector) maxStatsInterval() time.Duration {
	interval := dc.interval * 6
	if interval < 2*time.Minute {
		interval = 2 * time.Minute
	}
	if interval > 10*time.Minute {
		interval = 10 * time.Minute
	}
	return interval
}

func (dc *DockerCollector) nextStatsInterval(current time.Duration, stats protocol.DockerContainerStats, hadError bool) time.Duration {
	if current <= 0 {
		current = dc.defaultStatsInterval()
	}
	minInterval := dc.minStatsInterval()
	maxInterval := dc.maxStatsInterval()
	if hadError {
		next := current * 2
		if next > maxInterval {
			next = maxInterval
		}
		return next
	}
	isHot := stats.CPUPercent >= dockerStatsHotCPUThreshold || stats.MemoryPercent >= dockerStatsHotMemThreshold || stats.PIDs >= dockerStatsHotPIDThreshold
	if isHot {
		next := current / 2
		if next < minInterval {
			next = minInterval
		}
		return next
	}
	next := current + current/2
	if next > maxInterval {
		next = maxInterval
	}
	return next
}

// calculateStats converts raw Docker stats into our ContainerStats format.
func calculateStats(containerID string, raw DockerStatsResponse) protocol.DockerContainerStats {
	// CPU percent: (delta_container / delta_system) * num_cpus * 100
	cpuPercent := 0.0
	cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(raw.CPUStats.SystemCPUUsage - raw.PreCPUStats.SystemCPUUsage)
	if sysDelta > 0 && cpuDelta > 0 {
		cpus := raw.CPUStats.OnlineCPUs
		if cpus == 0 {
			cpus = 1
		}
		cpuPercent = (cpuDelta / sysDelta) * float64(cpus) * 100.0
	}

	// Memory percent
	memPercent := 0.0
	if raw.MemoryStats.Limit > 0 {
		memPercent = float64(raw.MemoryStats.Usage) / float64(raw.MemoryStats.Limit) * 100.0
	}

	// Network I/O (sum across all interfaces)
	var netRX, netTX int64
	for _, iface := range raw.Networks {
		netRX += iface.RxBytes
		netTX += iface.TxBytes
	}

	// Block I/O
	var blockRead, blockWrite int64
	for _, entry := range raw.BlkioStats.IoServiceBytesRecursive {
		switch entry.Op {
		case "Read", "read":
			blockRead += entry.Value
		case "Write", "write":
			blockWrite += entry.Value
		}
	}

	return protocol.DockerContainerStats{
		ID:              containerID,
		CPUPercent:      cpuPercent,
		MemoryBytes:     raw.MemoryStats.Usage,
		MemoryLimit:     raw.MemoryStats.Limit,
		MemoryPercent:   memPercent,
		NetRXBytes:      netRX,
		NetTXBytes:      netTX,
		BlockReadBytes:  blockRead,
		BlockWriteBytes: blockWrite,
		PIDs:            raw.PidsStats.Current,
	}
}
