package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// A failed initial sample must respect backoff; otherwise an unavailable
// Docker stats endpoint is retried on every poll indefinitely.
func TestStatsInitialFailureBackoffAndRecovery(t *testing.T) {
	var requests atomic.Int32
	var recovered atomic.Bool
	srv, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !recovered.Load() {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(DockerStatsResponse{})
	}))
	defer srv.Close()
	transport := newRecordingCollectorTransport(true)
	collector := NewTestCollector(srv.URL, transport, "asset-1")
	collector.client = client
	collector.updateRunningContainerIDs(map[string]struct{}{"ct-1": {}})

	collector.collectAndSendStats(context.Background())
	for range 5 {
		collector.collectAndSendStats(context.Background())
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests during backoff = %d, want 1", got)
	}
	recovered.Store(true)
	collector.statsSchedule["ct-1"].nextSample = time.Now().Add(-time.Second)
	collector.collectAndSendStats(context.Background())
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests after backoff = %d, want 2", got)
	}
	if !collector.statsSchedule["ct-1"].hasSample {
		t.Fatal("successful retry did not recover stats")
	}
}

func TestStatsIdleAndInventoryRemoval(t *testing.T) {
	transport := newRecordingCollectorTransport(true)
	collector := NewTestCollector("https://unused.invalid", transport, "asset-1")
	now := time.Now()
	running := map[string]struct{}{"ct-b": {}, "ct-a": {}}
	collector.updateRunningContainerIDs(running)
	// Discovery inputs and exported lists must not be able to mutate the
	// snapshot used by a concurrent stats poll.
	delete(running, "ct-a")
	exported := collector.CurrentRunningContainerIDs()
	exported[0] = "unexpected"
	for _, id := range []string{"ct-b", "ct-a"} {
		collector.statsSchedule[id] = &dockerStatsSchedule{
			hasSample: true, nextSample: now.Add(time.Hour),
			lastStats: protocol.DockerContainerStats{ID: id},
		}
	}
	collector.lastRunningSetHash = "ct-a,ct-b"
	collector.lastStatsPublish = now
	collector.collectAndSendStats(context.Background())
	if transport.MessageCount() != 0 {
		t.Fatal("idle poll published unchanged stats early")
	}
	collector.lastStatsPublish = now.Add(-collector.interval)
	collector.collectAndSendStats(context.Background())
	var payload protocol.DockerStatsData
	if err := json.Unmarshal(transport.messages[0].Data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Containers) != 2 || payload.Containers[0].ID != "ct-a" || payload.Containers[1].ID != "ct-b" {
		t.Fatalf("published stats ordering changed: %+v", payload.Containers)
	}
	collector.updateRunningContainerIDs(nil)
	collector.collectAndSendStats(context.Background())
	if err := json.Unmarshal(transport.messages[1].Data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Containers) != 0 || len(collector.statsSchedule) != 0 {
		t.Fatal("removed containers retained stats")
	}
}

// Discovery may replace inventory while a stats request is in flight. The
// in-flight poll must keep a coherent snapshot, then drop old IDs on the next.
func TestStatsSnapshotSurvivesConcurrentDiscovery(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	srv, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "ct-old") {
			close(started)
			select {
			case <-resume:
			case <-r.Context().Done():
				return
			}
		}
		_ = json.NewEncoder(w).Encode(DockerStatsResponse{})
	}))
	defer srv.Close()
	transport := newRecordingCollectorTransport(true)
	collector := NewTestCollector(srv.URL, transport, "asset-1")
	collector.client = client
	collector.updateRunningContainerIDs(map[string]struct{}{"ct-old": {}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		collector.collectAndSendStats(ctx)
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("initial stats request did not start")
	}
	collector.updateRunningContainerIDs(map[string]struct{}{"ct-new": {}})
	close(resume)
	<-finished
	collector.collectAndSendStats(ctx)
	if transport.MessageCount() != 2 {
		t.Fatalf("messages = %d, want 2", transport.MessageCount())
	}
	for index, id := range []string{"ct-old", "ct-new"} {
		var payload protocol.DockerStatsData
		if err := json.Unmarshal(transport.messages[index].Data, &payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Containers) != 1 || payload.Containers[0].ID != id {
			t.Fatalf("poll %d lost inventory snapshot: %+v", index, payload.Containers)
		}
	}
	if _, ok := collector.statsSchedule["ct-old"]; ok {
		t.Fatal("removed container retained a stats schedule")
	}
}

// Hot containers can be due on every stats tick. The per-tick request bound
// must not let the first sorted IDs prevent later containers being sampled.
func TestStatsHotContainersDoNotStarveLaterInventory(t *testing.T) {
	var seen sync.Map
	var requests atomic.Int32
	srv, client := newSecureDockerClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		seen.Store(strings.Split(r.URL.Path, "/")[2], true)
		var stats DockerStatsResponse
		stats.PidsStats.Current = dockerStatsHotPIDThreshold
		_ = json.NewEncoder(w).Encode(stats)
	}))
	defer srv.Close()
	collector := NewTestCollector(srv.URL, newRecordingCollectorTransport(true), "asset-1")
	collector.client = client
	running := make(map[string]struct{})
	for i := range dockerStatsMaxSamplesTick + 1 {
		running[fmt.Sprintf("ct-%04d", i)] = struct{}{}
	}
	collector.updateRunningContainerIDs(running)
	for tick := range 2 {
		for _, schedule := range collector.statsSchedule {
			schedule.nextSample = time.Now().Add(-time.Second)
		}
		collector.collectAndSendStats(context.Background())
		if got := int(requests.Load()); got != (tick+1)*dockerStatsMaxSamplesTick {
			t.Fatalf("request budget changed: tick %d, requests %d", tick, got)
		}
	}
	seenCount := 0
	seen.Range(func(_, _ any) bool { seenCount++; return true })
	if seenCount != len(running) {
		t.Fatalf("hot inventory starved: sampled %d of %d containers", seenCount, len(running))
	}
}

func BenchmarkStatsIdlePoll(b *testing.B) {
	for _, count := range []int{10, 500, 1000} {
		b.Run(fmt.Sprintf("containers-%d", count), func(b *testing.B) {
			collector := NewTestCollector("https://unused.invalid", newRecordingCollectorTransport(true), "asset-1")
			now := time.Now()
			running := make(map[string]struct{}, count)
			for index := range count {
				id := fmt.Sprintf("ct-%04d", index)
				running[id] = struct{}{}
				collector.statsSchedule[id] = &dockerStatsSchedule{
					hasSample: true, nextSample: now.Add(time.Hour),
					lastStats: protocol.DockerContainerStats{ID: id},
				}
			}
			collector.lastStatsPublish = now.Add(time.Hour)
			collector.updateRunningContainerIDs(running)
			collector.lastRunningSetHash = collector.runningContainerSnapshot().hash
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				collector.collectAndSendStats(context.Background())
			}
		})
	}
}
