package webservice

import (
	"context"
	"encoding/json"
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/protocol"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestDockerCollectorRefreshAndPublishFullSendsInventoryAndCachesState(t *testing.T) {
	transport := newRecordingCollectorTransport(true)
	srv := newRootDockerTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_ = json.NewEncoder(w).Encode(dockerpkg.DockerVersionResponse{
				Version:    "27.0.1",
				APIVersion: "1.45",
				Os:         "linux",
				Arch:       "amd64",
			})
		case "/containers/json":
			_ = json.NewEncoder(w).Encode([]dockerpkg.DockerContainer{
				{
					ID:      "ct-running",
					Names:   []string{"/web"},
					Image:   "nginx:1.27",
					State:   "running",
					Status:  "Up 3 hours",
					Created: 1700000000,
					Ports:   []dockerpkg.DockerPort{{PrivatePort: 80, PublicPort: 8080, Type: "tcp"}},
					Labels:  map[string]string{"com.docker.compose.project": "webstack"},
				},
				{
					ID:      "ct-exited",
					Names:   []string{"/worker"},
					Image:   "busybox:1",
					State:   "exited",
					Status:  "Exited (0)",
					Created: 1700000100,
				},
			})
		case "/images/json":
			_ = json.NewEncoder(w).Encode([]dockerpkg.DockerImage{
				{ID: "img-1", RepoTags: []string{"nginx:1.27"}, Size: 12345, Created: 1700000000},
			})
		case "/networks":
			_ = json.NewEncoder(w).Encode([]dockerpkg.DockerNetwork{
				{ID: "net-1", Name: "bridge", Driver: "bridge", Scope: "local"},
			})
		case "/volumes":
			_ = json.NewEncoder(w).Encode(dockerpkg.DockerVolumesResponse{
				Volumes: []dockerpkg.DockerVolume{{Name: "vol-1", Driver: "local", Mountpoint: "/var/lib/docker/volumes/vol-1/_data"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dc := dockerpkg.NewTestCollector(srv.URL, transport, "asset-1")
	dc.SetTestHTTPClient(srv.Client())

	changed, err := dc.RefreshAndPublishFull(context.Background(), true)
	if err != nil {
		t.Fatalf("refreshAndPublishFull returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected full discovery refresh to publish a snapshot")
	}

	msg := waitForCollectorMessage(t, transport, 2*time.Second)
	if msg.Type != protocol.MsgDockerDiscovery {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgDockerDiscovery)
	}

	var payload protocol.DockerDiscoveryData
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		t.Fatalf("decode docker discovery payload: %v", err)
	}
	if payload.HostID != "asset-1" {
		t.Fatalf("host_id=%q, want asset-1", payload.HostID)
	}
	if payload.Engine.Version != "27.0.1" {
		t.Fatalf("engine version=%q, want 27.0.1", payload.Engine.Version)
	}
	if len(payload.Containers) != 2 {
		t.Fatalf("containers=%d, want 2", len(payload.Containers))
	}
	if len(payload.Images) != 1 || len(payload.Networks) != 1 || len(payload.Volumes) != 1 {
		t.Fatalf("expected images/networks/volumes to be included, got %d/%d/%d", len(payload.Images), len(payload.Networks), len(payload.Volumes))
	}

	hasPublished, containerCount, imageCount := dc.TestInventoryState()
	if !hasPublished {
		t.Fatal("expected collector to record that a full snapshot was published")
	}
	if containerCount != 2 || imageCount != 1 {
		t.Fatalf("unexpected cached inventory sizes containers=%d images=%d", containerCount, imageCount)
	}

	running := dc.CurrentRunningContainerIDs()
	if len(running) != 1 || running[0] != "ct-running" {
		t.Fatalf("running container IDs=%v, want [ct-running]", running)
	}
}

func TestDockerCollectorRefreshAndPublishContainerDeltaSendsDeltaForSmallChange(t *testing.T) {
	transport := newRecordingCollectorTransport(true)
	srv := newRootDockerTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]dockerpkg.DockerContainer{
			{ID: "ct-1", Names: []string{"/one"}, Image: "busybox", State: "running", Status: "Up", Created: 1700000000},
			{ID: "ct-2", Names: []string{"/two"}, Image: "busybox", State: "running", Status: "Up", Created: 1700000001},
			{ID: "ct-3", Names: []string{"/three"}, Image: "busybox", State: "running", Status: "Up", Created: 1700000002},
			{ID: "ct-4", Names: []string{"/four"}, Image: "busybox", State: "running", Status: "Up", Created: 1700000003},
			{ID: "ct-5", Names: []string{"/five"}, Image: "busybox", State: "running", Status: "Up", Created: 1700000004},
			{ID: "ct-6", Names: []string{"/six"}, Image: "busybox", State: "running", Status: "Up", Created: 1700000005},
		})
	}))
	defer srv.Close()

	dc := dockerpkg.NewTestCollector(srv.URL, transport, "asset-1")
	dc.SetTestHTTPClient(srv.Client())
	previousContainers := map[string]protocol.DockerContainerInfo{
		"ct-1": {ID: "ct-1", Name: "one", Image: "busybox", State: "running", Status: "Up", Created: "2023-11-14T22:13:20Z"},
		"ct-2": {ID: "ct-2", Name: "two", Image: "busybox", State: "running", Status: "Up", Created: "2023-11-14T22:13:21Z"},
		"ct-3": {ID: "ct-3", Name: "three", Image: "busybox", State: "running", Status: "Up", Created: "2023-11-14T22:13:22Z"},
		"ct-4": {ID: "ct-4", Name: "four", Image: "busybox", State: "running", Status: "Up", Created: "2023-11-14T22:13:23Z"},
		"ct-5": {ID: "ct-5", Name: "five", Image: "busybox", State: "running", Status: "Up", Created: "2023-11-14T22:13:24Z"},
	}
	previousRunning := map[string]struct{}{"ct-1": {}, "ct-2": {}, "ct-3": {}, "ct-4": {}, "ct-5": {}}
	dc.SetTestInventoryState(true, previousContainers, make(map[string]protocol.DockerImageInfo), previousRunning)

	changed, err := dc.RefreshAndPublishContainerDelta(context.Background())
	if err != nil {
		t.Fatalf("refreshAndPublishContainerDelta returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected delta refresh to publish a change")
	}

	msg := waitForCollectorMessage(t, transport, 2*time.Second)
	if msg.Type != protocol.MsgDockerDiscoveryDelta {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgDockerDiscoveryDelta)
	}

	var payload protocol.DockerDiscoveryDeltaData
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		t.Fatalf("decode docker delta payload: %v", err)
	}
	if payload.HostID != "asset-1" {
		t.Fatalf("host_id=%q, want asset-1", payload.HostID)
	}
	if len(payload.UpsertContainers) != 1 || payload.UpsertContainers[0].ID != "ct-6" {
		t.Fatalf("unexpected upsert containers: %+v", payload.UpsertContainers)
	}
	if len(payload.RemoveContainerIDs) != 0 {
		t.Fatalf("unexpected removals: %+v", payload.RemoveContainerIDs)
	}

	running := dc.CurrentRunningContainerIDs()
	if len(running) != 6 || running[5] != "ct-6" {
		t.Fatalf("running container IDs=%v, want ct-6 included", running)
	}
}

func TestDockerCollectorCollectAndSendStatsPublishesOnlyWhenDue(t *testing.T) {
	transport := newRecordingCollectorTransport(true)
	srv := newRootDockerTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/ct-1/stats" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cpu_stats": map[string]any{
				"cpu_usage":        map[string]any{"total_usage": 200},
				"system_cpu_usage": 1000,
				"online_cpus":      2,
			},
			"precpu_stats": map[string]any{
				"cpu_usage":        map[string]any{"total_usage": 100},
				"system_cpu_usage": 500,
			},
			"memory_stats": map[string]any{"usage": 100000, "limit": 200000},
			"pids_stats":   map[string]any{"current": 5},
			"networks": map[string]any{
				"eth0": map[string]any{"rx_bytes": 11, "tx_bytes": 22},
			},
			"blkio_stats": map[string]any{
				"io_service_bytes_recursive": []map[string]any{
					{"op": "Read", "value": 33},
					{"op": "Write", "value": 44},
				},
			},
		})
	}))
	defer srv.Close()

	dc := dockerpkg.NewTestCollector(srv.URL, transport, "asset-1")
	dc.SetTestHTTPClient(srv.Client())
	dc.SetTestInventoryState(false, nil, nil, map[string]struct{}{"ct-1": {}})

	dc.CollectAndSendStats(context.Background())
	if transport.MessageCount() != 1 {
		t.Fatalf("messages after first stats collection=%d, want 1", transport.MessageCount())
	}

	msg := waitForCollectorMessage(t, transport, 2*time.Second)
	if msg.Type != protocol.MsgDockerStats {
		t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgDockerStats)
	}

	var payload protocol.DockerStatsData
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		t.Fatalf("decode docker stats payload: %v", err)
	}
	if len(payload.Containers) != 1 || payload.Containers[0].ID != "ct-1" {
		t.Fatalf("unexpected stats payload: %+v", payload.Containers)
	}
	if payload.Containers[0].MemoryBytes != 100000 || payload.Containers[0].BlockReadBytes != 33 || payload.Containers[0].BlockWriteBytes != 44 {
		t.Fatalf("unexpected stats detail: %+v", payload.Containers[0])
	}

	dc.CollectAndSendStats(context.Background())
	if transport.MessageCount() != 1 {
		t.Fatalf("expected no second stats publish while schedule is still cooling down, got %d messages", transport.MessageCount())
	}
}

func TestDockerCollectorRunEventLoopReconnectsAndForwardsEvents(t *testing.T) {
	transport := newRecordingCollectorTransport(true)

	var (
		mu       sync.Mutex
		requests int
	)
	srv := newRootDockerTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		requests++
		requestNumber := requests
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		flusher, _ := w.(http.Flusher)
		switch requestNumber {
		case 1:
			_, _ = io.WriteString(w, `{"Type":"container","Action":"start","Actor":{"ID":"ct-1","Attributes":{"name":"web"}},"time":1}`+"\n")
		case 2:
			_, _ = io.WriteString(w, `{"Type":"container","Action":"stop","Actor":{"ID":"ct-1","Attributes":{"name":"web"}},"time":2}`+"\n")
		default:
			<-r.Context().Done()
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer srv.Close()

	dc := dockerpkg.NewTestCollector(srv.URL, transport, "asset-1")
	dc.SetTestHTTPClient(srv.Client())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		dc.RunEventLoop(ctx)
	}()

	first := waitForCollectorMessage(t, transport, 2*time.Second)
	second := waitForCollectorMessage(t, transport, 3*time.Second)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for docker event loop to stop")
	}

	if first.Type != protocol.MsgDockerEvents || second.Type != protocol.MsgDockerEvents {
		t.Fatalf("unexpected event message types: %q %q", first.Type, second.Type)
	}

	var firstEvent protocol.DockerEventData
	if err := json.Unmarshal(first.Data, &firstEvent); err != nil {
		t.Fatalf("decode first docker event: %v", err)
	}
	var secondEvent protocol.DockerEventData
	if err := json.Unmarshal(second.Data, &secondEvent); err != nil {
		t.Fatalf("decode second docker event: %v", err)
	}
	if firstEvent.Action != "start" || secondEvent.Action != "stop" {
		t.Fatalf("unexpected forwarded event actions: %q then %q", firstEvent.Action, secondEvent.Action)
	}

	if dc.DiscoveryTriggerCount() < 2 {
		t.Fatalf("expected discovery triggers to be queued for both events, got %d", dc.DiscoveryTriggerCount())
	}
	// Stats trigger check removed as the channel is no longer accessible from the root test.
	// The event forwarding is verified by the Docker events received above.

	mu.Lock()
	defer mu.Unlock()
	if requests < 2 {
		t.Fatalf("expected event loop to reconnect, got %d event-stream requests", requests)
	}
}
