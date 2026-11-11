package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

// After `down` (from LabTether or on the host) Docker has no container left
// for a Compose project, so the agent stopped reporting it and the Hub could
// not bring it up again. The agent now remembers the project in its state
// folder, reports it stopped while its compose files exist, and lets `up` use
// the remembered selection, also after an agent restart.
func TestComposeProjectStaysListedAndCanComeUpAfterDown(t *testing.T) {
	t.Setenv("LABTETHER_ALLOW_INSECURE_TRANSPORT", "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	selected := composeTestSelection(t)
	var up atomic.Bool
	up.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if up.Load() {
			_ = json.NewEncoder(w).Encode(composeRows(selected))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	stateDir := t.TempDir()
	newCollector := func() *DockerCollector {
		dc := NewDockerCollector(srv.URL, nil, "host", time.Minute)
		dc.SetComposeStateDir(stateDir)
		return dc
	}

	dc := newCollector()
	if stacks := dc.composeStacks(composeRows(selected), false); len(stacks) != 1 || stacks[0].Status != "running(1)" {
		t.Fatalf("running project: %+v", stacks)
	}
	up.Store(false) // docker compose down
	stopped := func(stacks []protocol.DockerComposeStack) bool {
		return len(stacks) == 1 && stacks[0].Name == selected.Name && stacks[0].Status == "stopped" &&
			len(stacks[0].Containers) == 0 && stacks[0].ConfigDir == selected.Dir && reflect.DeepEqual(stacks[0].ConfigFiles, selected.Files)
	}
	if stacks := dc.composeStacks(nil, false); !stopped(stacks) {
		t.Fatalf("after down the project must stay listed as stopped: %+v", stacks)
	}
	if stacks := dc.composeStacks(nil, true); len(stacks) != 0 {
		t.Fatalf("an incomplete inventory must not mark projects down: %+v", stacks)
	}

	restarted := newCollector()
	if stacks := restarted.composeStacks(nil, false); !stopped(stacks) {
		t.Fatalf("the memory must survive an agent restart: %+v", stacks)
	}
	req := protocol.DockerComposeActionData{StackName: selected.Name, ConfigDir: selected.Dir, ConfigFiles: selected.Files, Action: "up"}
	got, err := restarted.resolveComposeSelection(context.Background(), req, true)
	if err != nil || !selectionsEqual(got, selected) {
		t.Fatalf("up after down: selection=%+v err=%v", got, err)
	}
	req.Action = "restart"
	if _, err := restarted.resolveComposeSelection(context.Background(), req, true); err == nil {
		t.Fatal("restart needs containers; only up and pull may use the remembered selection")
	}
	if info, err := os.Stat(filepath.Join(stateDir, composeMemoryFileName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("memory file in the state folder, mode 0600: %v %v", info, err)
	}

	for _, file := range selected.Files {
		_ = os.Remove(file)
	}
	if stacks := restarted.composeStacks(nil, false); len(stacks) != 0 {
		t.Fatalf("a project whose compose files are gone is forgotten: %+v", stacks)
	}
	if _, ok := newCollector().composeMemory.lookup(selected.Name); ok {
		t.Fatal("the forgotten project must be gone from the saved memory too")
	}
}
