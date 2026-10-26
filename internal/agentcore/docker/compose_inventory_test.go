package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestDockerComposeDiscoverySelection(t *testing.T) {
	selected := composeTestSelection(t)
	rows := composeRows(selected)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"Version":"fixture"}`))
		case "/containers/json":
			_ = json.NewEncoder(w).Encode(rows)
		case "/images/json", "/networks":
			_, _ = w.Write([]byte(`[]`))
		case "/volumes":
			_, _ = w.Write([]byte(`{"Volumes":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("LABTETHER_ALLOW_INSECURE_TRANSPORT", "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	sender := newRecordingCollectorTransport(true)
	dc := NewDockerCollector(srv.URL, sender, "host", time.Minute)
	publish := func(full bool) protocol.Message {
		t.Helper()
		var sent bool
		var err error
		if full {
			sent, err = dc.refreshAndPublishFull(context.Background(), true)
		} else {
			sent, err = dc.refreshAndPublishContainerDelta(context.Background())
		}
		if err != nil || !sent {
			t.Fatalf("discovery sent%v err%v", sent, err)
		}
		return waitForCollectorMessage(t, sender, time.Second)
	}
	message := publish(true)
	var full protocol.DockerDiscoveryData
	if json.Unmarshal(message.Data, &full) != nil || full.ComposeActionVersion != 2 || full.ComposeEndpointID != dc.composeEndpointID() || len(full.ComposeStacks) != 1 {
		t.Fatalf("missing full contract %s", message.Data)
	}
	stack := full.ComposeStacks[0]
	if stack.SelectionError != "" || stack.ConfigDir != selected.Dir || !reflect.DeepEqual(stack.ConfigFiles, selected.Files) || len(stack.Containers) != 2 {
		t.Fatalf("lost stopped-container selection: %+v", stack)
	}
	// A cloned published slice must not alias the stored inventory selection.
	copied := cloneComposeStacks(dc.inventory.ComposeStacks)
	copied[0].ConfigFiles[0] = "changed"
	if dc.inventory.ComposeStacks[0].ConfigFiles[0] != selected.Files[0] {
		t.Fatal("files alias inventory")
	}
	for i := range rows {
		rows[i].Labels[composeFilesLabel] = selected.Files[1] + "," + selected.Files[0]
	}
	message = publish(false)
	var delta protocol.DockerDiscoveryDeltaData
	if message.Type != protocol.MsgDockerDiscoveryDelta { // Existing fallback chooses full for high churn.
		if message.Type != protocol.MsgDockerDiscovery || json.Unmarshal(message.Data, &full) != nil {
			t.Fatal(message.Type)
		}
		if full.ComposeActionVersion != 2 || full.ComposeEndpointID != dc.composeEndpointID() || full.ComposeStacks[0].ConfigFiles[0] != selected.Files[1] {
			t.Fatal("full fallback lost files")
		}
	} else {
		if json.Unmarshal(message.Data, &delta) != nil || delta.ComposeActionVersion != 2 || delta.ComposeEndpointID != dc.composeEndpointID() || !delta.ReplaceComposeStacks || delta.ComposeStacks[0].ConfigFiles[0] != selected.Files[1] {
			t.Fatalf("delta lost ordered files: %s", message.Data)
		}
	}
	// Add unaffected containers so changing one state uses the actual delta path.
	for i := 0; i < 10; i++ {
		rows = append(rows, DockerContainer{ID: strings.Repeat("x", i+1), Names: []string{"/standalone"}, State: "running"})
	}
	publish(true)
	rows[0].State = "exited"
	message = publish(false)
	if message.Type != protocol.MsgDockerDiscoveryDelta || json.Unmarshal(message.Data, &delta) != nil || delta.ComposeActionVersion != 2 || delta.ComposeEndpointID != dc.composeEndpointID() {
		t.Fatalf("missing delta capability: %s", message.Data)
	}
	rows[1].Labels[composeFilesLabel] = selected.Files[0]
	message = publish(true)
	_ = json.Unmarshal(message.Data, &full)
	if full.ComposeStacks[0].SelectionError != "conflicting_labels" {
		t.Fatal("stopped conflict hidden")
	}
	rows = composeRows(selected)
	delete(rows[0].Labels, composeFilesLabel)
	message = publish(true)
	_ = json.Unmarshal(message.Data, &full)
	if full.ComposeStacks[0].SelectionError == "" {
		t.Fatal("missing labels certified")
	}
	rows = composeRows(selected)
	for len(rows) <= maxContainersPerHost {
		rows = append(rows, DockerContainer{ID: strings.Repeat("z", len(rows)), Names: []string{"/other"}})
	}
	message = publish(true)
	_ = json.Unmarshal(message.Data, &full)
	if full.ComposeStacks[0].SelectionError != "incomplete_inventory" {
		t.Fatal("truncated inventory certified selection")
	}
}
