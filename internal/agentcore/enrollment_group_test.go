package agentcore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrollmentGroupPlacementSurvivesRestart(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")

	for _, test := range []struct {
		name           string
		responseGroup  *string
		wantEnrollment string
		wantRestart    string
	}{
		{name: "hub assigned group", responseGroup: groupPointer("hub-group"), wantEnrollment: "hub-group", wantRestart: "hub-group"},
		{name: "hub left asset unplaced", responseGroup: groupPointer(""), wantEnrollment: "", wantRestart: ""},
		{name: "older hub omitted group", responseGroup: nil, wantEnrollment: "requested-group", wantRestart: "restart-group"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request enrollRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode enrollment request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if request.GroupID != "requested-group" {
					t.Errorf("requested group=%q", request.GroupID)
				}
				response := map[string]any{
					"agent_token": "issued-token",
					"asset_id":    "group-agent",
					"hub_ws_url":  "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/agent",
					"hub_api_url": server.URL,
				}
				if test.responseGroup != nil {
					response["group_id"] = *test.responseGroup
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			tokenFile := filepath.Join(t.TempDir(), "agent-token")
			cfg := &RuntimeConfig{
				AssetID:         "group-agent",
				GroupID:         "requested-group",
				APIBaseURL:      server.URL,
				EnrollmentToken: "enrollment-token",
				TokenFilePath:   tokenFile,
			}
			if err := ResolveToken(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GroupID != test.wantEnrollment {
				t.Fatalf("enrolled group=%q, want %q", cfg.GroupID, test.wantEnrollment)
			}

			restarted := &RuntimeConfig{AssetID: "group-agent", GroupID: "restart-group", TokenFilePath: tokenFile}
			if err := ResolveToken(context.Background(), restarted); err != nil {
				t.Fatal(err)
			}
			if restarted.GroupID != test.wantRestart {
				t.Fatalf("restarted group=%q, want %q", restarted.GroupID, test.wantRestart)
			}
		})
	}
}

func groupPointer(value string) *string { return &value }
