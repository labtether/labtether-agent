package agentcore

import (
	"encoding/json"
	"errors"
	"github.com/labtether/labtether-agent/internal/agentcore/backends"
	"github.com/labtether/labtether-agent/internal/agentcore/packagepolicy"
	"github.com/labtether/protocol"
	"reflect"
	"strings"
	"testing"
)

func TestPackageManagerHandlePackageListAndAction(t *testing.T) {
	t.Run("list success and error", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		successBackend := &stubPackageBackend{
			listPackages: []protocol.PackageInfo{{Name: "jq", Version: "1.7", Status: "installed"}},
		}
		manager := &backends.PackageManager{Backend: successBackend}
		manager.HandlePackageList(transport, protocol.Message{
			Type: protocol.MsgPackageList,
			Data: mustMarshalDesktopRuntime(t, protocol.PackageListData{RequestID: "req-package-list"}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.Type != protocol.MsgPackageListed {
			t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgPackageListed)
		}
		var listed protocol.PackageListedData
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode package listed payload: %v", err)
		}
		if listed.RequestID != "req-package-list" || len(listed.Packages) != 1 || listed.Packages[0].Name != "jq" {
			t.Fatalf("unexpected package list %+v", listed)
		}

		errorBackend := &stubPackageBackend{listErr: errors.New("rpm failed")}
		manager = &backends.PackageManager{Backend: errorBackend}
		manager.HandlePackageList(transport, protocol.Message{
			Type: protocol.MsgPackageList,
			Data: mustMarshalDesktopRuntime(t, protocol.PackageListData{RequestID: "req-package-error"}),
		})

		msg = readDesktopRuntimeMessage(t, messages)
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode package listed payload: %v", err)
		}
		if listed.Error != "rpm failed" {
			t.Fatalf("error=%q, want rpm failed", listed.Error)
		}
	})

	t.Run("upgradable inventory echoes discriminator and versions", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		backend := &stubPackageBackend{upgradablePackages: []backends.UpgradablePackageInfo{{
			Name:             "curl",
			Version:          "8.5.0",
			AvailableVersion: "8.6.0",
		}}}
		manager := &backends.PackageManager{Backend: backend}
		manager.HandlePackageList(transport, protocol.Message{
			Type: protocol.MsgPackageList,
			ID:   "req-package-upgradable",
			Data: mustMarshalDesktopRuntime(t, map[string]any{
				"request_id": "req-package-upgradable",
				"inventory":  "upgradable",
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		var listed struct {
			RequestID string `json:"request_id"`
			Inventory string `json:"inventory"`
			Packages  []struct {
				Name             string `json:"name"`
				Version          string `json:"version"`
				AvailableVersion string `json:"available_version"`
				Status           string `json:"status"`
			} `json:"packages"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(msg.Data, &listed); err != nil {
			t.Fatalf("decode upgradable package list: %v", err)
		}
		if listed.RequestID != "req-package-upgradable" || listed.Inventory != "upgradable" || listed.Error != "" || len(listed.Packages) != 1 {
			t.Fatalf("unexpected response %+v", listed)
		}
		pkg := listed.Packages[0]
		if pkg.Name != "curl" || pkg.Version != "8.5.0" || pkg.AvailableVersion != "8.6.0" || pkg.Status != "upgradable" {
			t.Fatalf("unexpected upgradable package %+v", pkg)
		}
	})

	t.Run("malformed and unknown inventories return correlated errors", func(t *testing.T) {
		for _, test := range []struct {
			name string
			data json.RawMessage
		}{
			{name: "malformed", data: json.RawMessage(`{"request_id":`)},
			{name: "unknown inventory", data: mustMarshalDesktopRuntime(t, map[string]any{"request_id": "req-package-bad", "inventory": "updates"})},
		} {
			t.Run(test.name, func(t *testing.T) {
				transport, messages, cleanup := newDesktopRuntimeTransport(t)
				defer cleanup()
				manager := &backends.PackageManager{Backend: &stubPackageBackend{}}
				manager.HandlePackageList(transport, protocol.Message{
					Type: protocol.MsgPackageList,
					ID:   "req-package-bad",
					Data: test.data,
				})

				msg := readDesktopRuntimeMessage(t, messages)
				var listed struct {
					RequestID string `json:"request_id"`
					Error     string `json:"error"`
				}
				if err := json.Unmarshal(msg.Data, &listed); err != nil {
					t.Fatalf("decode package error: %v", err)
				}
				if listed.RequestID != "req-package-bad" || listed.Error == "" {
					t.Fatalf("uncorrelated or empty error response: %+v", listed)
				}
			})
		}
	})

	t.Run("inventory envelope and payload ids must match", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()
		backend := &stubPackageBackend{}
		manager := &backends.PackageManager{Backend: backend}
		manager.HandlePackageList(transport, protocol.Message{
			Type: protocol.MsgPackageList,
			ID:   "req-package-envelope",
			Data: mustMarshalDesktopRuntime(t, map[string]any{
				"request_id": "req-package-payload",
				"inventory":  "upgradable",
			}),
		})
		msg := readDesktopRuntimeMessage(t, messages)
		var response struct {
			RequestID string `json:"request_id"`
			Error     string `json:"error"`
		}
		if err := json.Unmarshal(msg.Data, &response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if response.RequestID != "req-package-envelope" || !strings.Contains(response.Error, "mismatch") {
			t.Fatalf("unexpected mismatch response %+v", response)
		}
		if backend.upgradableCalls != 0 {
			t.Fatal("mismatched inventory request reached backend")
		}
	})

	t.Run("action normalizes packages and reports result", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		backend := &stubPackageBackend{
			actionResult: backends.PackageActionResult{
				Output:         "installed",
				RebootRequired: true,
			},
		}
		manager := &backends.PackageManager{Backend: backend}
		manager.HandlePackageAction(transport, protocol.Message{
			Type: protocol.MsgPackageAction,
			Data: mustMarshalDesktopRuntime(t, protocol.PackageActionData{
				RequestID: "req-package-action",
				Action:    "install",
				Packages:  []string{" jq ", "jq", "curl"},
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		if msg.Type != protocol.MsgPackageResult {
			t.Fatalf("message type=%q, want %q", msg.Type, protocol.MsgPackageResult)
		}
		var result protocol.PackageResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode package result payload: %v", err)
		}
		if !result.OK || result.Output != "installed" || !result.RebootRequired {
			t.Fatalf("unexpected package result %+v", result)
		}
		if got, want := backend.actionCalls, []stubBackendsPackageActionCall{{
			action:   "install",
			packages: []string{"jq", "curl"},
		}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("backend calls=%#v, want %#v", got, want)
		}
	})

	t.Run("unsafe package tokens never reach the backend", func(t *testing.T) {
		tests := []struct {
			name     string
			packages []string
		}{
			{name: "apt option and hook payload", packages: []string{"curl", "-o", "APT::Update::Pre-Invoke::=/bin/sh"}},
			{name: "pacman option", packages: []string{"--config", "tmp/evil"}},
			{name: "brew option", packages: []string{"--formula", "curl"}},
			{name: "windows option", packages: []string{"--source", "evil"}},
			{name: "control character", packages: []string{"curl\n--help"}},
			{name: "empty entry", packages: []string{"curl", ""}},
		}
		excessive := make([]string, packagepolicy.MaxPackageCount+1)
		for index := range excessive {
			excessive[index] = "curl"
		}
		tests = append(tests, struct {
			name     string
			packages []string
		}{name: "excessive package count", packages: excessive})

		for _, test := range tests {
			test := test
			t.Run(test.name, func(t *testing.T) {
				transport, messages, cleanup := newDesktopRuntimeTransport(t)
				defer cleanup()

				backend := &stubPackageBackend{}
				manager := &backends.PackageManager{Backend: backend}
				manager.HandlePackageAction(transport, protocol.Message{
					Type: protocol.MsgPackageAction,
					Data: mustMarshalDesktopRuntime(t, protocol.PackageActionData{
						RequestID: "req-package-unsafe",
						Action:    "install",
						Packages:  test.packages,
					}),
				})

				msg := readDesktopRuntimeMessage(t, messages)
				var result protocol.PackageResultData
				if err := json.Unmarshal(msg.Data, &result); err != nil {
					t.Fatalf("decode package result payload: %v", err)
				}
				if result.OK || result.Error == "" {
					t.Fatalf("unsafe package result = %+v", result)
				}
				if len(backend.actionCalls) != 0 {
					t.Fatalf("unsafe packages reached backend: %#v", backend.actionCalls)
				}
			})
		}
	})

	t.Run("invalid action", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		backend := &stubPackageBackend{}
		manager := &backends.PackageManager{Backend: backend}
		manager.HandlePackageAction(transport, protocol.Message{
			Type: protocol.MsgPackageAction,
			Data: mustMarshalDesktopRuntime(t, protocol.PackageActionData{
				RequestID: "req-package-invalid",
				Action:    "repair",
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		var result protocol.PackageResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode package result payload: %v", err)
		}
		if result.Error != "invalid package action" {
			t.Fatalf("error=%q, want invalid package action", result.Error)
		}
		if len(backend.actionCalls) != 0 {
			t.Fatalf("expected no backend calls, got %#v", backend.actionCalls)
		}
	})

	t.Run("update action alias normalizes to canonical upgrade", func(t *testing.T) {
		transport, messages, cleanup := newDesktopRuntimeTransport(t)
		defer cleanup()

		backend := &stubPackageBackend{}
		manager := &backends.PackageManager{Backend: backend}
		manager.HandlePackageAction(transport, protocol.Message{
			Type: protocol.MsgPackageAction,
			Data: mustMarshalDesktopRuntime(t, protocol.PackageActionData{
				RequestID: "req-package-update-alias",
				Action:    "update",
				Packages:  []string{"curl"},
			}),
		})

		msg := readDesktopRuntimeMessage(t, messages)
		var result protocol.PackageResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode package result: %v", err)
		}
		if !result.OK {
			t.Fatalf("alias result = %+v", result)
		}
		if got, want := backend.actionCalls, []stubBackendsPackageActionCall{{action: "upgrade", packages: []string{"curl"}}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("backend calls = %#v, want %#v", got, want)
		}
	})

	t.Run("malformed and mismatched package actions return correlated errors", func(t *testing.T) {
		for _, test := range []struct {
			name string
			data json.RawMessage
		}{
			{name: "malformed", data: json.RawMessage(`{"request_id":`)},
			{name: "mismatched", data: mustMarshalDesktopRuntime(t, protocol.PackageActionData{RequestID: "payload-id", Action: "upgrade", Packages: []string{"curl"}})},
		} {
			t.Run(test.name, func(t *testing.T) {
				transport, messages, cleanup := newDesktopRuntimeTransport(t)
				defer cleanup()
				backend := &stubPackageBackend{}
				manager := &backends.PackageManager{Backend: backend}
				manager.HandlePackageAction(transport, protocol.Message{Type: protocol.MsgPackageAction, ID: "envelope-id", Data: test.data})
				msg := readDesktopRuntimeMessage(t, messages)
				var result protocol.PackageResultData
				if err := json.Unmarshal(msg.Data, &result); err != nil {
					t.Fatalf("decode result: %v", err)
				}
				if result.RequestID != "envelope-id" || result.OK || result.Error == "" {
					t.Fatalf("unexpected correlated error %+v", result)
				}
				if len(backend.actionCalls) != 0 {
					t.Fatalf("invalid request reached backend: %#v", backend.actionCalls)
				}
			})
		}
	})
}
