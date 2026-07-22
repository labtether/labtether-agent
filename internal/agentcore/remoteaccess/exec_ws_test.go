package remoteaccess

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestTokenAllowsAnyCapability(t *testing.T) {
	token := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"capabilities":["agent.command.execute","agent.update.apply"]}`)) + ".sig"

	checked, allowed := TokenAllowsAnyCapability(token, "agent.command.execute")
	if !checked {
		t.Fatalf("expected capabilities to be parsed from token")
	}
	if !allowed {
		t.Fatalf("expected token capability check to allow command execution")
	}
	checked, allowed = TokenAllowsAnyCapability(token, "missing.capability")
	if !checked {
		t.Fatalf("expected capabilities to be parsed from token")
	}
	if allowed {
		t.Fatalf("expected missing capability to be denied")
	}
}

func TestTokenAllowsAnyCapabilityUnknownTokenFormat(t *testing.T) {
	checked, allowed := TokenAllowsAnyCapability("opaque-token", "agent.command.execute")
	if checked {
		t.Fatalf("expected opaque token to skip capability claim enforcement")
	}
	if !allowed {
		t.Fatalf("expected opaque token to be treated as legacy-allowed")
	}
}

func TestValidateUpdatePackages(t *testing.T) {
	if err := ValidateUpdatePackages([]string{"curl", "openssl-dev", "@scope/package@1.2.3", "libssl3:amd64=2:3.0.2-1~deb12u1"}); err != nil {
		t.Fatalf("expected valid package names, got %v", err)
	}
	if err := ValidateUpdatePackages([]string{"bad;rm -rf /"}); err == nil {
		t.Fatalf("expected invalid package name to be rejected")
	}
	if err := ValidateUpdatePackages([]string{"-o", "APT::Update::Pre-Invoke::=/bin/sh"}); err == nil {
		t.Fatalf("expected option-shaped package name to be rejected")
	}
}

func TestHandleUpdateRequestRejectsUnsupportedMode(t *testing.T) {
	transport := newMockTransport()
	data, err := json.Marshal(protocol.UpdateRequestData{
		JobID: "unsupported-update-mode",
		Mode:  "docker_images",
	})
	if err != nil {
		t.Fatalf("marshal update request: %v", err)
	}

	HandleUpdateRequest(transport, protocol.Message{Type: protocol.MsgUpdateRequest, Data: data}, ExecConfig{APIToken: "opaque-token"})

	select {
	case msg := <-transport.messages:
		if msg.Type != protocol.MsgUpdateResult {
			t.Fatalf("message type = %q, want %q", msg.Type, protocol.MsgUpdateResult)
		}
		var result protocol.UpdateResultData
		if err := json.Unmarshal(msg.Data, &result); err != nil {
			t.Fatalf("decode update result: %v", err)
		}
		if result.Status != "failed" {
			t.Fatalf("status = %q, want failed", result.Status)
		}
		if result.Error != `unsupported update mode "docker_images"` {
			t.Fatalf("error = %q", result.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rejected update result")
	}
}

func TestRemoteCommandTimeoutFromSecondsBoundsBeforeDurationConversion(t *testing.T) {
	if got := remoteCommandTimeoutFromSeconds(0); got != DefaultCommandTimeout {
		t.Fatalf("remoteCommandTimeoutFromSeconds(0) = %s, want %s", got, DefaultCommandTimeout)
	}
	if got := remoteCommandTimeoutFromSeconds(2); got != 2*time.Second {
		t.Fatalf("remoteCommandTimeoutFromSeconds(2) = %s, want 2s", got)
	}
	if got := remoteCommandTimeoutFromSeconds(math.MaxInt); got != MaxRemoteCommandTimeout {
		t.Fatalf("remoteCommandTimeoutFromSeconds(MaxInt) = %s, want %s", got, MaxRemoteCommandTimeout)
	}
}
