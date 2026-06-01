package remoteaccess

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/labtether/protocol"
)

func TestCollectDesktopDiagnosticBasicFields(t *testing.T) {
	diag := CollectDesktopDiagnostic(nil, nil)
	if envDisplay := os.Getenv("DISPLAY"); diag.EnvDisplay != envDisplay {
		t.Errorf("EnvDisplay=%q, want %q", diag.EnvDisplay, envDisplay)
	}
	if diag.ActiveVNCSessions != 0 {
		t.Errorf("ActiveVNCSessions=%d, want 0", diag.ActiveVNCSessions)
	}
	if diag.ActiveWebRTCSessions != 0 {
		t.Errorf("ActiveWebRTCSessions=%d, want 0", diag.ActiveWebRTCSessions)
	}
}

func TestCollectDesktopDiagnosticDetectsXterm(t *testing.T) {
	diag := CollectDesktopDiagnostic(nil, nil)
	_, xtermErr := exec.LookPath("xterm")
	wantXterm := xtermErr == nil
	if diag.XtermAvailable != wantXterm {
		t.Errorf("XtermAvailable=%v, want %v", diag.XtermAvailable, wantXterm)
	}
}

func TestHandleDesktopDiagnoseRejectsMalformedPayload(t *testing.T) {
	transport := newMockTransport()

	HandleDesktopDiagnose(transport, protocol.Message{
		Type: protocol.MsgDesktopDiagnose,
		Data: []byte(`{"request_id":`),
	}, nil, nil)

	select {
	case msg := <-transport.messages:
		t.Fatalf("unexpected response for malformed payload: %+v", msg)
	case <-time.After(100 * time.Millisecond):
	}
}
