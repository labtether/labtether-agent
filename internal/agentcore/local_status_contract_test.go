package agentcore

// The macOS and Windows apps decode GET /agent/status from this agent. The
// shared contract for that body lives in github.com/labtether/protocol
// localagent: a JSON Schema, closed code sets and one fixture per agent state.
// This test drives the real handler into each state and checks the body
// against the contract and the fixture of the same name. It fails when a
// field is added, renamed or retyped, or when a new last_error code appears,
// before both apps break on it.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labtether/labtether-agent/internal/agentidentity"
	"github.com/labtether/protocol"
	"github.com/labtether/protocol/localagent"
)

var (
	contractStartedAt      = time.Date(2026, 11, 14, 7, 26, 34, 418236512, time.UTC)
	contractCollectedAt    = time.Date(2026, 11, 14, 9, 41, 2, 907113845, time.UTC)
	contractDisconnectedAt = time.Date(2026, 11, 14, 9, 38, 51, 260417093, time.UTC)
)

type contractScenario struct {
	name  string
	serve func(t *testing.T) []byte
}

func TestLocalStatusMatchesContract(t *testing.T) {
	t.Parallel()
	names, err := localagent.StatusFixtureNames()
	if err != nil {
		t.Fatal(err)
	}
	var served []string
	for _, sc := range contractScenarios() {
		served = append(served, sc.name)
		t.Run(sc.name, func(t *testing.T) {
			want, err := localagent.StatusFixture(sc.name)
			if err != nil {
				t.Fatalf("no contract fixture for this state: %v", err)
			}
			body := sc.serve(t)
			if err := localagent.ValidateStatus(body); err != nil {
				t.Errorf("/agent/status breaks the local agent contract:\n%v\nbody: %s", err, body)
			}
			if err := localagent.CompareStatusShape(body, want); err != nil {
				t.Errorf("/agent/status and fixture %s differ in fields or types:\n%v\nbody: %s", sc.name, err, body)
			}
		})
	}
	for _, name := range names {
		if !slices.Contains(served, name) {
			t.Errorf("contract fixture %s has no agent state in this test", name)
		}
	}
}

func contractSample() TelemetrySample {
	return TelemetrySample{
		CPUPercent: 12.5, MemoryPercent: 41.8, DiskPercent: 63.2,
		NetRXBytes: 48213377024, NetTXBytes: 9132854272,
		NetRXBytesPerSec: 18432.5, NetTXBytesPerSec: 6120.25,
		CollectedAt: contractCollectedAt,
	}
}

func contractRuntime(sample TelemetrySample, withIdentity bool) *Runtime {
	cfg := RuntimeConfig{
		Name: "labtether-agent", Port: "8091", AssetID: "nas01", Version: "v2.0.1",
		CollectInterval: 10 * time.Second, HeartbeatInterval: 30 * time.Second,
	}
	if withIdentity {
		cfg.GroupID = "grp-servers"
	}
	rt := NewRuntime(cfg, stubProvider{sample: sample}, noopHeartbeatPublisher{})
	rt.startedAt = contractStartedAt
	rt.collectOnce(contractCollectedAt)
	if withIdentity {
		// A fixed, public test seed: only the fingerprint reaches the body.
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = 7
		}
		public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		rt.deviceIdentity = &deviceIdentity{
			KeyAlgorithm: agentidentity.KeyAlgorithmEd25519,
			Fingerprint:  agentidentity.FingerprintFromPublicKey(public),
		}
		rt.localBindAddress = "127.0.0.1"
		rt.localAuthEnabled = true
	}
	return rt
}

func contractTransport() *wsTransport {
	tr := newWSTransport("wss://hub.example.com/ws/agent", "", "nas01", "linux", "v2.0.1", nil, "", nil)
	tr.now = func() time.Time { return contractDisconnectedAt }
	tr.jitter = func(time.Duration) time.Duration { return 0 }
	return tr
}

// contractSetSocket sets the socket fields under the transport lock, as the
// other status tests do; there is no setter without a real socket.
func contractSetSocket(tr *wsTransport, open, pending bool) {
	tr.mu.Lock()
	tr.connected = open
	tr.pendingEnrollment = pending
	tr.mu.Unlock()
}

func contractServe(t *testing.T, rt *Runtime) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	rt.statusHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agent/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/agent/status returned %d", rec.Code)
	}
	return rec.Body.Bytes()
}

// contractFailedConnect runs the real reconnect loop against one failing
// dial and returns the body served while the loop waits to retry.
func contractFailedConnect(t *testing.T, resp *http.Response, dialErr error) []byte {
	t.Helper()
	rt := contractRuntime(contractSample(), true)
	tr := contractTransport()
	rt.transport = tr
	waiting := make(chan struct{}, 1)
	tr.timeAfter = func(time.Duration) <-chan time.Time {
		select {
		case waiting <- struct{}{}:
		default:
		}
		return make(chan time.Time)
	}
	tr.connectWithResponseFn = func(context.Context) (*http.Response, error) { return resp, dialErr }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.reconnectLoop(ctx, nil); close(done) }()
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("reconnect loop did not reach its retry wait")
	}
	body := contractServe(t, rt)
	cancel()
	<-done
	return body
}

// withContractTransport serves a runtime whose transport was put into a
// state by setup.
func withContractTransport(setup func(tr *wsTransport)) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		rt := contractRuntime(contractSample(), true)
		tr := contractTransport()
		rt.transport = tr
		setup(tr)
		return contractServe(t, rt)
	}
}

// contractScenarios returns one scenario per contract fixture.
func contractScenarios() []contractScenario {
	return []contractScenario{
		{"connected", withContractTransport(func(tr *wsTransport) { contractSetSocket(tr, true, false) })},
		{"connecting-transient-host-unreachable", func(t *testing.T) []byte {
			dialErr := &net.OpError{Op: "dial", Net: "tcp",
				Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8443},
				Err:  os.NewSyscallError("connect", syscall.EHOSTUNREACH)}
			return contractFailedConnect(t, nil, dialErr)
		}},
		{"enrollment-pending", withContractTransport(func(tr *wsTransport) { contractSetSocket(tr, true, true) })},
		{"auth-failed-token-rejected", func(t *testing.T) []byte {
			return contractFailedConnect(t, &http.Response{StatusCode: http.StatusUnauthorized}, websocket.ErrBadHandshake)
		}},
		{"auth-failed-enrollment-token-rejected", withContractTransport(func(tr *wsTransport) {
			// The same steps as run.go after resolveTokenWithIdentity fails.
			err := newEnrollmentRefusal(http.StatusUnauthorized, strings.NewReader(
				`{"error":"This enrollment token expired. Make a new one in Devices, Add device."}`))
			credentialError := ""
			if isEnrollmentCredentialRejected(err) {
				credentialError = enrollmentTokenRejected
			}
			tr.setCredentialPersistenceError("")
			tr.setCredentialError(credentialError)
			tr.setEnrollmentRefusal(enrollmentRefusalMessage(err))
			contractSetSocket(tr, true, true)
		})},
		{"connected-token-persistence-failed", withContractTransport(func(tr *wsTransport) {
			contractSetSocket(tr, true, false)
			tr.setCredentialPersistenceError(agentTokenPersistenceFailed)
		})},
		{"enrollment-refused-hub-words", withContractTransport(func(tr *wsTransport) {
			contractSetSocket(tr, true, true)
			data, _ := json.Marshal(protocol.EnrollmentRejectedData{Reason: "An admin rejected this device in LabTether."})
			handleEnrollmentRejected(tr, protocol.Message{Type: protocol.MsgEnrollmentRejected, Data: data})
			tr.markDisconnected() // the Hub closes the pending socket after a rejection
		})},
		{"disconnected-no-transport", func(t *testing.T) []byte {
			return contractServe(t, contractRuntime(contractSample(), true))
		}},
		{"alerts-with-temperature", func(t *testing.T) []byte {
			sample := contractSample()
			temp := 47.5
			sample.TempCelsius = &temp
			rt := contractRuntime(sample, true)
			tr := contractTransport()
			rt.transport = tr
			contractSetSocket(tr, true, false)
			for _, alert := range []protocol.AlertNotifyData{
				{ID: "alr-disk-nas01", Severity: "high", Title: "Disk usage above 90%", Summary: "/srv/media is 93% full", State: "firing", Timestamp: "2026-11-14T09:12:40Z"},
				{ID: "alr-cpu-nas01", Severity: "medium", Title: "CPU above 85% for 10 minutes", Summary: "CPU was 88% for 10 minutes", State: "resolved", Timestamp: "2026-11-14T08:55:03.512Z"},
			} {
				data, _ := json.Marshal(alert)
				handleAlertNotify(protocol.Message{Type: protocol.MsgAlertNotify, Data: data}, rt)
			}
			return contractServe(t, rt)
		}},
		{"minimal-optional-fields-absent", func(t *testing.T) []byte {
			// No group, device key, transport or local listener, and a zero
			// start time, which is how the Go type omits uptime.
			rt := contractRuntime(TelemetrySample{CollectedAt: contractCollectedAt}, false)
			rt.startedAt = time.Time{}
			return contractServe(t, rt)
		}},
	}
}
