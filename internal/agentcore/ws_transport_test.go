package agentcore

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyConnectError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		resp     *http.Response
		expected connectErrorKind
	}{
		{
			name:     "nil error returns none",
			err:      nil,
			resp:     nil,
			expected: errKindNone,
		},
		{
			name: "401 returns auth",
			err:  errors.New("websocket: bad handshake"),
			resp: &http.Response{
				StatusCode: http.StatusUnauthorized,
			},
			expected: errKindAuth,
		},
		{
			name: "403 returns auth",
			err:  errors.New("websocket: bad handshake"),
			resp: &http.Response{
				StatusCode: http.StatusForbidden,
			},
			expected: errKindAuth,
		},
		{
			name:     "connection refused returns transient",
			err:      errors.New("dial tcp 127.0.0.1:8080: connect: connection refused"),
			resp:     nil,
			expected: errKindTransient,
		},
		{
			name:     "DNS failure returns transient",
			err:      errors.New("dial tcp: lookup hub.example.com: no such host"),
			resp:     nil,
			expected: errKindTransient,
		},
		{
			name: "500 returns transient",
			err:  errors.New("websocket: bad handshake"),
			resp: &http.Response{
				StatusCode: http.StatusInternalServerError,
			},
			expected: errKindTransient,
		},
		{
			name:     "timeout returns transient",
			err:      errors.New("dial tcp 127.0.0.1:8080: i/o timeout"),
			resp:     nil,
			expected: errKindTransient,
		},
		{
			name:     "unknown error returns transient",
			err:      errors.New("something unexpected"),
			resp:     nil,
			expected: errKindTransient,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyConnectError(tc.err, tc.resp)
			if got != tc.expected {
				t.Errorf("classifyConnectError(%v, %v) = %s, want %s", tc.err, tc.resp, got, tc.expected)
			}
		})
	}
}

func TestConnectErrorKindString(t *testing.T) {
	tests := []struct {
		kind     connectErrorKind
		expected string
	}{
		{errKindNone, "none"},
		{errKindAuth, "auth_failed"},
		{errKindTransient, "transient"},
		{connectErrorKind(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.kind.String(); got != tc.expected {
			t.Errorf("connectErrorKind(%d).String() = %q, want %q", tc.kind, got, tc.expected)
		}
	}
}

func TestConnectionStateMethod(t *testing.T) {
	tests := []struct {
		name              string
		connected         bool
		pendingEnrollment bool
		lastError         string
		disconnectedAt    time.Time
		expectedState     string
		expectedLastErr   string
		expectedDiscoTime time.Time
	}{
		{
			name:            "connected returns connected state",
			connected:       true,
			lastError:       "",
			expectedState:   "connected",
			expectedLastErr: "",
		},
		{
			name:              "pending socket returns connecting state",
			connected:         true,
			pendingEnrollment: true,
			expectedState:     "connecting",
			expectedLastErr:   enrollmentPendingState,
		},
		{
			name:            "auth failure returns auth_failed state",
			connected:       false,
			lastError:       "auth_failed",
			disconnectedAt:  time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC),
			expectedState:   "auth_failed",
			expectedLastErr: "auth_failed",
		},
		{
			name:            "transient error returns connecting state",
			connected:       false,
			lastError:       "transient",
			disconnectedAt:  time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC),
			expectedState:   "connecting",
			expectedLastErr: "transient",
		},
		{
			name:            "no error and not connected returns disconnected",
			connected:       false,
			lastError:       "",
			expectedState:   "disconnected",
			expectedLastErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := &wsTransport{
				connected:         tc.connected,
				pendingEnrollment: tc.pendingEnrollment,
				lastError:         tc.lastError,
				disconnectedAt:    tc.disconnectedAt,
			}

			state, lastErr, discoAt := tr.ConnectionState()

			if state != tc.expectedState {
				t.Errorf("ConnectionState() state = %q, want %q", state, tc.expectedState)
			}
			if lastErr != tc.expectedLastErr {
				t.Errorf("ConnectionState() lastErr = %q, want %q", lastErr, tc.expectedLastErr)
			}
			if tc.name == "auth failure returns auth_failed state" {
				if !discoAt.Equal(tc.disconnectedAt) {
					t.Errorf("ConnectionState() disconnectedAt = %v, want %v", discoAt, tc.disconnectedAt)
				}
			}
		})
	}
}

func TestEnrollmentCredentialRejectionOverridesPendingSocketState(t *testing.T) {
	t.Parallel()
	transport := &wsTransport{
		connected:         true,
		pendingEnrollment: true,
		credentialError:   enrollmentTokenRejected,
	}

	state, lastErr, _ := transport.ConnectionState()
	if state != "auth_failed" || lastErr != enrollmentTokenRejected {
		t.Fatalf("ConnectionState() = (%q, %q), want (%q, %q)", state, lastErr, "auth_failed", enrollmentTokenRejected)
	}

	transport.updateToken("new-agent-token")
	state, lastErr, _ = transport.ConnectionState()
	if state != "connecting" || lastErr != enrollmentPendingState {
		t.Fatalf("credential adoption did not clear rejection: (%q, %q)", state, lastErr)
	}
}

func TestTransportUpdateToken(t *testing.T) {
	t.Parallel()
	transport := &wsTransport{
		runtimeIdentity: newRuntimeIdentitySource(RuntimeConfig{APIToken: "old-token"}),
	}
	transport.consecutiveAuthFailures = 5
	transport.lastError = "auth_failed"
	transport.updateToken("new-token")

	if got := transport.identitySource().Snapshot().BearerToken; got != "new-token" {
		t.Fatalf("expected token %q, got %q", "new-token", got)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.consecutiveAuthFailures != 0 {
		t.Fatalf("expected auth failures reset to 0, got %d", transport.consecutiveAuthFailures)
	}
	if transport.lastError != "" {
		t.Fatalf("expected lastError cleared, got %q", transport.lastError)
	}
}

func TestMarkDisconnectedStopsPing(t *testing.T) {
	t.Parallel()
	transport := &wsTransport{}
	transport.connected = true
	transport.pingDone = make(chan struct{})
	transport.markDisconnected()
	if transport.Connected() {
		t.Fatal("expected disconnected after markDisconnected")
	}
	if transport.pingDone != nil {
		t.Fatal("expected pingDone to be nil after markDisconnected")
	}
}

func TestTransportStatsInitialValues(t *testing.T) {
	t.Parallel()
	before := time.Now()
	transport := newWSTransport("ws://hub.example.com/ws", "token", "node-01", "linux", "v1.2.3", nil, "", nil)
	after := time.Now()

	sent, received, reconnects, uptime := transport.Stats()
	if sent != 0 {
		t.Errorf("initial messagesSent = %d, want 0", sent)
	}
	if received != 0 {
		t.Errorf("initial messagesReceived = %d, want 0", received)
	}
	if reconnects != 0 {
		t.Errorf("initial reconnectCount = %d, want 0", reconnects)
	}
	if uptime < 0 {
		t.Errorf("uptime = %v, want >= 0", uptime)
	}
	if transport.startedAt.Before(before) || transport.startedAt.After(after) {
		t.Errorf("startedAt = %v, expected between %v and %v", transport.startedAt, before, after)
	}
}

func TestTransportStatsCounterIncrements(t *testing.T) {
	t.Parallel()
	transport := &wsTransport{startedAt: time.Now()}

	atomic.AddInt64(&transport.messagesSent, 5)
	atomic.AddInt64(&transport.messagesReceived, 3)
	atomic.AddInt64(&transport.reconnectCount, 2)

	sent, received, reconnects, uptime := transport.Stats()
	if sent != 5 {
		t.Errorf("messagesSent = %d, want 5", sent)
	}
	if received != 3 {
		t.Errorf("messagesReceived = %d, want 3", received)
	}
	if reconnects != 2 {
		t.Errorf("reconnectCount = %d, want 2", reconnects)
	}
	if uptime < 0 {
		t.Errorf("uptime = %v, want >= 0", uptime)
	}
}

func TestValidateWebSocketTransportURLRequiresSecureSchemeByDefault(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "false")
	if err := validateWebSocketTransportURL("ws://hub.example.com/ws/agent"); err == nil {
		t.Fatalf("expected ws URL to be rejected without insecure opt-in")
	}
	if err := validateWebSocketTransportURL("wss://hub.example.com/ws/agent"); err != nil {
		t.Fatalf("expected wss URL to be accepted, got %v", err)
	}
}

func TestValidateWebSocketTransportURLAllowsInsecureWhenOptedIn(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	if err := validateWebSocketTransportURL("ws://hub.example.com/ws/agent"); err != nil {
		t.Fatalf("expected ws URL to be allowed with explicit opt-in, got %v", err)
	}
}

func TestValidateWebSocketTransportURLRejectsUserInfoWithoutEchoingIt(t *testing.T) {
	const sensitive = "credential-that-must-not-be-logged"
	err := validateWebSocketTransportURL("wss://agent:" + sensitive + "@hub.example.com/ws/agent")
	if err == nil {
		t.Fatal("expected websocket URL user info to be rejected")
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatal("websocket validation error exposed URL user info")
	}
}

func TestWebSocketOriginForLogOmitsPathQueryAndUserInfo(t *testing.T) {
	got := websocketOriginForLog("wss://agent:secret@hub.example.com/ws/agent?token=secret")
	if got != "wss://hub.example.com" {
		t.Fatalf("sanitized websocket origin = %q", got)
	}
}
