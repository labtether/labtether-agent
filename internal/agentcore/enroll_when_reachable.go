package agentcore

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"math"
	"net/http"
	"strings"
	"time"
)

// An agent started while its Hub is down cannot enroll at start. It used to
// connect without a token, so the Hub held it as a pending device for an
// admin to approve, and its one-use token was never used. Now the reconnect
// loop enrolls with the staged token before it would open a socket without
// one, waiting between tries as after a failed connect. Once the Hub refuses
// the token or the request, the agent connects as a pending device, as it
// does when the Hub refuses the token at start.

// enrollmentRetryable reports whether a failed enrollment can work later: no
// answer from the Hub (no route, refused connection, TLS failure, time-out,
// an answer that is not the Hub's), or an answer that says it cannot take the
// request now (408, 429, or a 5xx from the Hub or a proxy in front of it).
// The Hub refuses the token itself with 401 (unknown, used, expired, revoked,
// made for another device) and other requests with 400 or 409; those stay.
func enrollmentRetryable(err error) bool {
	if err == nil {
		return false
	}
	var refusal *enrollmentHTTPStatusError
	if !errors.As(err, &refusal) {
		return true
	}
	code := refusal.statusCode
	return code == http.StatusRequestTimeout || code == http.StatusTooManyRequests ||
		code >= http.StatusInternalServerError
}

// startEnrollmentUnanswered reports whether enrollment at start left the
// staged token unused because the Hub did not answer. Run checks it right
// after start-up enrollment, before cfg.APIToken is cleared.
func startEnrollmentUnanswered(cfg RuntimeConfig, startErr error) bool {
	return cfg.APIToken == "" && cfg.EnrollmentToken != "" && enrollmentRetryable(startErr)
}

// armEnrollmentWhenHubReachable gives the reconnect loop the start-up
// enrollment to try again. fallback is the HTTP heartbeat publisher Run
// built, which a late enrollment gives the new TLS settings too.
func armEnrollmentWhenHubReachable(cfg RuntimeConfig, transport *wsTransport, fallback HeartbeatPublisher) {
	transport.mu.Lock()
	transport.enrollFn = func(ctx context.Context) (string, error) {
		return enrollWhenHubReachable(ctx, cfg, transport, fallback)
	}
	transport.mu.Unlock()
}

// enrollWhenHubReachable runs the start-up enrollment again and puts the
// issued token in use. As at start, the agent keeps the configured Hub
// address, saves its token and state, removes the used token file and trusts
// the CA the Hub returned from the next connection.
func enrollWhenHubReachable(ctx context.Context, cfg RuntimeConfig, transport *wsTransport, fallback HeartbeatPublisher) (string, error) {
	err := enrollWithStagedToken(ctx, &cfg, transport.deviceIdentity)
	if cfg.APIToken == "" {
		return "", err
	}
	if err != nil {
		log.Printf("agent: %v", err)
	}
	// Before the token is in use, so no connection carries it with the TLS
	// settings from start.
	useEnrolledHubTrust(cfg, transport, fallback)
	if _, adoptErr := transport.identitySource().AdoptCredential(cfg.APIToken, cfg.AssetID, cfg.WSBaseURL,
		cfg.APIBaseURL, canonicalGroupIDPointer(cfg.GroupID, cfg.groupIDCanonical)); adoptErr != nil {
		return "", adoptErr
	}
	warning := ""
	if errors.Is(err, errAgentTokenPersistence) {
		warning = agentTokenPersistenceFailed
	}
	transport.setCredentialPersistenceError(warning)
	// The token is spent, so there is nothing left to re-enroll with.
	transport.mu.Lock()
	transport.reEnrollFn = nil
	transport.mu.Unlock()
	return cfg.APIToken, nil
}

// enrollBeforeConnect tries the start-up enrollment again while it is armed
// and the agent has no token. retry is true when the Hub did not answer: the
// loop waits the returned time, as after a failed connect, and comes back.
// After success or a refusal it returns retry false and the loop connects,
// with the issued token or without one.
func (t *wsTransport) enrollBeforeConnect(ctx context.Context, backoff *time.Duration) (wait time.Duration, retry bool) {
	t.mu.Lock()
	enroll := t.enrollFn
	t.mu.Unlock()
	if enroll == nil || t.identitySource().Snapshot().BearerToken != "" {
		return 0, false
	}
	token, err := enroll(ctx)
	if err == nil {
		t.disarmEnrollment()
		t.updateToken(token)
		*backoff = time.Second
		log.Printf("agentws: enrolled with the enrollment token, connecting")
		return 0, false
	}
	if ctx.Err() != nil {
		return 0, true
	}
	if !enrollmentRetryable(err) {
		// Never offer a refused token again from here; the loop connects
		// as a pending device instead.
		t.disarmEnrollment()
		if refusal := enrollmentRefusalMessage(err); refusal != "" {
			t.setEnrollmentRefusal(refusal)
			log.Printf("agentws: LabTether refused the enrollment: %s", refusal)
		} else {
			log.Printf("agentws: enrollment failed: %v", err)
		}
		if isEnrollmentCredentialRejected(err) {
			t.setCredentialError(enrollmentTokenRejected)
		}
		return 0, false
	}

	now := t.currentTime()
	wait = *backoff + t.jitterDuration(*backoff/4)
	*backoff = time.Duration(math.Min(float64(*backoff*2), float64(maxBackoff)))
	t.mu.Lock()
	t.lastError = errKindTransient.String()
	t.lastErrorReason = classifyConnectReason(err, nil)
	t.lastErrorAt = now
	if t.disconnectedAt.IsZero() {
		t.disconnectedAt = now
	}
	t.mu.Unlock()
	log.Printf("agentws: enrollment did not reach the Hub, retrying in %s: %v", wait, err)
	return wait, true
}

func (t *wsTransport) disarmEnrollment() {
	t.mu.Lock()
	t.enrollFn = nil
	t.mu.Unlock()
}

// Start-up enrollment runs before Run builds the connections to the Hub, so
// they trust the CA the Hub returned from the first one, and that CA turns
// certificate checks back on for an agent started with
// LABTETHER_TLS_SKIP_VERIFY and no CA file. A late enrollment runs after
// those connections exist, so it gives them the settings Run would have
// built from the same answer.

// enrolledHubTrust is the trust a late enrollment put in use.
type enrolledHubTrust struct {
	caFile     string
	skipVerify bool
}

// hubTLSUser is a Hub connection built at start with its own TLS settings.
type hubTLSUser interface {
	useHubTLSConfig(*tls.Config)
}

// useEnrolledHubTrust repeats Run's TLS steps for cfg after a late
// enrollment: a CA wins over skip-verify, and the WebSocket, the HTTP
// heartbeat fallback and Hub requests from handlers use the result from
// their next connection. enrollWithStagedToken saves the Hub's CA only when
// allowed (not with LABTETHER_TLS_CA_ONLY, never over a CA file the person
// set); without a saved CA the settings come out as they were.
func useEnrolledHubTrust(cfg RuntimeConfig, transport *wsTransport, fallback HeartbeatPublisher) {
	if cfg.TLSSkipVerify && strings.TrimSpace(cfg.TLSCAFile) != "" {
		log.Printf("agent: the Hub CA in %s takes priority; ignoring LABTETHER_TLS_SKIP_VERIFY", cfg.TLSCAFile)
		cfg.TLSSkipVerify = false
	}
	tlsCfg := buildTLSConfig(&cfg)
	transport.mu.Lock()
	transport.tlsConfig = tlsCfg
	transport.enrolledTrust = &enrolledHubTrust{caFile: cfg.TLSCAFile, skipVerify: cfg.TLSSkipVerify}
	transport.mu.Unlock()
	if user, ok := fallback.(hubTLSUser); ok {
		user.useHubTLSConfig(tlsCfg)
	}
}

func (t *wsTransport) hubTLSConfig() *tls.Config {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tlsConfig
}

// withEnrolledHubTrust gives cfg the trust a late enrollment put in use, for
// Hub requests that handlers build from the configuration (update checks).
func (t *wsTransport) withEnrolledHubTrust(cfg RuntimeConfig) RuntimeConfig {
	t.mu.Lock()
	trust := t.enrolledTrust
	t.mu.Unlock()
	if trust != nil {
		cfg.TLSCAFile, cfg.TLSSkipVerify = trust.caFile, trust.skipVerify
	}
	return cfg
}
