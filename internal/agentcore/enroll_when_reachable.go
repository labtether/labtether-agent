package agentcore

import (
	"context"
	"errors"
	"log"
	"math"
	"net/http"
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
// enrollment to try again.
func armEnrollmentWhenHubReachable(cfg RuntimeConfig, transport *wsTransport) {
	transport.mu.Lock()
	transport.enrollFn = func(ctx context.Context) (string, error) {
		return enrollWhenHubReachable(ctx, cfg, transport)
	}
	transport.mu.Unlock()
}

// enrollWhenHubReachable runs the start-up enrollment again and puts the
// issued token in use. As at start, the agent keeps the configured Hub
// address, saves its token and state, and removes the used token file.
func enrollWhenHubReachable(ctx context.Context, cfg RuntimeConfig, transport *wsTransport) (string, error) {
	err := enrollWithStagedToken(ctx, &cfg, transport.deviceIdentity)
	if cfg.APIToken == "" {
		return "", err
	}
	if err != nil {
		log.Printf("agent: %v", err)
	}
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
