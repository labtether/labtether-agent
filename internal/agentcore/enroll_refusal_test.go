package agentcore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A refused enrollment reached the user as only "enroll returned status
// 409": the Hub's explanation was dropped. It must reach the error the agent
// logs, as one line of printable text.
func TestEnrollmentRefusalCarriesTheHubsWords(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	const words = "This device was removed from LabTether. Only a new single-use enrollment token made after the removal can add it back."
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"` + words + `\u001b[31m\nsecond line"}`))
	}))
	defer server.Close()

	_, err := enrollWithHub(context.Background(), &RuntimeConfig{EnrollmentToken: "t", APIBaseURL: server.URL})
	got := enrollmentRefusalMessage(err)
	if !strings.HasPrefix(got, words) || strings.ContainsAny(got, "\x1b\n") {
		t.Fatalf("refusal = %q, want the Hub's words on one printable line", got)
	}
	if !strings.Contains(err.Error(), "LabTether refused the enrollment (HTTP 409): "+words) {
		t.Fatalf("error = %q", err)
	}
	if isEnrollmentCredentialRejected(err) {
		t.Fatal("a 409 refusal is not a rejected credential")
	}
}
