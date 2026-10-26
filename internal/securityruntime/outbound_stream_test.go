package securityruntime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOutboundStreamRetainsURLAndRedirectPolicy(t *testing.T) {
	t.Setenv(envOutboundAllowlistMode, "true")
	t.Setenv(envOutboundAllowedHosts, "127.0.0.1")
	t.Setenv(envOutboundAllowLoopback, "true")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1", nil)
	if _, err := DoOutboundStreamRequest(nil, req); err == nil || !strings.Contains(err.Error(), "cancellable") {
		t.Fatalf("uncancellable request: %v", err)
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost:1", nil)
	if _, err := DoOutboundStreamRequest(nil, req); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("unapproved original URL: %v", err)
	}
	var calls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer target.Close()
	redirect := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, redirect, http.StatusFound) }))
	defer origin.Close()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
	resp, err := DoOutboundStreamRequest(origin.Client(), req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "allowlist") || calls.Load() != 0 {
		t.Fatalf("redirect policy err=%v target requests=%d", err, calls.Load())
	}
}
