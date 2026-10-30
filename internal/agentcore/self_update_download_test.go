package agentcore

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func trickleServer(chunks int, gap time.Duration, stallAfter int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < chunks; i++ {
			if i == stallAfter {
				<-r.Context().Done()
				return
			}
			_, _ = w.Write([]byte("chunk-"))
			w.(http.Flusher).Flush()
			select {
			case <-time.After(gap):
			case <-r.Context().Done():
				return
			}
		}
	}))
}

// One 30 s limit used to cover the whole update download, so a slow link
// failed partway although data kept arriving. Only a stall may end it now.
func TestSelfUpdateDownloadAllowsSlowLinksAndStopsStalls(t *testing.T) {
	t.Setenv(envAllowInsecureTransport, "true")
	t.Setenv("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", "true")
	originalRequest, originalStall := selfUpdateTimeout, selfUpdateStallTimeout
	selfUpdateTimeout, selfUpdateStallTimeout = 100*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { selfUpdateTimeout, selfUpdateStallTimeout = originalRequest, originalStall })

	slow := trickleServer(8, 50*time.Millisecond, -1)
	defer slow.Close()
	payload, err := downloadReleaseBinary(RuntimeConfig{}, slow.URL+"/binary", int64(8*len("chunk-")))
	if err != nil {
		t.Fatalf("slow but steady download failed: %v", err)
	}
	if len(payload) != 8*len("chunk-") {
		t.Fatalf("payload = %d bytes", len(payload))
	}

	stalled := trickleServer(8, 10*time.Millisecond, 2)
	defer stalled.Close()
	started := time.Now()
	if _, err := downloadReleaseBinary(RuntimeConfig{}, stalled.URL+"/binary", 0); err == nil || !strings.Contains(err.Error(), "no data received") {
		t.Fatalf("stalled download error = %v, want a stall error", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("stall took %s to detect", elapsed)
	}
}
