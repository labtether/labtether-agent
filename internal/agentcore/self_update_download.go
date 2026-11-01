package agentcore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

var (
	// selfUpdateStallTimeout ends a download when no data arrives for this
	// long, from the request start (connect, TLS, headers) and between reads.
	selfUpdateStallTimeout = 60 * time.Second
	// selfUpdateDownloadLimit caps the whole download, so a link that keeps
	// trickling bytes cannot hold an update open forever. 30 minutes moves a
	// 100 MB binary at about 60 KB/s.
	selfUpdateDownloadLimit = 30 * time.Minute
)

// stallWatch cancels a request when no progress happens for the stall timeout.
type stallWatch struct {
	timer   *time.Timer
	timeout time.Duration
	stalled atomic.Bool
}

func newStallWatch(timeout time.Duration, cancel context.CancelFunc) *stallWatch {
	watch := &stallWatch{timeout: timeout}
	watch.timer = time.AfterFunc(timeout, func() {
		watch.stalled.Store(true)
		cancel()
	})
	return watch
}

func (w *stallWatch) progress() { w.timer.Reset(w.timeout) }

func (w *stallWatch) stop() { w.timer.Stop() }

// stallErr names a stall plainly instead of a bare "context canceled".
func (w *stallWatch) stallErr(err error) error {
	if err != nil && w.stalled.Load() {
		return fmt.Errorf("no data received for %s: %w", w.timeout, err)
	}
	return err
}

type progressReader struct {
	r     io.Reader
	watch *stallWatch
}

func (p progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	if n > 0 {
		p.watch.progress()
	}
	return n, err
}

// downloadReleaseBinary fetches the release binary. A slow link is fine as
// long as data keeps arriving; only a stall or the overall cap ends it.
func downloadReleaseBinary(cfg RuntimeConfig, absoluteURL string, expectedSize int64) ([]byte, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := newStallWatch(selfUpdateStallTimeout, cancel)
	defer watch.stop()

	client := newSelfUpdateHTTPClient(cfg)
	client.Timeout = selfUpdateDownloadLimit
	req, err := securityruntime.NewOutboundRequestWithContext(ctx, http.MethodGet, absoluteURL, nil)
	if err != nil {
		return nil, err
	}
	if token := strings.TrimSpace(cfg.APIToken); token != "" && shouldAttachUpdateToken(cfg, absoluteURL) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := securityruntime.DoOutboundRequest(client, req)
	if err != nil {
		return nil, watch.stallErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("download endpoint returned status %d", resp.StatusCode)
	}
	watch.progress()
	body := progressReader{r: resp.Body, watch: watch}
	payload, err := io.ReadAll(io.LimitReader(body, maxSelfUpdateBinarySize+1))
	if err != nil {
		return nil, watch.stallErr(err)
	}
	if len(payload) > maxSelfUpdateBinarySize {
		return nil, fmt.Errorf("download exceeded maximum size of %d bytes", maxSelfUpdateBinarySize)
	}
	if expectedSize > 0 && int64(len(payload)) != expectedSize {
		return nil, fmt.Errorf("download size mismatch: expected %d bytes, got %d bytes", expectedSize, len(payload))
	}
	return payload, nil
}
