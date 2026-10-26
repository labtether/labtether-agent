package securityruntime

import (
	"fmt"
	"net/http"
	"strings"
)

// DoOutboundStreamRequest preserves URL, redirect and dial policy for long-lived
// bodies, including duplex upgrades. The caller owns cancellation, plus any
// setup deadline. A whole-response http.Client.Timeout would cut off the stream.
func DoOutboundStreamRequest(base *http.Client, req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request is required")
	}
	if req.Context().Done() == nil {
		return nil, fmt.Errorf("HTTP stream requires a cancellable context")
	}
	if _, err := ValidateOutboundURL(req.URL.String()); err != nil {
		return nil, err
	}
	client := secureOutboundHTTPClient(base, strings.ToLower(strings.TrimSpace(req.URL.Scheme)))
	client.Timeout = 0
	// #nosec G704 -- Existing secured client validates URL, redirects and resolved addresses.
	return client.Do(req)
}
