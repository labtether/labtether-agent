package securityruntime

import (
	"fmt"
	"net/http"
)

// HostRoutedTransport sends a request through Matched when Match reports true
// for its URL host name, and through Other for every other host. Each hop of
// a redirect is routed on its own. DoOutboundRequest applies the same dial
// checks to both transports.
type HostRoutedTransport struct {
	Match   func(hostname string) bool
	Matched *http.Transport
	Other   *http.Transport
}

func (t *HostRoutedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || req == nil || req.URL == nil {
		return nil, fmt.Errorf("request is required")
	}
	if t.Match != nil && t.Match(req.URL.Hostname()) {
		return t.Matched.RoundTrip(req)
	}
	return t.Other.RoundTrip(req)
}
