package securityruntime

import (
	"fmt"
	"net/http"
	"strings"
)

// NewReusableOutboundHTTPClient keeps an independently owned secure connection
// pool for a long-lived caller. Other DoOutboundRequest callers keep their
// existing behavior. URL and redirect checks still run for every request.
func NewReusableOutboundHTTPClient(base *http.Client, scheme string) *http.Client {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	client := secureOutboundHTTPClient(base, scheme)
	client.Transport = &reusableOutboundTransport{
		transport:     client.Transport,
		scheme:        scheme,
		allowPrivate:  resolvedOutboundAllowPrivate(scheme),
		allowLoopback: parseBoolEnv(envOutboundAllowLoopback, false),
	}
	return client
}

type reusableOutboundTransport struct {
	transport     http.RoundTripper
	scheme        string
	allowPrivate  bool
	allowLoopback bool
}

func (rt *reusableOutboundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request is required")
	}
	if _, err := ValidateOutboundURL(req.URL.String()); err != nil {
		return nil, err
	}
	scheme := strings.ToLower(strings.TrimSpace(req.URL.Scheme))
	if scheme != rt.scheme || resolvedOutboundAllowPrivate(scheme) != rt.allowPrivate ||
		parseBoolEnv(envOutboundAllowLoopback, false) != rt.allowLoopback {
		// A changed policy must never inherit the old pool's dial permissions.
		transport := secureOutboundRoundTripper(rt.transport, scheme)
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			defer closer.CloseIdleConnections()
		}
		return transport.RoundTrip(req)
	}
	return rt.transport.RoundTrip(req)
}

func (rt *reusableOutboundTransport) CloseIdleConnections() {
	if closer, ok := rt.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
