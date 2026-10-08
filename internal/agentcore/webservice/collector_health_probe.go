package webservice

import (
	"github.com/labtether/protocol"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// healthCheckWithFallback performs health check on a service.
// If the primary URL fails and a raw_url exists in metadata, retries with the raw URL
// to avoid false "down" from DNS resolution failures on proxied domains.
func (wsc *WebServiceCollector) healthCheckWithFallback(svc *protocol.DiscoveredWebService) {
	wsc.healthCheck(svc)

	// If proxied URL failed and we have a raw URL, retry with raw
	if svc.Status == "down" && svc.Metadata != nil && svc.Metadata["raw_url"] != "" {
		rawURL := svc.Metadata["raw_url"]
		healthPath := ""
		if svc.Metadata["health_path"] != "" {
			healthPath = svc.Metadata["health_path"]
		}
		result := wsc.probeHealthURL(rawURL, healthPath)
		if result.responded && result.status > 0 && result.status < 500 {
			svc.Status = "up"
			svc.ResponseMs = result.responseMs
		}
	}
}

// healthCheck performs an HTTP health check on a discovered service.
// It tries HEAD first, then falls back to GET. Status < 500 = "up".
func (wsc *WebServiceCollector) healthCheck(svc *protocol.DiscoveredWebService) {
	healthPath := ""
	if svc.Metadata != nil && svc.Metadata["health_path"] != "" {
		healthPath = svc.Metadata["health_path"]
	}

	result := wsc.probeHealthURL(svc.URL, healthPath)
	if result.responded {
		if result.baseURL != "" && result.baseURL != svc.URL {
			svc.URL = result.baseURL
		}
		svc.ResponseMs = result.responseMs
		if result.status > 0 && result.status < 500 {
			svc.Status = "up"
		} else {
			svc.Status = "down"
		}
		return
	}

	svc.ResponseMs = 0
	svc.Status = "down"
}

type healthProbeResult struct {
	baseURL    string
	status     int
	responseMs int
	responded  bool
}

// probeHealthURL checks both the provided scheme and its alternate (http<->https),
// then selects the most credible response. This improves scheme detection for
// non-standard TLS ports where static port heuristics are unreliable.
func (wsc *WebServiceCollector) probeHealthURL(baseURL, healthPath string) healthProbeResult {
	primary := wsc.probeCandidateHealth(baseURL, healthPath)
	tryAlternate := !primary.responded || primary.status == http.StatusBadRequest
	if !tryAlternate {
		return primary
	}

	altURL := alternateSchemeURL(baseURL)
	if altURL == "" {
		return primary
	}
	alternate := wsc.probeCandidateHealth(altURL, healthPath)
	return betterProbeResult(primary, alternate)
}

func (wsc *WebServiceCollector) probeCandidateHealth(baseURL, healthPath string) healthProbeResult {
	checkURL := baseURL
	if healthPath != "" {
		checkURL = strings.TrimRight(baseURL, "/") + healthPath
	}
	status, responseMs, responded := wsc.probeHTTP(checkURL)
	return healthProbeResult{
		baseURL:    baseURL,
		status:     status,
		responseMs: responseMs,
		responded:  responded,
	}
}

func betterProbeResult(primary, alternate healthProbeResult) healthProbeResult {
	primaryScore := probeScore(primary)
	alternateScore := probeScore(alternate)
	if alternateScore > primaryScore {
		return alternate
	}
	if primaryScore > alternateScore {
		return primary
	}

	// On equal confidence, prefer HTTPS for safer defaults.
	if primaryScore > 0 {
		primaryHTTPS := strings.HasPrefix(strings.ToLower(primary.baseURL), "https://")
		alternateHTTPS := strings.HasPrefix(strings.ToLower(alternate.baseURL), "https://")
		if alternateHTTPS && !primaryHTTPS {
			return alternate
		}
	}
	return primary
}

func probeScore(result healthProbeResult) int {
	if !result.responded {
		return 0
	}
	switch {
	case result.status >= 200 && result.status < 400:
		return 4
	case result.status == http.StatusUnauthorized || result.status == http.StatusForbidden || result.status == http.StatusNotFound:
		return 3
	case result.status == http.StatusBadRequest:
		return 1
	case result.status >= 400 && result.status < 500:
		return 2
	default:
		return 1
	}
}

func (wsc *WebServiceCollector) probeHTTP(url string) (status int, responseMs int, responded bool) {
	start := time.Now()
	status, ok := wsc.doHealthRequest(http.MethodHead, url)
	if ok {
		return status, int(time.Since(start).Milliseconds()), true
	}

	// HEAD failed — retry with GET (some services reject HEAD).
	start = time.Now()
	status, ok = wsc.doHealthRequest(http.MethodGet, url)
	if !ok {
		return 0, 0, false
	}
	return status, int(time.Since(start).Milliseconds()), true
}

func (wsc *WebServiceCollector) probeClientForURL(targetURL string) *http.Client {
	if wsc == nil {
		return nil
	}
	isHTTPS := strings.HasPrefix(strings.ToLower(strings.TrimSpace(targetURL)), "https://")
	if isHTTPS && wsc.insecureClient != nil {
		// Discovery probes do not carry secrets, so prefer the insecure client for HTTPS
		// to avoid cert-validation noise against self-signed/local endpoints.
		return wsc.insecureClient
	}
	return wsc.client
}

func (wsc *WebServiceCollector) fallbackProbeClientForURL(targetURL string, primary *http.Client) *http.Client {
	if wsc == nil {
		return nil
	}
	isHTTPS := strings.HasPrefix(strings.ToLower(strings.TrimSpace(targetURL)), "https://")
	if isHTTPS {
		if primary != wsc.insecureClient && wsc.insecureClient != nil {
			return wsc.insecureClient
		}
		if primary != wsc.client && wsc.client != nil {
			return wsc.client
		}
		return nil
	}
	if primary != wsc.client && wsc.client != nil {
		return wsc.client
	}
	return nil
}

// doHealthRequest makes an HTTP request and returns the status code and success flag.
func (wsc *WebServiceCollector) doHealthRequest(method, url string) (int, bool) {
	client := wsc.probeClientForURL(url)
	if client == nil {
		return 0, false
	}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("User-Agent", "LabTether-Agent/1.0")

	resp, err := client.Do(req) // #nosec G704 -- Request target already passed discovery/outbound validation before probing.
	if err != nil {
		if fallback := wsc.fallbackProbeClientForURL(url, client); fallback != nil {
			fallbackReq, reqErr := http.NewRequest(method, url, nil)
			if reqErr == nil {
				fallbackReq.Header.Set("User-Agent", "LabTether-Agent/1.0")
				resp, err = fallback.Do(fallbackReq) // #nosec G704 -- Fallback client reuses the same validated target URL.
			}
		}
	}
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	return resp.StatusCode, true
}

func alternateSchemeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		parsed.Scheme = "https"
	case "https":
		parsed.Scheme = "http"
	default:
		return ""
	}
	return parsed.String()
}
