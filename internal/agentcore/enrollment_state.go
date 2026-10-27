package agentcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	enrollmentStateFileName = "enrollment-state.json"
	enrollmentStateVersion  = 1
	maxEnrollmentStateBytes = 64 * 1024
)

type enrollmentState struct {
	Version   int     `json:"version"`
	AssetID   string  `json:"asset_id"`
	GroupID   *string `json:"group_id,omitempty"`
	HubWSURL  string  `json:"hub_ws_url,omitempty"`
	HubAPIURL string  `json:"hub_api_url,omitempty"`
	// TokenOrigins lists the Hub host:port addresses the saved agent token
	// was issued for. The token is never sent anywhere else.
	TokenOrigins []string `json:"token_origins,omitempty"`
}

func canonicalGroupIDPointer(groupID string, known bool) *string {
	if !known {
		return nil
	}
	normalized := strings.TrimSpace(groupID)
	return &normalized
}

func enrollmentStatePath(tokenFilePath string) string {
	if strings.TrimSpace(tokenFilePath) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(tokenFilePath), enrollmentStateFileName)
}

func saveEnrollmentState(tokenFilePath string, state enrollmentState) error {
	path := enrollmentStatePath(tokenFilePath)
	if path == "" {
		return nil
	}
	state.Version = enrollmentStateVersion
	state.AssetID = strings.TrimSpace(state.AssetID)
	if state.GroupID != nil {
		state.GroupID = canonicalGroupIDPointer(*state.GroupID, true)
	}
	state.HubWSURL = normalizeWSBaseURL(state.HubWSURL)
	state.HubAPIURL = normalizeAPIBaseURL(state.HubAPIURL)
	if state.HubAPIURL == "" {
		state.HubAPIURL = apiBaseURLFromWS(state.HubWSURL)
	}
	if !validPersistedAssetID(state.AssetID) {
		return fmt.Errorf("invalid enrollment asset id")
	}
	if err := validatePersistedHubURL(state.HubWSURL, true); err != nil {
		return err
	}
	if err := validatePersistedHubURL(state.HubAPIURL, false); err != nil {
		return err
	}
	state.TokenOrigins = mergeHubOrigins(state.TokenOrigins, state.HubWSURL, state.HubAPIURL)

	raw, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal enrollment state: %w", err)
	}
	if err := writeManagedFileAtomic(path, raw, 0o600, true); err != nil {
		return fmt.Errorf("commit enrollment state: %w", err)
	}
	return nil
}

func restoreEnrollmentState(cfg *RuntimeConfig) error {
	if cfg == nil {
		return nil
	}
	path := enrollmentStatePath(cfg.TokenFilePath)
	if path == "" {
		return nil
	}
	raw, err := readBoundedRegularFile(path, maxEnrollmentStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		if cfg.APIBaseURL == "" {
			cfg.APIBaseURL = apiBaseURLFromWS(cfg.WSBaseURL)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat enrollment state: %w", err)
	}
	var state enrollmentState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("decode enrollment state: %w", err)
	}
	if state.Version != enrollmentStateVersion || !validPersistedAssetID(strings.TrimSpace(state.AssetID)) {
		return fmt.Errorf("invalid enrollment state content")
	}
	if err := validatePersistedHubURL(state.HubWSURL, true); err != nil {
		return err
	}
	if err := validatePersistedHubURL(state.HubAPIURL, false); err != nil {
		return err
	}

	// The token-bound canonical asset ID is authoritative. A single endpoint
	// override moves both transports to the chosen origin. A deliberately split
	// WS/API setup must provide both endpoints explicitly.
	cfg.AssetID = strings.TrimSpace(state.AssetID)
	if state.GroupID != nil {
		cfg.GroupID = strings.TrimSpace(*state.GroupID)
		cfg.groupIDCanonical = true
	}
	configuredWS := normalizeWSBaseURL(cfg.WSBaseURL)
	configuredAPI := normalizeAPIBaseURL(cfg.APIBaseURL)
	savedWS := normalizeWSBaseURL(state.HubWSURL)
	savedAPI := normalizeAPIBaseURL(state.HubAPIURL)
	switch {
	case configuredWS != "" && configuredAPI != "":
		cfg.WSBaseURL, cfg.APIBaseURL = configuredWS, configuredAPI
	case configuredWS != "":
		cfg.WSBaseURL, cfg.APIBaseURL = configuredWS, apiBaseURLFromWS(configuredWS)
	case configuredAPI != "":
		cfg.WSBaseURL, cfg.APIBaseURL = wsBaseURLFromAPI(configuredAPI, savedWS), configuredAPI
	default:
		cfg.WSBaseURL, cfg.APIBaseURL = savedWS, savedAPI
		if cfg.APIBaseURL == "" {
			cfg.APIBaseURL = apiBaseURLFromWS(cfg.WSBaseURL)
		}
	}
	holdTokenForOtherHub(cfg, state)
	return nil
}

// holdTokenForOtherHub clears cfg.APIToken when the configured Hub address is
// not one the saved token was issued for, so a changed LABTETHER_WS_URL never
// hands this Hub's credential to whoever runs the new address. With a staged
// enrollment token the agent then enrolls with the new Hub.
func holdTokenForOtherHub(cfg *RuntimeConfig, state enrollmentState) {
	if len(state.TokenOrigins) == 0 {
		// State saved before token origins existed: trust the addresses this
		// agent already uses with the token, once, and record them.
		state.TokenOrigins = mergeHubOrigins(nil, state.HubWSURL, state.HubAPIURL, cfg.WSBaseURL, cfg.APIBaseURL)
		if err := saveEnrollmentState(cfg.TokenFilePath, state); err != nil {
			log.Printf("agent: warning: could not record the Hub addresses for the saved token: %v", err)
		}
		return
	}
	allowed := make(map[string]bool, len(state.TokenOrigins))
	for _, origin := range state.TokenOrigins {
		allowed[origin] = true
	}
	for _, target := range []string{cfg.WSBaseURL, cfg.APIBaseURL} {
		if origin := hubOrigin(target); origin != "" && !allowed[origin] {
			log.Printf("agent: the saved agent token was issued by another Hub address, so it is not sent to %s. Stage an enrollment token from that Hub to enroll this agent there.", origin)
			cfg.APIToken = ""
			return
		}
	}
}

// savedTokenOrigins returns the token origins already recorded, for callers
// that rewrite the state without changing the token.
func savedTokenOrigins(tokenFilePath string) []string {
	path := enrollmentStatePath(tokenFilePath)
	if path == "" {
		return nil
	}
	raw, err := readBoundedRegularFile(path, maxEnrollmentStateBytes)
	if err != nil {
		return nil
	}
	var state enrollmentState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil
	}
	return state.TokenOrigins
}

// hubOrigin returns the lower-case host:port a Hub URL reaches, so the ws/wss
// and http/https spellings of one address compare equal.
func hubOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "wss", "https":
			port = "443"
		case "ws", "http":
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(parsed.Hostname()), port)
}

func mergeHubOrigins(origins []string, urls ...string) []string {
	seen := make(map[string]bool, len(origins)+len(urls))
	merged := make([]string, 0, len(origins)+len(urls))
	for _, origin := range origins {
		if origin = strings.TrimSpace(origin); origin != "" && !seen[origin] {
			seen[origin] = true
			merged = append(merged, origin)
		}
	}
	for _, raw := range urls {
		if origin := hubOrigin(raw); origin != "" && !seen[origin] {
			seen[origin] = true
			merged = append(merged, origin)
		}
	}
	return merged
}

func validPersistedAssetID(assetID string) bool {
	if assetID == "" || len(assetID) > 128 {
		return false
	}
	for _, ch := range assetID {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-', ch == '_', ch == '.':
		default:
			return false
		}
	}
	return true
}

func validatePersistedHubURL(raw string, websocketURL bool) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("invalid persisted hub URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if websocketURL {
		if scheme != "wss" && !(scheme == "ws" && allowInsecureTransportOptIn()) {
			return fmt.Errorf("invalid persisted hub websocket URL")
		}
		return nil
	}
	if scheme != "https" && !(scheme == "http" && allowInsecureTransportOptIn()) {
		return fmt.Errorf("invalid persisted hub API URL")
	}
	return nil
}

func apiBaseURLFromWS(raw string) string {
	parsed, err := url.Parse(normalizeWSBaseURL(raw))
	if err != nil || strings.TrimSpace(parsed.Host) == "" {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "wss":
		parsed.Scheme = "https"
	case "ws":
		if allowInsecureTransportOptIn() {
			parsed.Scheme = "http"
		} else {
			parsed.Scheme = "https"
		}
	default:
		return ""
	}
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}

func wsBaseURLFromAPI(rawAPI, savedWS string) string {
	api, err := url.Parse(normalizeAPIBaseURL(rawAPI))
	if err != nil || api.Host == "" || api.User != nil {
		return ""
	}
	ws := &url.URL{Host: api.Host, Path: "/ws/agent"}
	if saved, err := url.Parse(normalizeWSBaseURL(savedWS)); err == nil && saved.Path != "" {
		ws.Path, ws.RawPath = saved.Path, saved.RawPath
	}
	switch api.Scheme {
	case "https":
		ws.Scheme = "wss"
	case "http":
		if !allowInsecureTransportOptIn() {
			return ""
		}
		ws.Scheme = "ws"
	default:
		return ""
	}
	return ws.String()
}
