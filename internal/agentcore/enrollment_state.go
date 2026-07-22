package agentcore

import (
	"encoding/json"
	"errors"
	"fmt"
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
	Version   int    `json:"version"`
	AssetID   string `json:"asset_id"`
	HubWSURL  string `json:"hub_ws_url,omitempty"`
	HubAPIURL string `json:"hub_api_url,omitempty"`
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

	// The token-bound canonical asset ID is authoritative. Endpoint settings
	// remain operator-overridable, so saved URLs only fill absent values.
	cfg.AssetID = strings.TrimSpace(state.AssetID)
	if cfg.WSBaseURL == "" {
		cfg.WSBaseURL = normalizeWSBaseURL(state.HubWSURL)
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = normalizeAPIBaseURL(state.HubAPIURL)
		if cfg.APIBaseURL == "" {
			cfg.APIBaseURL = apiBaseURLFromWS(cfg.WSBaseURL)
		}
	}
	return nil
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
