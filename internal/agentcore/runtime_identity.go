package agentcore

import (
	"fmt"
	"strings"
	"sync"
)

const maxAgentBearerTokenBytes = 4096

func normalizeIssuedAgentToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)
	if token == "" || len(token) > maxAgentBearerTokenBytes {
		return "", fmt.Errorf("agent credential length is invalid")
	}
	for _, ch := range token {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-', ch == '.', ch == '_', ch == '~', ch == '+', ch == '/', ch == '=':
		default:
			return "", fmt.Errorf("agent credential contains invalid characters")
		}
	}
	return token, nil
}

// runtimeIdentitySnapshot is the complete credential and routing identity used
// by every outbound agent transport. Values are immutable once returned from
// Snapshot; updates replace the whole snapshot under one lock so readers can
// never observe a token paired with the wrong asset or hub origin.
type runtimeIdentitySnapshot struct {
	BearerToken string
	AssetID     string
	WSBaseURL   string
	APIBaseURL  string
	generation  uint64
}

type runtimeIdentitySource struct {
	mu      sync.RWMutex
	current runtimeIdentitySnapshot
}

func newRuntimeIdentitySource(cfg RuntimeConfig) *runtimeIdentitySource {
	wsBaseURL := normalizeWSBaseURL(cfg.WSBaseURL)
	apiBaseURL := normalizeAPIBaseURL(cfg.APIBaseURL)
	if apiBaseURL == "" {
		apiBaseURL = apiBaseURLFromWS(wsBaseURL)
	}
	return &runtimeIdentitySource{current: runtimeIdentitySnapshot{
		BearerToken: strings.TrimSpace(cfg.APIToken),
		AssetID:     strings.TrimSpace(cfg.AssetID),
		WSBaseURL:   wsBaseURL,
		APIBaseURL:  apiBaseURL,
		generation:  1,
	}}
}

func (s *runtimeIdentitySource) Snapshot() runtimeIdentitySnapshot {
	if s == nil {
		return runtimeIdentitySnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *runtimeIdentitySource) AssetID() string {
	return s.Snapshot().AssetID
}

// AdoptCredential atomically installs a newly issued bearer and its canonical
// identity. Empty origins preserve the currently active origin. When a new WS
// origin is supplied without an API origin, the API origin is derived from it
// so HTTP fallback cannot remain pinned to a previous hub.
func (s *runtimeIdentitySource) AdoptCredential(token, assetID, wsBaseURL, apiBaseURL string) (runtimeIdentitySnapshot, error) {
	if s == nil {
		return runtimeIdentitySnapshot{}, fmt.Errorf("runtime identity source is unavailable")
	}
	var err error
	token, err = normalizeIssuedAgentToken(token)
	assetID = strings.TrimSpace(assetID)
	if err != nil {
		return runtimeIdentitySnapshot{}, err
	}
	if !validPersistedAssetID(assetID) {
		return runtimeIdentitySnapshot{}, fmt.Errorf("canonical asset id is invalid")
	}

	normalizedWS := normalizeWSBaseURL(wsBaseURL)
	normalizedAPI := normalizeAPIBaseURL(apiBaseURL)

	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.current
	next.BearerToken = token
	next.AssetID = assetID
	if normalizedWS != "" {
		next.WSBaseURL = normalizedWS
	}
	if normalizedAPI != "" {
		next.APIBaseURL = normalizedAPI
	} else if normalizedWS != "" || next.APIBaseURL == "" {
		next.APIBaseURL = apiBaseURLFromWS(next.WSBaseURL)
	}
	next.generation++
	s.current = next
	return next, nil
}

// AdoptCanonicalAsset applies a token-bound asset ID returned by the exact
// handshake represented by expected. A concurrent credential/origin rotation
// wins and makes this stale handshake update a no-op.
func (s *runtimeIdentitySource) AdoptCanonicalAsset(expected runtimeIdentitySnapshot, assetID string) (runtimeIdentitySnapshot, bool, error) {
	if s == nil {
		return runtimeIdentitySnapshot{}, false, fmt.Errorf("runtime identity source is unavailable")
	}
	assetID = strings.TrimSpace(assetID)
	if !validPersistedAssetID(assetID) {
		return runtimeIdentitySnapshot{}, false, fmt.Errorf("canonical asset id is invalid")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.generation != expected.generation {
		return s.current, false, nil
	}
	next := s.current
	next.AssetID = assetID
	if next.APIBaseURL == "" {
		next.APIBaseURL = apiBaseURLFromWS(next.WSBaseURL)
	}
	next.generation++
	s.current = next
	return next, true, nil
}

// UpdateToken keeps compatibility with the reconnect state machine while
// still updating the single authoritative snapshot. Full enrollment/recovery
// paths use AdoptCredential so token, asset, and origins change together.
func (s *runtimeIdentitySource) UpdateToken(token string) error {
	if s == nil {
		return fmt.Errorf("runtime identity source is unavailable")
	}
	var err error
	token, err = normalizeIssuedAgentToken(token)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.BearerToken == token {
		return nil
	}
	next := s.current
	next.BearerToken = token
	next.generation++
	s.current = next
	return nil
}

func (s *runtimeIdentitySource) MatchesConnection(snapshot runtimeIdentitySnapshot) bool {
	current := s.Snapshot()
	return current.generation == snapshot.generation
}
