package webservice

import (
	"github.com/labtether/protocol"
	"strconv"
	"strings"
	"time"
)

const (
	compatMetadataConnector  = "compat_connector"
	compatMetadataConfidence = "compat_confidence"
	compatMetadataAuthHint   = "compat_auth_hint"
	compatMetadataProfile    = "compat_profile"
	compatMetadataEvidence   = "compat_evidence"

	compatMinConfidence = 0.60
	compatCacheHitTTL   = 10 * time.Minute
	compatCacheMissTTL  = 3 * time.Minute
)

type compatCacheEntry struct {
	match     compatMatch
	expiresAt time.Time
}

type compatMatch struct {
	connector  string
	profile    string
	authHint   string
	evidence   string
	confidence float64
	responded  bool

	serviceKey  string
	displayName string
	category    string
	iconKey     string
	healthPath  string
}

func (wsc *WebServiceCollector) applyCompatibilityMetadata(svc *protocol.DiscoveredWebService, baseURL string) {
	if svc == nil {
		return
	}
	if svc.Source == "manual" {
		return
	}
	if wsc.compatCache == nil {
		wsc.compatCache = make(map[string]compatCacheEntry)
	}

	if svc.Metadata == nil {
		svc.Metadata = make(map[string]string)
	}

	cacheKey := strings.ToLower(strings.TrimSpace(baseURL))
	if cacheKey == "" {
		cacheKey = strings.ToLower(strings.TrimSpace(svc.URL))
	}
	if cacheKey == "" {
		return
	}

	now := wsc.now()
	if cached, ok := wsc.compatCache[cacheKey]; ok {
		if now.Before(cached.expiresAt) {
			if cached.match.confidence >= compatMinConfidence {
				applyCompatMatchToService(svc, cached.match)
			}
			return
		}
		delete(wsc.compatCache, cacheKey)
	}

	match := matchCompatibilityFromServiceKey(strings.TrimSpace(svc.ServiceKey))
	if match.confidence < compatMinConfidence {
		match = wsc.detectCompatibleAPI(baseURL)
	}

	if match.confidence >= compatMinConfidence {
		wsc.compatCache[cacheKey] = compatCacheEntry{
			match:     match,
			expiresAt: now.Add(compatCacheHitTTL),
		}
		wsc.pruneCompatCache(now)
		applyCompatMatchToService(svc, match)
		return
	}

	wsc.compatCache[cacheKey] = compatCacheEntry{expiresAt: now.Add(compatCacheMissTTL)}
	wsc.pruneCompatCache(now)
}

func (wsc *WebServiceCollector) pruneCompatCache(now time.Time) {
	if len(wsc.compatCache) <= maxCompatCacheEntries {
		return
	}

	for key, entry := range wsc.compatCache {
		if now.After(entry.expiresAt) {
			delete(wsc.compatCache, key)
		}
	}
	if len(wsc.compatCache) <= maxCompatCacheEntries {
		return
	}

	for len(wsc.compatCache) > maxCompatCacheEntries {
		oldestKey := ""
		var oldestExpiry time.Time
		for key, entry := range wsc.compatCache {
			if oldestKey == "" || entry.expiresAt.Before(oldestExpiry) {
				oldestKey = key
				oldestExpiry = entry.expiresAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(wsc.compatCache, oldestKey)
	}
}

func matchCompatibilityFromServiceKey(serviceKey string) compatMatch {
	switch strings.ToLower(strings.TrimSpace(serviceKey)) {
	case "portainer":
		known, _ := LookupByKey("portainer")
		return compatMatch{
			connector:   "portainer",
			profile:     "service-key.portainer",
			authHint:    "api_key,password",
			evidence:    "known service key",
			confidence:  0.92,
			serviceKey:  known.Key,
			displayName: known.Name,
			category:    known.Category,
			iconKey:     known.IconKey,
			healthPath:  known.HealthPath,
		}
	case "homeassistant":
		known, _ := LookupByKey("homeassistant")
		return compatMatch{
			connector:   "homeassistant",
			profile:     "service-key.homeassistant",
			authHint:    "token",
			evidence:    "known service key",
			confidence:  0.92,
			serviceKey:  known.Key,
			displayName: known.Name,
			category:    known.Category,
			iconKey:     known.IconKey,
			healthPath:  known.HealthPath,
		}
	default:
		return compatMatch{}
	}
}

func (wsc *WebServiceCollector) detectCompatibleAPI(baseURL string) compatMatch {
	trimmedBase := strings.TrimSpace(baseURL)
	if trimmedBase == "" {
		return compatMatch{}
	}

	probeOrder := compatibilityProbeOrder(portFromURL(trimmedBase))
	best, responded := wsc.detectCompatibleAPIAtBase(trimmedBase, probeOrder)
	if best.confidence >= 0.97 || responded {
		return best
	}

	alternateBase := alternateSchemeURL(trimmedBase)
	if alternateBase == "" || strings.EqualFold(trimmedBase, alternateBase) {
		return best
	}

	alternateBest, _ := wsc.detectCompatibleAPIAtBase(alternateBase, probeOrder)
	if alternateBest.confidence > best.confidence {
		return alternateBest
	}
	return best
}

func (wsc *WebServiceCollector) detectCompatibleAPIAtBase(baseURL string, probeOrder []compatProbeFn) (compatMatch, bool) {
	best := compatMatch{}
	responded := false
	for _, probe := range probeOrder {
		match := probe(wsc, baseURL)
		if match.responded {
			responded = true
		}
		if match.confidence > best.confidence {
			best = match
			if best.confidence >= 0.97 {
				return best, responded
			}
		}
	}
	return best, responded
}

type compatProbeFn func(*WebServiceCollector, string) compatMatch

func compatibilityProbeOrder(port int) []compatProbeFn {
	switch port {
	case 8123:
		return []compatProbeFn{probeHomeAssistantAPI, probePortainerAPI, probeTrueNASAPI, probePBSAPI, probeProxmoxAPI, probeDockerEngineAPI}
	case 9443, 9000:
		return []compatProbeFn{probePortainerAPI, probeHomeAssistantAPI, probeTrueNASAPI, probePBSAPI, probeProxmoxAPI, probeDockerEngineAPI}
	case 8006:
		return []compatProbeFn{probeProxmoxAPI, probePBSAPI, probePortainerAPI, probeTrueNASAPI, probeHomeAssistantAPI, probeDockerEngineAPI}
	case 8007:
		return []compatProbeFn{probePBSAPI, probeProxmoxAPI, probePortainerAPI, probeTrueNASAPI, probeHomeAssistantAPI, probeDockerEngineAPI}
	case 2375, 2376:
		return []compatProbeFn{probeDockerEngineAPI, probePortainerAPI, probeHomeAssistantAPI, probeTrueNASAPI, probePBSAPI, probeProxmoxAPI}
	default:
		return []compatProbeFn{probePortainerAPI, probeHomeAssistantAPI, probeTrueNASAPI, probePBSAPI, probeProxmoxAPI, probeDockerEngineAPI}
	}
}

func applyCompatMatchToService(svc *protocol.DiscoveredWebService, match compatMatch) {
	if svc == nil || match.confidence < compatMinConfidence || strings.TrimSpace(match.connector) == "" {
		return
	}
	if svc.Metadata == nil {
		svc.Metadata = make(map[string]string)
	}

	svc.Metadata[compatMetadataConnector] = strings.TrimSpace(match.connector)
	svc.Metadata[compatMetadataConfidence] = strconv.FormatFloat(match.confidence, 'f', 2, 64)
	if strings.TrimSpace(match.authHint) != "" {
		svc.Metadata[compatMetadataAuthHint] = strings.TrimSpace(match.authHint)
	}
	if strings.TrimSpace(match.profile) != "" {
		svc.Metadata[compatMetadataProfile] = strings.TrimSpace(match.profile)
	}
	if strings.TrimSpace(match.evidence) != "" {
		svc.Metadata[compatMetadataEvidence] = strings.TrimSpace(match.evidence)
	}

	if strings.TrimSpace(svc.ServiceKey) == "" && strings.TrimSpace(match.serviceKey) != "" {
		svc.ServiceKey = strings.TrimSpace(match.serviceKey)
	}
	if strings.TrimSpace(match.displayName) != "" {
		if strings.TrimSpace(svc.Name) == "" || isGenericPortServiceName(svc.Name) {
			svc.Name = strings.TrimSpace(match.displayName)
		}
	}
	if strings.TrimSpace(match.category) != "" {
		if strings.TrimSpace(svc.Category) == "" || strings.EqualFold(strings.TrimSpace(svc.Category), CatOther) {
			svc.Category = strings.TrimSpace(match.category)
		}
	}
	if strings.TrimSpace(match.iconKey) != "" && strings.TrimSpace(svc.IconKey) == "" {
		svc.IconKey = strings.TrimSpace(match.iconKey)
	}
	if strings.TrimSpace(match.healthPath) != "" && strings.TrimSpace(svc.Metadata["health_path"]) == "" {
		svc.Metadata["health_path"] = strings.TrimSpace(match.healthPath)
	}
}

func isGenericPortServiceName(name string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(name))
	if !strings.HasPrefix(trimmed, "port ") {
		return false
	}
	return parsePortValue(strings.TrimPrefix(trimmed, "port ")) > 0
}
