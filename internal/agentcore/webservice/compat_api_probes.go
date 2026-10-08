package webservice

import (
	"encoding/json"
	"net/http"
	"strings"
)

func probePortainerAPI(wsc *WebServiceCollector, baseURL string) compatMatch {
	responded := false
	if payload, status, ok := wsc.fetchJSON(baseURL, "/api/status"); ok {
		responded = true
		if status == http.StatusOK && payload != nil {
			if value := mapStringValue(payload, "Version", "version"); strings.TrimSpace(value) != "" {
				known, _ := LookupByKey("portainer")
				return compatMatch{
					connector:   "portainer",
					profile:     "portainer.api.status",
					authHint:    "api_key,password",
					evidence:    "api/status version",
					confidence:  0.97,
					responded:   true,
					serviceKey:  known.Key,
					displayName: known.Name,
					category:    known.Category,
					iconKey:     known.IconKey,
					healthPath:  known.HealthPath,
				}
			}
		}
	}
	if marker, markerResponded := wsc.pageContainsMarkerWithResponse(baseURL, "/", "portainer"); marker {
		known, _ := LookupByKey("portainer")
		return compatMatch{
			connector:   "portainer",
			profile:     "portainer.ui.marker",
			authHint:    "api_key,password",
			evidence:    "page marker",
			confidence:  0.83,
			responded:   true,
			serviceKey:  known.Key,
			displayName: known.Name,
			category:    known.Category,
			iconKey:     known.IconKey,
			healthPath:  known.HealthPath,
		}
	} else if markerResponded {
		responded = true
	}
	return compatMatch{responded: responded}
}

func probeHomeAssistantAPI(wsc *WebServiceCollector, baseURL string) compatMatch {
	responded := false
	if payload, status, ok := wsc.fetchJSON(baseURL, "/api"); ok {
		responded = true
		if status == http.StatusOK && payload != nil {
			if strings.Contains(strings.ToLower(mapStringValue(payload, "message")), "api running") {
				known, _ := LookupByKey("homeassistant")
				return compatMatch{
					connector:   "homeassistant",
					profile:     "homeassistant.api.root",
					authHint:    "token",
					evidence:    "api running message",
					confidence:  0.97,
					responded:   true,
					serviceKey:  known.Key,
					displayName: known.Name,
					category:    known.Category,
					iconKey:     known.IconKey,
					healthPath:  known.HealthPath,
				}
			}
		}
	}
	if marker, markerResponded := wsc.pageContainsMarkerWithResponse(baseURL, "/", "home assistant"); marker {
		known, _ := LookupByKey("homeassistant")
		return compatMatch{
			connector:   "homeassistant",
			profile:     "homeassistant.ui.marker",
			authHint:    "token",
			evidence:    "page marker",
			confidence:  0.82,
			responded:   true,
			serviceKey:  known.Key,
			displayName: known.Name,
			category:    known.Category,
			iconKey:     known.IconKey,
			healthPath:  known.HealthPath,
		}
	} else if markerResponded {
		responded = true
	}
	return compatMatch{responded: responded}
}

func probeTrueNASAPI(wsc *WebServiceCollector, baseURL string) compatMatch {
	responded := false
	if body, status, ok := wsc.fetchBody(baseURL, "/api/v2.0/system/version"); ok {
		responded = true
		lower := strings.ToLower(string(body))
		if status == http.StatusOK && (strings.Contains(lower, "truenas") || strings.Contains(lower, "freenas")) {
			return compatMatch{
				connector:   "truenas",
				profile:     "truenas.api.system.version",
				authHint:    "api_key",
				evidence:    "api/v2.0/system/version",
				confidence:  0.97,
				responded:   true,
				displayName: "TrueNAS",
				category:    CatStorage,
			}
		}
	}
	if marker, markerResponded := wsc.pageContainsMarkerWithResponse(baseURL, "/", "truenas"); marker {
		return compatMatch{
			connector:   "truenas",
			profile:     "truenas.ui.marker",
			authHint:    "api_key",
			evidence:    "page marker",
			confidence:  0.82,
			responded:   true,
			displayName: "TrueNAS",
			category:    CatStorage,
		}
	} else if markerResponded {
		responded = true
	}
	return compatMatch{responded: responded}
}

func probePBSAPI(wsc *WebServiceCollector, baseURL string) compatMatch {
	responded := false
	if marker, markerResponded := wsc.pageContainsMarkerWithResponse(baseURL, "/", "proxmox backup server"); marker {
		return compatMatch{
			connector:   "pbs",
			profile:     "pbs.ui.marker",
			authHint:    "api_token",
			evidence:    "page marker",
			confidence:  0.96,
			responded:   true,
			displayName: "Proxmox Backup Server",
			category:    CatStorage,
		}
	} else if markerResponded {
		responded = true
	}
	if payload, status, ok := wsc.fetchJSON(baseURL, "/api2/json/version"); ok {
		responded = true
		if status == http.StatusOK && payload != nil && hasProxmoxVersionShape(payload) {
			if strings.Contains(strings.ToLower(marshalMapToString(payload)), "backup") {
				return compatMatch{
					connector:   "pbs",
					profile:     "pbs.api2.version",
					authHint:    "api_token",
					evidence:    "api2 version payload",
					confidence:  0.88,
					responded:   true,
					displayName: "Proxmox Backup Server",
					category:    CatStorage,
				}
			}
		}
	}
	return compatMatch{responded: responded}
}

func probeProxmoxAPI(wsc *WebServiceCollector, baseURL string) compatMatch {
	responded := false
	if marker, markerResponded := wsc.pageContainsMarkerWithResponse(baseURL, "/", "proxmox virtual environment"); marker {
		return compatMatch{
			connector:   "proxmox",
			profile:     "proxmox.ui.marker",
			authHint:    "api_token,password",
			evidence:    "page marker",
			confidence:  0.96,
			responded:   true,
			displayName: "Proxmox VE",
			category:    CatManagement,
		}
	} else if markerResponded {
		responded = true
	}
	if payload, status, ok := wsc.fetchJSON(baseURL, "/api2/json/version"); ok {
		responded = true
		if status == http.StatusOK && payload != nil && hasProxmoxVersionShape(payload) && !strings.Contains(strings.ToLower(marshalMapToString(payload)), "backup") {
			return compatMatch{
				connector:   "proxmox",
				profile:     "proxmox.api2.version",
				authHint:    "api_token,password",
				evidence:    "api2 version payload",
				confidence:  0.74,
				responded:   true,
				displayName: "Proxmox VE",
				category:    CatManagement,
			}
		}
	}
	return compatMatch{responded: responded}
}

func probeDockerEngineAPI(wsc *WebServiceCollector, baseURL string) compatMatch {
	responded := false
	if payload, status, ok := wsc.fetchJSON(baseURL, "/version"); ok {
		responded = true
		if status == http.StatusOK && payload != nil && strings.TrimSpace(mapStringValue(payload, "ApiVersion")) != "" && strings.TrimSpace(mapStringValue(payload, "Version")) != "" {
			return compatMatch{
				connector:   "docker",
				profile:     "docker.api.version",
				authHint:    "none_or_mtls",
				evidence:    "docker /version payload",
				confidence:  0.96,
				responded:   true,
				displayName: "Docker Engine API",
				category:    CatManagement,
			}
		}
	}

	port := portFromURL(baseURL)
	if port == 2375 || port == 2376 {
		if body, status, ok := wsc.fetchBody(baseURL, "/_ping"); ok && status == http.StatusOK {
			responded = true
			if strings.Contains(strings.ToLower(string(body)), "ok") {
				return compatMatch{
					connector:   "docker",
					profile:     "docker.api.ping",
					authHint:    "none_or_mtls",
					evidence:    "docker /_ping",
					confidence:  0.86,
					responded:   true,
					displayName: "Docker Engine API",
					category:    CatManagement,
				}
			}
		} else if ok {
			responded = true
		}
	}
	return compatMatch{responded: responded}
}

func hasProxmoxVersionShape(payload map[string]any) bool {
	dataRaw, ok := payload["data"]
	if !ok {
		return false
	}
	data, ok := dataRaw.(map[string]any)
	if !ok {
		return false
	}
	version := strings.TrimSpace(mapStringValue(data, "version"))
	release := strings.TrimSpace(mapStringValue(data, "release"))
	return version != "" || release != ""
}

func mapStringValue(values map[string]any, keys ...string) string {
	if len(values) == 0 {
		return ""
	}
	for _, key := range keys {
		for existing, raw := range values {
			if !strings.EqualFold(strings.TrimSpace(existing), strings.TrimSpace(key)) {
				continue
			}
			if asString, ok := raw.(string); ok {
				return strings.TrimSpace(asString)
			}
		}
	}
	return ""
}

func marshalMapToString(values map[string]any) string {
	if len(values) == 0 {
		return ""
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return string(encoded)
}
