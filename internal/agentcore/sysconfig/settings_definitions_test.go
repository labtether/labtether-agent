package sysconfig

import (
	"strings"
	"testing"
)

func TestEveryAgentSettingDefaultNormalizes(t *testing.T) {
	for _, definition := range AgentSettingDefinitions() {
		definition := definition
		t.Run(definition.Key, func(t *testing.T) {
			normalized, err := NormalizeAgentSettingValue(definition.Key, definition.DefaultValue)
			if err != nil {
				t.Fatalf("default %q is invalid: %v", definition.DefaultValue, err)
			}
			if normalized != definition.DefaultValue {
				t.Fatalf("default %q normalizes to %q; defaults must be canonical", definition.DefaultValue, normalized)
			}
		})
	}
}

func TestServiceDiscoveryAgentSettingDefinitionsPresent(t *testing.T) {
	tests := []struct {
		key      string
		wantType AgentSettingType
	}{
		{SettingKeyServicesDiscoveryDockerEnabled, AgentSettingTypeBool},
		{SettingKeyServicesDiscoveryProxyEnabled, AgentSettingTypeBool},
		{SettingKeyServicesDiscoveryProxyTraefikEnabled, AgentSettingTypeBool},
		{SettingKeyServicesDiscoveryProxyCaddyEnabled, AgentSettingTypeBool},
		{SettingKeyServicesDiscoveryProxyNPMEnabled, AgentSettingTypeBool},
		{SettingKeyServicesDiscoveryPortScanEnabled, AgentSettingTypeBool},
		{SettingKeyServicesDiscoveryPortScanIncludeListening, AgentSettingTypeBool},
		{SettingKeyServicesDiscoveryPortScanPorts, AgentSettingTypeString},
		{SettingKeyServicesDiscoveryLANScanEnabled, AgentSettingTypeBool},
		{SettingKeyServicesDiscoveryLANScanCIDRs, AgentSettingTypeString},
		{SettingKeyServicesDiscoveryLANScanPorts, AgentSettingTypeString},
		{SettingKeyServicesDiscoveryLANScanMaxHosts, AgentSettingTypeInt},
	}

	for _, tt := range tests {
		definition, ok := AgentSettingDefinitionByKey(tt.key)
		if !ok {
			t.Fatalf("expected definition for %s", tt.key)
		}
		if definition.Type != tt.wantType {
			t.Fatalf("definition %s type = %s; want %s", tt.key, definition.Type, tt.wantType)
		}
	}
}

func TestNormalizeAgentSettingValueServiceDiscoveryPortList(t *testing.T) {
	normalized, err := NormalizeAgentSettingValue(SettingKeyServicesDiscoveryPortScanPorts, "8080, 443,8080")
	if err != nil {
		t.Fatalf("NormalizeAgentSettingValue returned error: %v", err)
	}
	if normalized != "443,8080" {
		t.Fatalf("NormalizeAgentSettingValue returned %q; want 443,8080", normalized)
	}

	if _, err := NormalizeAgentSettingValue(SettingKeyServicesDiscoveryPortScanPorts, "443,nope"); err == nil {
		t.Fatalf("expected invalid port list to fail validation")
	}
}

func TestNormalizeAgentSettingValueServiceDiscoveryCIDRs(t *testing.T) {
	normalized, err := NormalizeAgentSettingValue(SettingKeyServicesDiscoveryLANScanCIDRs, "192.168.1.0/24,10.0.0.0/24")
	if err != nil {
		t.Fatalf("NormalizeAgentSettingValue returned error: %v", err)
	}
	if normalized != "10.0.0.0/24,192.168.1.0/24" {
		t.Fatalf("NormalizeAgentSettingValue returned %q; want sorted private CIDRs", normalized)
	}

	if _, err := NormalizeAgentSettingValue(SettingKeyServicesDiscoveryLANScanCIDRs, "8.8.8.0/24"); err == nil {
		t.Fatalf("expected public CIDR to fail validation")
	}
}

func TestNormalizeAgentSettingValueDockerEndpointUnixSchemeCaseInsensitive(t *testing.T) {
	normalized, err := NormalizeAgentSettingValue(SettingKeyDockerEndpoint, "UNIX:///var/run/docker.sock")
	if err != nil {
		t.Fatalf("NormalizeAgentSettingValue returned error: %v", err)
	}
	if normalized != "unix:///var/run/docker.sock" {
		t.Fatalf("NormalizeAgentSettingValue returned %q; want unix:///var/run/docker.sock", normalized)
	}
}

func TestNormalizeAgentSettingValueDockerEndpointCanonicalNpipe(t *testing.T) {
	const endpoint = "npipe:////./pipe/docker_engine"
	normalized, err := NormalizeAgentSettingValue(SettingKeyDockerEndpoint, endpoint)
	if err != nil {
		t.Fatalf("NormalizeAgentSettingValue returned error: %v", err)
	}
	if normalized != endpoint {
		t.Fatalf("NormalizeAgentSettingValue returned %q; want %q", normalized, endpoint)
	}
}

func TestNormalizeAgentSettingValueDockerEndpointRejectsUnsafeNpipe(t *testing.T) {
	tests := map[string]string{
		"empty pipe":          "npipe:////./pipe/",
		"relative form":       "npipe://./pipe/docker_engine",
		"remote host":         "npipe:////server/pipe/docker_engine",
		"UNC backslashes":     `npipe:\\\\server\\pipe\\docker_engine`,
		"uppercase scheme":    "NPIPE:////./pipe/docker_engine",
		"traversal":           "npipe:////./pipe/docker..engine",
		"dot only":            "npipe:////./pipe/.",
		"leading punctuation": "npipe:////./pipe/_docker_engine",
		"trailing dot":        "npipe:////./pipe/docker_engine.",
		"slash":               "npipe:////./pipe/docker/engine",
		"backslash":           `npipe:////./pipe/docker\\engine`,
		"percent confusable":  "npipe:////./pipe/%64ocker_engine",
		"unicode confusable":  "npipe:////./pipe/dockеr_engine",
		"control":             "npipe:////./pipe/docker\nengine",
		"query":               "npipe:////./pipe/docker_engine?x=1",
		"fragment":            "npipe:////./pipe/docker_engine#x",
		"credential":          "npipe:////./pipe/user@docker_engine",
		"oversize":            "npipe:////./pipe/" + strings.Repeat("a", 129),
		"unsupported scheme":  "tcp://127.0.0.1:2375",
	}
	for name, endpoint := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizeAgentSettingValue(SettingKeyDockerEndpoint, endpoint); err == nil {
				t.Fatalf("unsafe endpoint %q was accepted", endpoint)
			}
		})
	}
}
