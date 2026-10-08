package sysconfig

import (
	"fmt"
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	"github.com/labtether/labtether-agent/internal/securityruntime"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func NormalizeAgentSettingValue(key, raw string) (string, error) {
	definition, ok := AgentSettingDefinitionByKey(key)
	if !ok {
		return "", fmt.Errorf("unknown agent setting key: %s", key)
	}
	value := strings.TrimSpace(raw)
	switch definition.Type {
	case AgentSettingTypeString:
		if definition.Key == SettingKeyDockerEndpoint {
			return normalizeDockerEndpointValue(value)
		}
		if definition.Key == SettingKeyWebRTCTURNURL ||
			definition.Key == SettingKeyWebRTCTURNUser ||
			definition.Key == SettingKeyWebRTCTURNPass ||
			definition.Key == SettingKeyWebRTCWaylandPipeWireNodeID ||
			definition.Key == SettingKeyTLSCAFile {
			return value, nil
		}
		if definition.Key == SettingKeyServicesDiscoveryPortScanPorts ||
			definition.Key == SettingKeyServicesDiscoveryLANScanPorts {
			return NormalizeDiscoveryPortListValue(definition.Key, value)
		}
		if definition.Key == SettingKeyServicesDiscoveryLANScanCIDRs {
			return NormalizeDiscoveryCIDRListValue(definition.Key, value)
		}
		if value == "" {
			return "", fmt.Errorf("%s cannot be empty", definition.Key)
		}
		return value, nil
	case AgentSettingTypeInt:
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("%s must be a number", definition.Key)
		}
		if definition.MinInt > 0 && parsed < definition.MinInt {
			return "", fmt.Errorf("%s must be >= %d", definition.Key, definition.MinInt)
		}
		if definition.MaxInt > 0 && parsed > definition.MaxInt {
			return "", fmt.Errorf("%s must be <= %d", definition.Key, definition.MaxInt)
		}
		return strconv.Itoa(parsed), nil
	case AgentSettingTypeBool:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return "", fmt.Errorf("%s must be true or false", definition.Key)
		}
		return strconv.FormatBool(parsed), nil
	case AgentSettingTypeEnum:
		for _, allowed := range definition.AllowedValues {
			if strings.EqualFold(value, allowed) {
				return allowed, nil
			}
		}
		return "", fmt.Errorf("%s must be one of: %s", definition.Key, strings.Join(definition.AllowedValues, ", "))
	default:
		return "", fmt.Errorf("unsupported agent setting type for %s", definition.Key)
	}
}

func NormalizeDiscoveryPortListValue(key, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}

	fields := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\n', '\t':
			return true
		default:
			return false
		}
	})

	if len(fields) == 0 {
		return "", nil
	}

	seen := make(map[int]struct{}, len(fields))
	ports := make([]int, 0, len(fields))
	for _, field := range fields {
		token := strings.TrimSpace(field)
		if token == "" {
			continue
		}
		port, err := strconv.Atoi(token)
		if err != nil || port <= 0 || port > 65535 {
			return "", fmt.Errorf("%s must contain only TCP ports between 1 and 65535", key)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	sort.Ints(ports)
	items := make([]string, 0, len(ports))
	for _, port := range ports {
		items = append(items, strconv.Itoa(port))
	}
	return strings.Join(items, ","), nil
}

func NormalizeDiscoveryCIDRListValue(key, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}

	fields := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\n', '\t':
			return true
		default:
			return false
		}
	})
	if len(fields) == 0 {
		return "", nil
	}

	seen := make(map[string]struct{}, len(fields))
	cidrs := make([]string, 0, len(fields))
	for _, field := range fields {
		token := strings.TrimSpace(field)
		if token == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(token)
		if err != nil || !prefix.IsValid() {
			return "", fmt.Errorf("%s must contain valid CIDR values", key)
		}

		addr := prefix.Addr()
		if !addr.Is4() && !addr.Is6() {
			return "", fmt.Errorf("%s only supports IPv4 or IPv6 CIDR values", key)
		}
		if !isPrivateOrLocalCIDR(prefix) {
			return "", fmt.Errorf("%s only allows private/local CIDR ranges", key)
		}

		normalized := prefix.Masked().String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		cidrs = append(cidrs, normalized)
	}

	sort.Strings(cidrs)
	return strings.Join(cidrs, ","), nil
}

func isPrivateOrLocalCIDR(prefix netip.Prefix) bool {
	addr := prefix.Addr()
	if !addr.IsValid() {
		return false
	}
	if addr.IsLoopback() || addr.IsPrivate() {
		return true
	}
	if addr.Is4() {
		ip := net.ParseIP(addr.String())
		return ip != nil && ip.IsLinkLocalUnicast()
	}
	return addr.Is6() && addr.IsLinkLocalUnicast()
}

func normalizeDockerEndpointValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("%s cannot be empty", SettingKeyDockerEndpoint)
	}
	if normalized, matched, err := dockerpkg.NormalizeDockerNpipeEndpoint(value); matched {
		if err != nil {
			return "", fmt.Errorf("%s: %w", SettingKeyDockerEndpoint, err)
		}
		return normalized, nil
	}

	if strings.HasPrefix(value, "/") {
		if len(value) > 1 && (value[1] == '/' || value[1] == '\\') {
			return "", fmt.Errorf("%s absolute path must not begin with a network-path prefix", SettingKeyDockerEndpoint)
		}
		return value, nil
	}
	if path, ok := dockerpkg.TrimDockerUnixScheme(value); ok {
		if path == "" || !strings.HasPrefix(path, "/") {
			return "", fmt.Errorf("%s unix path must be absolute", SettingKeyDockerEndpoint)
		}
		return "unix://" + path, nil
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%s must be an absolute unix path, unix:// path, canonical npipe path, or http(s) URL", SettingKeyDockerEndpoint)
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("%s URL scheme must be http or https", SettingKeyDockerEndpoint)
	}

	validated, err := securityruntime.ValidateOutboundURL(value)
	if err != nil {
		return "", fmt.Errorf("%s is not allowed by outbound policy: %w", SettingKeyDockerEndpoint, err)
	}
	validated.RawQuery = ""
	validated.Fragment = ""
	return strings.TrimRight(validated.String(), "/"), nil
}
