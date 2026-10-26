package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"path"
	"runtime"
	"strings"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const (
	composeHTTPSUnsupported = "HTTPS Compose requires Docker Compose v2 with verified collector TLS trust."
	// composeActionVersion is the Compose action wire version this agent handles.
	composeActionVersion = 2
)

func composeDaemonHost(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if normalized, matched, err := NormalizeDockerNpipeEndpoint(endpoint); matched {
		if err != nil {
			return "", err
		}
		if runtime.GOOS != "windows" {
			return "", fmt.Errorf("Docker named pipes require Windows")
		}
		return normalized, nil
	}
	if value, matched := TrimDockerUnixScheme(endpoint); matched {
		endpoint = value
	}
	if strings.HasPrefix(endpoint, "/") && !strings.HasPrefix(endpoint, "//") && !strings.HasPrefix(endpoint, "/\\") && !strings.ContainsRune(endpoint, 0) {
		return "unix://" + endpoint, nil
	}
	parsed, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("Docker endpoint cannot be represented by Compose")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported Docker Compose endpoint")
	}
	if _, err := securityruntime.ValidateOutboundURL(parsed.String()); err != nil {
		return "", err
	}
	port := parsed.Port()
	if port == "" {
		port = "80"
		if parsed.Scheme == "https" {
			port = "443"
		}
	}
	host := "tcp://" + net.JoinHostPort(parsed.Hostname(), port) + parsed.Path
	round, err := url.Parse(host)
	// Docker's CLI parser decodes its path, and the Engine client parses it again.
	// Refuse a selection whose bytes change on that round trip or path.Join.
	if err != nil || round.Path != parsed.Path || round.EscapedPath() != parsed.EscapedPath() || round.RawQuery != "" || round.Fragment != "" || (parsed.Path != "" && path.Clean(parsed.Path) != parsed.Path) {
		return "", fmt.Errorf("Docker endpoint path cannot round-trip through Compose")
	}
	return host, nil
}

// Explicit empty overrides prevent a project .env from reintroducing ambient
// connection settings. The caller supplies the existing strict child-env allowlist.
func composeEnvironment(base []string, host, project string) []string {
	overrides := map[string]string{
		"DOCKER_HOST": host, "DOCKER_CONTEXT": "", "DOCKER_TLS": "", "DOCKER_TLS_VERIFY": "", "DOCKER_CERT_PATH": "", "DOCKER_API_VERSION": "",
		"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "*", "COMPOSE_PROJECT_NAME": project,
	}
	result := make([]string, 0, len(base)+len(overrides)+4)
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[strings.ToUpper(key)]; !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	for _, key := range []string{"http_proxy", "https_proxy", "all_proxy"} {
		result = append(result, key+"=")
	}
	return append(result, "no_proxy=*")
}

func composeCommandArgs(version int, host string, selection composeSelection, action string, extraArgs ...string) (string, []string) {
	name := "docker-compose"
	args := []string{"--host", host}
	if version == 2 {
		name = "docker"
		args = append(args, "compose")
	}
	args = append(args, "--project-directory", selection.Dir, "-p", selection.Name)
	for _, file := range selection.Files {
		args = append(args, "-f", file)
	}
	args = append(args, action)
	return name, append(args, extraArgs...)
}

// composeWireContract advertises Compose action v2 (ordered config-file
// selection pinned to an endpoint ID) only when this collector's endpoint can
// be handed to the Compose CLI. Otherwise the Hub sees no v2 support.
func (dc *DockerCollector) composeWireContract() (int, string) {
	if _, err := composeDaemonHost(dc.socketPath); err != nil {
		return 0, ""
	}
	return composeActionVersion, dc.composeEndpointID()
}

func (dc *DockerCollector) composeEndpointID() string {
	hash := sha256.Sum256([]byte("labtether-compose-endpoint-v2\x00" + dc.socketPath))
	return hex.EncodeToString(hash[:])
}
