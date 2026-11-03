package webservice

import (
	dockerpkg "github.com/labtether/labtether-agent/internal/agentcore/docker"
	proxypkg "github.com/labtether/labtether-agent/internal/agentcore/proxy"
	"github.com/labtether/labtether-agent/internal/agentplatform/netid"
	"github.com/labtether/protocol"
	"log"
	"net"
	"regexp"
	"strings"
)

// enrichFromProxies queries all registered proxy providers concurrently, then
// enriches the discovered services with proxy route information.
func (wsc *WebServiceCollector) enrichFromProxies(containers []dockerpkg.DockerContainer, services []protocol.DiscoveredWebService) ([]protocol.DiscoveredWebService, bool) {
	type providerResult struct {
		name   string
		routes []ProxyRoute
		err    error
	}

	ch := make(chan providerResult, len(wsc.proxyProviders))

	for _, provider := range wsc.proxyProviders {
		go func(p proxypkg.Provider) {
			apiURL, ok := p.DetectAndConnect(containers)
			if !ok {
				ch <- providerResult{name: p.Name()}
				return
			}
			log.Printf("webservices: proxy/%s detected at %s", p.Name(), apiURL)
			routes, err := p.FetchRoutes(apiURL)
			ch <- providerResult{name: p.Name(), routes: routes, err: err}
		}(provider)
	}

	hadProviderError := false
	for i := 0; i < len(wsc.proxyProviders); i++ {
		result := <-ch
		if result.err != nil {
			hadProviderError = true
			log.Printf("webservices: proxy/%s error: %v", result.name, result.err)
			continue
		}
		if len(result.routes) > 0 {
			log.Printf("webservices: proxy/%s discovered %d routes", result.name, len(result.routes))
			services = enrichServicesWithRoutes(services, result.routes, result.name, wsc.currentAssetID(), wsc.hostIP, containers)
		}
	}

	return services, hadProviderError
}

func cloneDiscoveredServices(in []protocol.DiscoveredWebService) []protocol.DiscoveredWebService {
	if len(in) == 0 {
		return nil
	}
	out := make([]protocol.DiscoveredWebService, 0, len(in))
	for _, svc := range in {
		cloned := svc
		if svc.Metadata != nil {
			cloned.Metadata = make(map[string]string, len(svc.Metadata))
			for key, value := range svc.Metadata {
				cloned.Metadata[key] = value
			}
		}
		out = append(out, cloned)
	}
	return out
}

func filterServicesBySource(in []protocol.DiscoveredWebService, source string) []protocol.DiscoveredWebService {
	if len(in) == 0 {
		return nil
	}
	out := make([]protocol.DiscoveredWebService, 0, len(in))
	for _, svc := range in {
		if svc.Source == source {
			out = append(out, svc)
		}
	}
	return out
}

func dedupeDiscoveredServices(in []protocol.DiscoveredWebService) []protocol.DiscoveredWebService {
	if len(in) == 0 {
		return in
	}
	out := make([]protocol.DiscoveredWebService, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, svc := range in {
		if svc.ID == "" {
			out = append(out, svc)
			continue
		}
		if _, ok := seen[svc.ID]; ok {
			continue
		}
		seen[svc.ID] = struct{}{}
		out = append(out, svc)
	}
	return out
}

// traefikHostRegex matches Traefik v2+ Host(`...`) rules.
var traefikHostRegex = regexp.MustCompile("Host\\(`([^`]+)`\\)")

// extractTraefikURL parses Traefik labels for a Host() routing rule and returns
// the corresponding URL. Returns empty string if no Traefik rule is found.
func extractTraefikURL(labels map[string]string) string {
	if labels == nil {
		return ""
	}

	// Look through all labels for Traefik router rules
	for key, val := range labels {
		if !strings.Contains(key, "traefik") {
			continue
		}
		if !strings.Contains(key, "rule") {
			continue
		}
		matches := traefikHostRegex.FindStringSubmatch(val)
		if len(matches) >= 2 {
			host := strings.TrimSpace(matches[1])
			if host != "" {
				return "https://" + host
			}
		}
	}
	return ""
}

// resolveHostIP attempts to determine the machine's outbound IP address
// without requiring Internet connectivity. Returns "localhost" on failure.
func ResolveHostIP() string {
	if ip := firstNonLoopbackHostIP(); ip != "" {
		return ip
	}
	return "localhost"
}

func firstNonLoopbackHostIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	candidates := make([]hostIPCandidate, 0, 8)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			if ip := ipFromAddr(addr); ip != nil {
				candidates = append(candidates, hostIPCandidate{iface: iface.Name, ip: ip})
			}
		}
	}
	return chooseHostIP(candidates, netid.DefaultRouteIP())
}

type hostIPCandidate struct {
	iface string
	ip    net.IP
}

var virtualInterfacePrefixes = []string{"docker", "br-", "veth", "virbr", "vnet", "tailscale", "tun", "tap", "wg", "zt", "utun", "lxc", "cni", "flannel", "cali", "kube"}

// hostIPRank orders addresses for the service URLs this host advertises:
// a LAN address first. Before, the first IPv4 address in interface order
// won, which on many hosts is a Tailscale (100.64.0.0/10) or Docker bridge
// address that other LAN machines cannot reach. -1 means never.
func hostIPRank(c hostIPCandidate) int {
	ip := c.ip
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return -1
	}
	name := strings.ToLower(c.iface)
	virtual := false
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			virtual = true
			break
		}
	}
	v4 := ip.To4()
	if v4 == nil {
		return 5
	}
	cgnat := v4[0] == 100 && v4[1]&0xC0 == 64
	switch {
	case cgnat:
		return 4
	case !virtual && v4.IsPrivate():
		return 0
	case !virtual:
		return 1
	case v4.IsPrivate():
		return 2
	}
	return 3
}

// chooseHostIP prefers the address the default route uses when it is a LAN
// address, then the best ranked one (interface order breaks ties).
func chooseHostIP(candidates []hostIPCandidate, routeIP net.IP) string {
	best, bestRank := "", 99
	for _, c := range candidates {
		rank := hostIPRank(c)
		if rank < 0 {
			continue
		}
		if routeIP != nil && c.ip.Equal(routeIP) && rank <= 1 {
			return c.ip.String()
		}
		if rank < bestRank {
			best, bestRank = c.ip.String(), rank
		}
	}
	return best
}

func ipFromAddr(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}
