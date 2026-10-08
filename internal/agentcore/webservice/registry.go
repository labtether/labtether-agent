package webservice

// KnownService defines metadata for a recognized web service.
type KnownService struct {
	Key          string   // unique lowercase identifier (e.g. "plex", "grafana")
	Name         string   // human-readable display name
	Category     string   // one of the Cat* constants
	IconKey      string   // icon identifier (matches Key for dashboard rendering)
	DefaultPort  int      // most common default port
	DockerImages []string // known Docker image names (without tags)
	HealthPath   string   // HTTP health check path (e.g. "/api/health")
	Description  string   // short description of the service
}

// Service category constants.
const (
	CatMedia          = "Media"
	CatDownloads      = "Downloads"
	CatGaming         = "Gaming"
	CatNetworking     = "Networking"
	CatMonitoring     = "Monitoring"
	CatDevelopment    = "Development"
	CatHomeAutomation = "Home Automation"
	CatStorage        = "Storage"
	CatDatabases      = "Databases"
	CatSecurity       = "Security"
	CatProductivity   = "Productivity"
	CatManagement     = "Management"
	CatOther          = "Other"
)

// registry is the static lookup table of known services, keyed by service key.
var registry = buildServiceRegistry(
	mediaServices,
	downloadsServices,
	gamingServices,
	networkingServices,
	monitoringServices,
	managementServices,
	homeautomationServices,
	storageServices,
	securityServices,
	databasesServices,
	developmentServices,
	productivityServices,
)

func buildServiceRegistry(categories ...map[string]KnownService) map[string]KnownService {
	services := make(map[string]KnownService)
	for _, category := range categories {
		for key, service := range category {
			if _, exists := services[key]; exists {
				panic("duplicate known service: " + key)
			}
			services[key] = service
		}
	}
	return services
}

// imageIndex maps normalized Docker image names to service keys.
var imageIndex map[string]string

// portIndex maps default ports to service keys.
var portIndex map[int]string

// uniquePortIndex maps ports to service keys only when exactly one service uses that default port.
var uniquePortIndex map[int]string

// hintIndex maps normalized service hints (names/domains/container labels) to service keys.
var hintIndex map[string]string

func init() {
	buildRegistryIndexes()
	registerBaselineHintAliases()
}
