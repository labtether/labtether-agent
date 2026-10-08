package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/labtether/protocol"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultDockerDiscoveryInterval        = 30 * time.Second
	defaultDockerFullReconcileMinInterval = 5 * time.Minute
	defaultDockerFullReconcileMaxInterval = 30 * time.Minute
	dockerDiscoveryDebounce               = 1200 * time.Millisecond
	dockerDiscoveryImmediateDebounce      = 350 * time.Millisecond

	maxContainersPerHost = 500

	dockerStatsPollMinInterval = 5 * time.Second
	dockerStatsPollMaxInterval = 20 * time.Second
	dockerStatsMaxSamplesTick  = 24
	dockerStatsHotCPUThreshold = 25.0
	dockerStatsHotMemThreshold = 70.0
	dockerStatsHotPIDThreshold = 150
)

type dockerDiscoveryTrigger struct {
	full      bool
	immediate bool
}

type dockerInventorySnapshot struct {
	Engine        protocol.DockerEngineInfo
	Containers    map[string]protocol.DockerContainerInfo
	Images        map[string]protocol.DockerImageInfo
	Networks      map[string]protocol.DockerNetworkInfo
	Volumes       map[string]protocol.DockerVolumeInfo
	ComposeStacks []protocol.DockerComposeStack
}

// DockerCollector manages Docker discovery and stats collection on the agent side.
type DockerCollector struct {
	client            *dockerClient
	transport         Transport
	socketPath        string
	assetID           string // agent's own asset ID, used as host_id
	assetIDProviderMu sync.RWMutex
	assetIDProvider   func() string
	interval          time.Duration

	fullReconcileInterval time.Duration
	discoveryTriggerCh    chan dockerDiscoveryTrigger
	statsTriggerCh        chan struct{}

	inventoryMu          sync.RWMutex
	inventory            dockerInventorySnapshot
	runningContainerIDs  map[string]struct{}
	hasPublishedFull     bool
	lastPublishedAssetID string

	statsMu            sync.Mutex
	statsSchedule      map[string]*dockerStatsSchedule
	lastRunningSetHash string
	lastStatsPublish   time.Time
}

// SetAssetIDProvider installs the authoritative runtime asset-ID reader. The
// provider is invoked immediately before outbound payloads are marshaled so a
// credential rotation cannot leave Docker messages pinned to startup identity.
func (dc *DockerCollector) SetAssetIDProvider(provider func() string) {
	if dc == nil {
		return
	}
	dc.assetIDProviderMu.Lock()
	dc.assetIDProvider = provider
	dc.assetIDProviderMu.Unlock()
}

func (dc *DockerCollector) currentAssetID() string {
	if dc == nil {
		return ""
	}
	dc.assetIDProviderMu.RLock()
	provider := dc.assetIDProvider
	dc.assetIDProviderMu.RUnlock()
	if provider != nil {
		if assetID := strings.TrimSpace(provider()); assetID != "" {
			return assetID
		}
	}
	return strings.TrimSpace(dc.assetID)
}

// NewDockerCollector creates a collector. socketPath is the Docker socket path.
// transport is used to send messages to the hub.
func NewDockerCollector(socketPath string, transport Transport, assetID string, interval time.Duration) *DockerCollector {
	if interval <= 0 {
		interval = defaultDockerDiscoveryInterval
	}
	return &DockerCollector{
		client:                NewDockerClient(socketPath),
		transport:             transport,
		socketPath:            socketPath,
		assetID:               assetID,
		interval:              interval,
		fullReconcileInterval: deriveDockerFullReconcileInterval(interval),
		discoveryTriggerCh:    make(chan dockerDiscoveryTrigger, 32),
		statsTriggerCh:        make(chan struct{}, 4),
		inventory: dockerInventorySnapshot{
			Containers: make(map[string]protocol.DockerContainerInfo),
			Images:     make(map[string]protocol.DockerImageInfo),
			Networks:   make(map[string]protocol.DockerNetworkInfo),
			Volumes:    make(map[string]protocol.DockerVolumeInfo),
		},
		runningContainerIDs: make(map[string]struct{}),
		statsSchedule:       make(map[string]*dockerStatsSchedule),
	}
}

func deriveDockerFullReconcileInterval(base time.Duration) time.Duration {
	interval := base * 10
	if interval < defaultDockerFullReconcileMinInterval {
		interval = defaultDockerFullReconcileMinInterval
	}
	if interval > defaultDockerFullReconcileMaxInterval {
		interval = defaultDockerFullReconcileMaxInterval
	}
	return interval
}

// IsAvailable checks if the Docker socket exists and is accessible.
func (dc *DockerCollector) IsAvailable() bool {
	endpoint := strings.TrimSpace(dc.socketPath)
	if endpoint == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(endpoint), "unix://") {
		endpoint = strings.TrimPrefix(endpoint, "unix://")
	}
	if strings.HasPrefix(endpoint, "/") {
		if _, err := os.Stat(endpoint); err != nil {
			return false
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return dc.client.ping(ctx) == nil
}

// ResetPublishedState clears the published-full flag so the next discovery
// cycle forces a full republish. Call this after a WebSocket reconnect so the
// hub receives fresh Docker inventory immediately.
func (dc *DockerCollector) ResetPublishedState() {
	dc.inventoryMu.Lock()
	dc.hasPublishedFull = false
	dc.lastPublishedAssetID = ""
	dc.inventoryMu.Unlock()
}

func (dc *DockerCollector) transportConnected() bool {
	return dc.transport != nil && dc.transport.Connected()
}

func (dc *DockerCollector) queueDiscoveryTrigger(full, immediate bool) {
	if dc == nil || dc.discoveryTriggerCh == nil {
		return
	}
	trigger := dockerDiscoveryTrigger{full: full, immediate: immediate}
	select {
	case dc.discoveryTriggerCh <- trigger:
	default:
		if full {
			// Preserve full refresh requests under bursty event load.
			select {
			case <-dc.discoveryTriggerCh:
			default:
			}
			select {
			case dc.discoveryTriggerCh <- trigger:
			default:
			}
		}
	}
}

// Run starts periodic discovery, event streaming, and stats collection.
// Blocks until ctx is cancelled.
func (dc *DockerCollector) Run(ctx context.Context) {
	go dc.runEventLoop(ctx)
	go dc.runStats(ctx)
	dc.runDiscoveryManager(ctx)
}

func (dc *DockerCollector) runDiscoveryManager(ctx context.Context) {
	cheapTicker := time.NewTicker(dc.interval)
	defer cheapTicker.Stop()

	fullTicker := time.NewTicker(dc.fullReconcileInterval)
	defer fullTicker.Stop()

	var (
		debounceTimer    *time.Timer
		debounceC        <-chan time.Time
		pendingContainer bool
		pendingFull      bool
		forceFullPublish bool
	)

	armDebounce := func(delay time.Duration) {
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(delay)
			debounceC = debounceTimer.C
			return
		}
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
		debounceTimer.Reset(delay)
		debounceC = debounceTimer.C
	}

	pendingFull = true
	forceFullPublish = true
	armDebounce(0)

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				if !debounceTimer.Stop() {
					select {
					case <-debounceTimer.C:
					default:
					}
				}
			}
			return
		case <-cheapTicker.C:
			pendingContainer = true
			armDebounce(dockerDiscoveryDebounce)
		case <-fullTicker.C:
			pendingFull = true
			forceFullPublish = true // periodic snapshot keeps hub state fully reconciled
			armDebounce(dockerDiscoveryDebounce)
		case trigger := <-dc.discoveryTriggerCh:
			if trigger.full {
				pendingFull = true
			} else {
				pendingContainer = true
			}
			if trigger.immediate {
				armDebounce(dockerDiscoveryImmediateDebounce)
			} else {
				armDebounce(dockerDiscoveryDebounce)
			}
		case <-debounceC:
			debounceC = nil
			if pendingFull {
				pendingFull = false
				pendingContainer = false
				if _, err := dc.refreshAndPublishFull(ctx, forceFullPublish); err != nil {
					log.Printf("docker: full discovery refresh failed: %v", err)
				}
				forceFullPublish = false
				continue
			}
			if pendingContainer {
				pendingContainer = false
				if _, err := dc.refreshAndPublishContainerDelta(ctx); err != nil {
					log.Printf("docker: container delta refresh failed: %v", err)
				}
			}
		}
	}
}

func (dc *DockerCollector) refreshAndPublishFull(ctx context.Context, forcePublish bool) (bool, error) {
	if !dc.transportConnected() {
		return false, nil
	}

	discovery, snapshot, runningIDs, err := dc.collectFullDiscovery(ctx)
	if err != nil {
		return false, err
	}

	dc.inventoryMu.RLock()
	currentAssetID := dc.currentAssetID()
	identityChanged := dc.lastPublishedAssetID != "" && dc.lastPublishedAssetID != currentAssetID
	changed := identityChanged || !dockerInventorySnapshotsEqual(dc.inventory, snapshot)
	hasPublished := dc.hasPublishedFull
	dc.inventoryMu.RUnlock()

	if !changed && !forcePublish && hasPublished {
		dc.updateRunningContainerIDs(runningIDs)
		return false, nil
	}

	discovery.HostID = currentAssetID
	if err := dc.sendDockerMessage(protocol.MsgDockerDiscovery, discovery); err != nil {
		dc.updateRunningContainerIDs(runningIDs)
		return false, err
	}
	dc.replaceInventory(snapshot, runningIDs)
	dc.inventoryMu.Lock()
	dc.hasPublishedFull = true
	dc.lastPublishedAssetID = currentAssetID
	dc.inventoryMu.Unlock()
	return true, nil
}

func (dc *DockerCollector) refreshAndPublishContainerDelta(ctx context.Context) (bool, error) {
	if !dc.transportConnected() {
		return false, nil
	}

	dc.inventoryMu.RLock()
	hasPublished := dc.hasPublishedFull
	lastPublishedAssetID := dc.lastPublishedAssetID
	previousContainers := cloneDockerContainerInfoMap(dc.inventory.Containers)
	previousCompose := cloneComposeStacks(dc.inventory.ComposeStacks)
	dc.inventoryMu.RUnlock()

	if !hasPublished {
		return dc.refreshAndPublishFull(ctx, true)
	}
	if lastPublishedAssetID != "" && lastPublishedAssetID != dc.currentAssetID() {
		return dc.refreshAndPublishFull(ctx, true)
	}

	rawContainers, err := dc.client.listContainers(ctx)
	if err != nil {
		return false, fmt.Errorf("containers: %w", err)
	}
	if len(rawContainers) > maxContainersPerHost {
		rawContainers = rawContainers[:maxContainersPerHost]
	}
	nextContainers, runningIDs := buildContainerInfoMap(rawContainers)
	nextCompose := inferComposeStacks(rawContainers)

	upserts, removals := diffContainerInfoMap(previousContainers, nextContainers)
	composeChanged := !composeStacksEqual(previousCompose, nextCompose)
	changeCount := len(upserts) + len(removals)
	if changeCount == 0 && !composeChanged {
		dc.updateRunningContainerIDs(runningIDs)
		return false, nil
	}
	if shouldFallbackToFull(changeCount, len(previousContainers), composeChanged) {
		return dc.refreshAndPublishFull(ctx, false)
	}

	delta := protocol.DockerDiscoveryDeltaData{
		HostID:             dc.currentAssetID(),
		UpsertContainers:   upserts,
		RemoveContainerIDs: removals,
	}
	if composeChanged {
		delta.ReplaceComposeStacks = true
		delta.ComposeStacks = cloneComposeStacks(nextCompose)
	}

	if err := dc.sendDockerMessage(protocol.MsgDockerDiscoveryDelta, delta); err != nil {
		dc.updateRunningContainerIDs(runningIDs)
		return false, err
	}

	dc.inventoryMu.Lock()
	dc.inventory.Containers = nextContainers
	dc.inventory.ComposeStacks = cloneComposeStacks(nextCompose)
	dc.runningContainerIDs = cloneStringSet(runningIDs)
	dc.inventoryMu.Unlock()
	return true, nil
}

func shouldFallbackToFull(changeCount, previousCount int, composeChanged bool) bool {
	if changeCount >= 200 {
		return true
	}
	if previousCount == 0 {
		return false
	}
	// When most containers churn in one cycle, a full snapshot is cheaper to apply.
	if changeCount*2 > previousCount {
		return true
	}
	if composeChanged && changeCount > 100 {
		return true
	}
	return false
}

func (dc *DockerCollector) sendDockerMessage(messageType string, payload any) error {
	if dc.transport == nil {
		return fmt.Errorf("transport unavailable")
	}
	payload = dc.bindCurrentAssetID(messageType, payload)
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := dc.transport.Send(protocol.Message{Type: messageType, Data: raw}); err != nil {
		return err
	}
	return nil
}

func (dc *DockerCollector) bindCurrentAssetID(messageType string, payload any) any {
	assetID := dc.currentAssetID()
	switch value := payload.(type) {
	case protocol.DockerDiscoveryData:
		value.HostID = assetID
		return value
	case protocol.DockerDiscoveryDeltaData:
		value.HostID = assetID
		return value
	case protocol.DockerStatsData:
		value.HostID = assetID
		return value
	case protocol.DockerEventData:
		value.HostID = assetID
		return value
	case *protocol.DockerDiscoveryData:
		copyValue := *value
		copyValue.HostID = assetID
		return &copyValue
	case *protocol.DockerDiscoveryDeltaData:
		copyValue := *value
		copyValue.HostID = assetID
		return &copyValue
	case *protocol.DockerStatsData:
		copyValue := *value
		copyValue.HostID = assetID
		return &copyValue
	case *protocol.DockerEventData:
		copyValue := *value
		copyValue.HostID = assetID
		return &copyValue
	default:
		return payload
	}
}

func (dc *DockerCollector) replaceInventory(snapshot dockerInventorySnapshot, runningIDs map[string]struct{}) {
	dc.inventoryMu.Lock()
	dc.inventory = snapshot
	dc.runningContainerIDs = cloneStringSet(runningIDs)
	dc.inventoryMu.Unlock()
}

func (dc *DockerCollector) updateRunningContainerIDs(runningIDs map[string]struct{}) {
	dc.inventoryMu.Lock()
	dc.runningContainerIDs = cloneStringSet(runningIDs)
	dc.inventoryMu.Unlock()
}

func (dc *DockerCollector) currentRunningContainerIDs() []string {
	dc.inventoryMu.RLock()
	ids := make([]string, 0, len(dc.runningContainerIDs))
	for containerID := range dc.runningContainerIDs {
		ids = append(ids, containerID)
	}
	dc.inventoryMu.RUnlock()
	sort.Strings(ids)
	return ids
}

func (dc *DockerCollector) collectFullDiscovery(ctx context.Context) (protocol.DockerDiscoveryData, dockerInventorySnapshot, map[string]struct{}, error) {
	result := protocol.DockerDiscoveryData{HostID: dc.currentAssetID()}
	snapshot := dockerInventorySnapshot{
		Containers: make(map[string]protocol.DockerContainerInfo),
		Images:     make(map[string]protocol.DockerImageInfo),
		Networks:   make(map[string]protocol.DockerNetworkInfo),
		Volumes:    make(map[string]protocol.DockerVolumeInfo),
	}

	ver, err := dc.client.version(ctx)
	if err != nil {
		return result, snapshot, nil, fmt.Errorf("version: %w", err)
	}
	result.Engine = protocol.DockerEngineInfo{
		Version:    ver.Version,
		APIVersion: ver.APIVersion,
		OS:         ver.Os,
		Arch:       ver.Arch,
	}
	snapshot.Engine = result.Engine

	rawContainers, err := dc.client.listContainers(ctx)
	if err != nil {
		return result, snapshot, nil, fmt.Errorf("containers: %w", err)
	}
	if len(rawContainers) > maxContainersPerHost {
		rawContainers = rawContainers[:maxContainersPerHost]
	}
	var runningIDs map[string]struct{}
	snapshot.Containers, runningIDs = buildContainerInfoMap(rawContainers)
	result.Containers = containerInfoMapToSlice(snapshot.Containers)
	result.ComposeStacks = inferComposeStacks(rawContainers)
	snapshot.ComposeStacks = cloneComposeStacks(result.ComposeStacks)

	if images, err := dc.client.listImages(ctx); err == nil {
		snapshot.Images = buildImageInfoMap(images)
		result.Images = imageInfoMapToSlice(snapshot.Images)
	}
	if networks, err := dc.client.listNetworks(ctx); err == nil {
		snapshot.Networks = buildNetworkInfoMap(networks)
		result.Networks = networkInfoMapToSlice(snapshot.Networks)
	}
	if volumes, err := dc.client.listVolumes(ctx); err == nil {
		snapshot.Volumes = buildVolumeInfoMap(volumes)
		result.Volumes = volumeInfoMapToSlice(snapshot.Volumes)
	}

	return result, snapshot, runningIDs, nil
}
