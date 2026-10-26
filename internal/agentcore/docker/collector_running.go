package docker

import (
	"slices"
	"sort"
	"strings"
)

// dockerRunningContainers is immutable after publication under inventoryMu.
// Discovery owns rebuilding the index, so each stats poll can reuse it safely.
type dockerRunningContainers struct {
	ids  []string
	set  map[string]struct{}
	hash string
}

func (dc *DockerCollector) setRunningContainersLocked(runningIDs map[string]struct{}) {
	if len(runningIDs) == len(dc.runningContainers.set) {
		unchanged := true
		for id := range runningIDs {
			if _, ok := dc.runningContainers.set[id]; !ok {
				unchanged = false
				break
			}
		}
		if unchanged {
			return
		}
	}
	ids := make([]string, 0, len(runningIDs))
	for id := range runningIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	dc.runningContainers = dockerRunningContainers{
		ids: ids, set: cloneStringSet(runningIDs), hash: strings.Join(ids, ","),
	}
}

func (dc *DockerCollector) replaceInventory(snapshot dockerInventorySnapshot, runningIDs map[string]struct{}) {
	dc.inventoryMu.Lock()
	dc.inventory = snapshot
	dc.setRunningContainersLocked(runningIDs)
	dc.inventoryMu.Unlock()
}

func (dc *DockerCollector) updateRunningContainerIDs(runningIDs map[string]struct{}) {
	dc.inventoryMu.Lock()
	dc.setRunningContainersLocked(runningIDs)
	dc.inventoryMu.Unlock()
}

func (dc *DockerCollector) runningContainerSnapshot() dockerRunningContainers {
	dc.inventoryMu.RLock()
	snapshot := dc.runningContainers
	dc.inventoryMu.RUnlock()
	return snapshot
}

func (dc *DockerCollector) currentRunningContainerIDs() []string {
	// Public/test callers retain an owned copy; internal stats only read the index.
	return slices.Clone(dc.runningContainerSnapshot().ids)
}
