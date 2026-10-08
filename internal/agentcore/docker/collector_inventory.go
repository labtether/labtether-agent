package docker

import (
	"fmt"
	"github.com/labtether/protocol"
	"sort"
	"strings"
	"time"
)

func buildContainerInfoMap(rawContainers []DockerContainer) (map[string]protocol.DockerContainerInfo, map[string]struct{}) {
	containers := make(map[string]protocol.DockerContainerInfo, len(rawContainers))
	running := make(map[string]struct{})
	for _, container := range rawContainers {
		info := protocol.DockerContainerInfo{
			ID:      container.ID,
			Name:    ContainerName(container.Names),
			Image:   container.Image,
			State:   container.State,
			Status:  container.Status,
			Created: time.Unix(container.Created, 0).UTC().Format(time.RFC3339),
			Labels:  cloneStringMap(container.Labels),
		}
		if container.State == "running" {
			running[container.ID] = struct{}{}
		}

		for _, port := range container.Ports {
			if port.PublicPort <= 0 {
				continue
			}
			info.Ports = append(info.Ports, protocol.DockerPortMapping{
				Host:      port.PublicPort,
				Container: port.PrivatePort,
				Protocol:  strings.ToLower(port.Type),
			})
		}
		sort.Slice(info.Ports, func(i, j int) bool {
			if info.Ports[i].Host == info.Ports[j].Host {
				if info.Ports[i].Container == info.Ports[j].Container {
					return info.Ports[i].Protocol < info.Ports[j].Protocol
				}
				return info.Ports[i].Container < info.Ports[j].Container
			}
			return info.Ports[i].Host < info.Ports[j].Host
		})

		for networkName := range container.NetworkSettings.Networks {
			info.Networks = append(info.Networks, networkName)
		}
		sort.Strings(info.Networks)

		for _, mount := range container.Mounts {
			info.Mounts = append(info.Mounts, protocol.DockerMountInfo{
				Type:        mount.Type,
				Source:      mount.Source,
				Destination: mount.Destination,
			})
		}
		sort.Slice(info.Mounts, func(i, j int) bool {
			if info.Mounts[i].Destination == info.Mounts[j].Destination {
				if info.Mounts[i].Source == info.Mounts[j].Source {
					return info.Mounts[i].Type < info.Mounts[j].Type
				}
				return info.Mounts[i].Source < info.Mounts[j].Source
			}
			return info.Mounts[i].Destination < info.Mounts[j].Destination
		})

		containers[container.ID] = info
	}
	return containers, running
}

func containerInfoMapToSlice(values map[string]protocol.DockerContainerInfo) []protocol.DockerContainerInfo {
	result := make([]protocol.DockerContainerInfo, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result
}

func buildImageInfoMap(values []DockerImage) map[string]protocol.DockerImageInfo {
	result := make(map[string]protocol.DockerImageInfo, len(values))
	for _, image := range values {
		tags := append([]string(nil), image.RepoTags...)
		sort.Strings(tags)
		result[image.ID] = protocol.DockerImageInfo{
			ID:      image.ID,
			Tags:    tags,
			Size:    image.Size,
			Created: time.Unix(image.Created, 0).UTC().Format(time.RFC3339),
		}
	}
	return result
}

func imageInfoMapToSlice(values map[string]protocol.DockerImageInfo) []protocol.DockerImageInfo {
	result := make([]protocol.DockerImageInfo, 0, len(values))
	for _, image := range values {
		result = append(result, image)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

func buildNetworkInfoMap(values []DockerNetwork) map[string]protocol.DockerNetworkInfo {
	result := make(map[string]protocol.DockerNetworkInfo, len(values))
	for _, network := range values {
		result[network.ID] = protocol.DockerNetworkInfo{
			ID:     network.ID,
			Name:   network.Name,
			Driver: network.Driver,
			Scope:  network.Scope,
		}
	}
	return result
}

func networkInfoMapToSlice(values map[string]protocol.DockerNetworkInfo) []protocol.DockerNetworkInfo {
	result := make([]protocol.DockerNetworkInfo, 0, len(values))
	for _, network := range values {
		result = append(result, network)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result
}

func buildVolumeInfoMap(values []DockerVolume) map[string]protocol.DockerVolumeInfo {
	result := make(map[string]protocol.DockerVolumeInfo, len(values))
	for _, volume := range values {
		result[volume.Name] = protocol.DockerVolumeInfo{
			Name:       volume.Name,
			Driver:     volume.Driver,
			Mountpoint: volume.Mountpoint,
		}
	}
	return result
}

func volumeInfoMapToSlice(values map[string]protocol.DockerVolumeInfo) []protocol.DockerVolumeInfo {
	result := make([]protocol.DockerVolumeInfo, 0, len(values))
	for _, volume := range values {
		result = append(result, volume)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

func dockerInventorySnapshotsEqual(a, b dockerInventorySnapshot) bool {
	if a.Engine != b.Engine {
		return false
	}
	if !DockerContainerInfoMapsEqual(a.Containers, b.Containers) {
		return false
	}
	if !DockerImageInfoMapsEqual(a.Images, b.Images) {
		return false
	}
	if !DockerNetworkInfoMapsEqual(a.Networks, b.Networks) {
		return false
	}
	if !DockerVolumeInfoMapsEqual(a.Volumes, b.Volumes) {
		return false
	}
	return composeStacksEqual(a.ComposeStacks, b.ComposeStacks)
}

func DockerContainerInfoMapsEqual(a, b map[string]protocol.DockerContainerInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for id, left := range a {
		right, ok := b[id]
		if !ok || !DockerContainerInfoEqual(left, right) {
			return false
		}
	}
	return true
}

func DockerContainerInfoEqual(a, b protocol.DockerContainerInfo) bool {
	if a.ID != b.ID || a.Name != b.Name || a.Image != b.Image || a.State != b.State || a.Status != b.Status || a.Created != b.Created {
		return false
	}
	if !DockerPortMappingsEqual(a.Ports, b.Ports) {
		return false
	}
	if !stringSlicesEqual(a.Networks, b.Networks) {
		return false
	}
	if !stringMapsEqual(a.Labels, b.Labels) {
		return false
	}
	if len(a.Mounts) != len(b.Mounts) {
		return false
	}
	for i := range a.Mounts {
		if a.Mounts[i] != b.Mounts[i] {
			return false
		}
	}
	return true
}

func DockerPortMappingsEqual(a, b []protocol.DockerPortMapping) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func diffContainerInfoMap(previous, next map[string]protocol.DockerContainerInfo) ([]protocol.DockerContainerInfo, []string) {
	upserts := make([]protocol.DockerContainerInfo, 0)
	removals := make([]string, 0)
	for id, nextContainer := range next {
		prevContainer, ok := previous[id]
		if !ok || !DockerContainerInfoEqual(prevContainer, nextContainer) {
			upserts = append(upserts, nextContainer)
		}
	}
	for id := range previous {
		if _, ok := next[id]; !ok {
			removals = append(removals, id)
		}
	}
	sort.Slice(upserts, func(i, j int) bool {
		if upserts[i].Name == upserts[j].Name {
			return upserts[i].ID < upserts[j].ID
		}
		return upserts[i].Name < upserts[j].Name
	})
	sort.Strings(removals)
	return upserts, removals
}

func DockerImageInfoMapsEqual(a, b map[string]protocol.DockerImageInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for id, left := range a {
		right, ok := b[id]
		if !ok || left.ID != right.ID || left.Size != right.Size || left.Created != right.Created || !stringSlicesEqual(left.Tags, right.Tags) {
			return false
		}
	}
	return true
}

func DockerNetworkInfoMapsEqual(a, b map[string]protocol.DockerNetworkInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for id, left := range a {
		right, ok := b[id]
		if !ok || left != right {
			return false
		}
	}
	return true
}

func DockerVolumeInfoMapsEqual(a, b map[string]protocol.DockerVolumeInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for name, left := range a {
		right, ok := b[name]
		if !ok || left != right {
			return false
		}
	}
	return true
}

func composeStacksEqual(a, b []protocol.DockerComposeStack) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	left := make(map[string]protocol.DockerComposeStack, len(a))
	for _, stack := range a {
		left[stack.Name] = stack
	}
	for _, stack := range b {
		other, ok := left[stack.Name]
		if !ok {
			return false
		}
		if other.Status != stack.Status || other.ConfigFile != stack.ConfigFile || !stringSlicesEqual(other.Containers, stack.Containers) {
			return false
		}
	}
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func cloneDockerContainerInfoMap(source map[string]protocol.DockerContainerInfo) map[string]protocol.DockerContainerInfo {
	if len(source) == 0 {
		return make(map[string]protocol.DockerContainerInfo)
	}
	result := make(map[string]protocol.DockerContainerInfo, len(source))
	for id, container := range source {
		copyContainer := container
		copyContainer.Labels = cloneStringMap(container.Labels)
		copyContainer.Ports = append([]protocol.DockerPortMapping(nil), container.Ports...)
		copyContainer.Networks = append([]string(nil), container.Networks...)
		copyContainer.Mounts = append([]protocol.DockerMountInfo(nil), container.Mounts...)
		result[id] = copyContainer
	}
	return result
}

func cloneComposeStacks(source []protocol.DockerComposeStack) []protocol.DockerComposeStack {
	if len(source) == 0 {
		return nil
	}
	result := make([]protocol.DockerComposeStack, len(source))
	for i, stack := range source {
		result[i] = stack
		result[i].Containers = append([]string(nil), stack.Containers...)
	}
	return result
}

func cloneStringSet(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for key := range source {
		result[key] = struct{}{}
	}
	return result
}

// inferComposeStacks groups containers by com.docker.compose.project label.
func inferComposeStacks(containers []DockerContainer) []protocol.DockerComposeStack {
	type composeAccumulator struct {
		stack       *protocol.DockerComposeStack
		running     int
		containerID map[string]struct{}
	}
	stacks := make(map[string]*composeAccumulator)

	for _, c := range containers {
		project := c.Labels["com.docker.compose.project"]
		if project == "" {
			continue
		}
		acc, exists := stacks[project]
		if !exists {
			stack := &protocol.DockerComposeStack{Name: project, Status: "running(0)"}
			if dir := c.Labels["com.docker.compose.project.working_dir"]; dir != "" {
				stack.ConfigFile = dir + "/docker-compose.yml"
			}
			acc = &composeAccumulator{
				stack:       stack,
				containerID: make(map[string]struct{}),
			}
			stacks[project] = acc
		}
		name := ContainerName(c.Names)
		if name != "" {
			if _, seen := acc.containerID[name]; !seen {
				acc.stack.Containers = append(acc.stack.Containers, name)
				acc.containerID[name] = struct{}{}
			}
		}
		if c.State == "running" {
			acc.running++
		}
	}

	result := make([]protocol.DockerComposeStack, 0, len(stacks))
	for _, acc := range stacks {
		sort.Strings(acc.stack.Containers)
		acc.stack.Status = fmt.Sprintf("running(%d)", acc.running)
		result = append(result, *acc.stack)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}
