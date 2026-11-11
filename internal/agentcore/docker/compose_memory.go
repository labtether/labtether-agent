package docker

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/labtether/protocol"
)

const (
	composeMemoryFileName = "compose-projects.json"
	composeMemoryMaxBytes = 1 << 20
	composeMemoryMaxItems = 256
	composeStoppedStatus  = "stopped"
)

// composeMemory remembers the Compose projects this agent has seen with
// containers, so a project taken down (from LabTether or with `docker compose
// down` on the host) stays listed as stopped and can be brought up again. It
// is kept in the agent's state folder and survives a restart. A project is
// forgotten once its compose files are gone.
type composeMemory struct {
	mu       sync.Mutex
	path     string
	projects map[string]composeSelection
}

type rememberedComposeProject struct {
	Name  string   `json:"name"`
	Dir   string   `json:"dir"`
	Files []string `json:"files"`
}

// newComposeMemory loads the memory from stateDir. With an empty stateDir it
// remembers only while the agent runs.
func newComposeMemory(stateDir string) *composeMemory {
	memory := &composeMemory{projects: make(map[string]composeSelection)}
	if stateDir == "" {
		return memory
	}
	memory.path = filepath.Join(stateDir, composeMemoryFileName)
	file, err := os.Open(memory.path) // #nosec G304 -- fixed file name in the agent's own state folder.
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("docker: Compose project memory not read: %v", err)
		}
		return memory
	}
	defer file.Close()
	var saved []rememberedComposeProject
	if err := json.NewDecoder(io.LimitReader(file, composeMemoryMaxBytes)).Decode(&saved); err != nil {
		log.Printf("docker: Compose project memory not read: %v", err)
		return memory
	}
	for _, project := range saved {
		selection := composeSelection{Name: project.Name, Dir: project.Dir, Files: project.Files}
		if validRememberedSelection(selection) && len(memory.projects) < composeMemoryMaxItems {
			memory.projects[selection.Name] = selection
		}
	}
	return memory
}

func validRememberedSelection(selection composeSelection) bool {
	if !composeProjectName.MatchString(selection.Name) || !filepath.IsAbs(selection.Dir) || len(selection.Files) == 0 {
		return false
	}
	for _, file := range selection.Files {
		if !filepath.IsAbs(file) {
			return false
		}
	}
	return true
}

// merge remembers every certified live project and adds each remembered
// project that has no containers now, as stopped with 0 containers, while its
// compose files still exist. An incomplete inventory adds nothing: a project
// past the container limit is not down.
func (m *composeMemory) merge(live []protocol.DockerComposeStack, incomplete bool) []protocol.DockerComposeStack {
	if m == nil {
		return live
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := false
	seen := make(map[string]bool, len(live))
	for _, stack := range live {
		seen[stack.Name] = true
		selection := composeSelection{Name: stack.Name, Dir: stack.ConfigDir, Files: stack.ConfigFiles}
		if stack.SelectionError != "" || !validRememberedSelection(selection) {
			continue
		}
		if known, ok := m.projects[stack.Name]; ok && selectionsEqual(known, selection) {
			continue
		}
		if _, ok := m.projects[stack.Name]; !ok && len(m.projects) >= composeMemoryMaxItems {
			continue
		}
		m.projects[stack.Name] = composeSelection{Name: selection.Name, Dir: selection.Dir, Files: append([]string(nil), selection.Files...)}
		changed = true
	}
	merged := append([]protocol.DockerComposeStack(nil), live...)
	if !incomplete {
		for name, selection := range m.projects {
			if seen[name] {
				continue
			}
			if validateComposeFiles(selection) != nil {
				delete(m.projects, name)
				changed = true
				continue
			}
			merged = append(merged, protocol.DockerComposeStack{
				Name:        name,
				Status:      composeStoppedStatus,
				ConfigDir:   selection.Dir,
				ConfigFile:  selection.Dir + "/docker-compose.yml", // deprecated projection for old Hubs
				ConfigFiles: append([]string(nil), selection.Files...),
				Containers:  []string{},
			})
		}
	}
	if changed {
		m.saveLocked()
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Name < merged[j].Name })
	return merged
}

// lookup returns a remembered project's selection.
func (m *composeMemory) lookup(name string) (composeSelection, bool) {
	if m == nil {
		return composeSelection{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	selection, ok := m.projects[name]
	return selection, ok
}

func (m *composeMemory) saveLocked() {
	if m.path == "" {
		return
	}
	saved := make([]rememberedComposeProject, 0, len(m.projects))
	for _, selection := range m.projects {
		saved = append(saved, rememberedComposeProject{Name: selection.Name, Dir: selection.Dir, Files: selection.Files})
	}
	sort.Slice(saved, func(i, j int) bool { return saved[i].Name < saved[j].Name })
	data, err := json.Marshal(saved)
	if err != nil {
		return
	}
	temporary := m.path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		log.Printf("docker: Compose project memory not saved: %v", err)
		return
	}
	if err := os.Rename(temporary, m.path); err != nil {
		_ = os.Remove(temporary)
		log.Printf("docker: Compose project memory not saved: %v", err)
	}
}
