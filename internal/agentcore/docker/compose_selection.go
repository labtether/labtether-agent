package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/labtether/protocol"
)

const (
	composeProjectLabel   = "com.docker.compose.project"
	composeDirectoryLabel = "com.docker.compose.project.working_dir"
	composeFilesLabel     = "com.docker.compose.project.config_files"
	composeInventoryLimit = 10 * 1024 * 1024
)

var composeProjectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

type composeSelection struct {
	Name  string
	Dir   string
	Files []string
}

func selectionFromLabels(labels map[string]string) (composeSelection, string) {
	value := composeSelection{Name: labels[composeProjectLabel], Dir: labels[composeDirectoryLabel]}
	files := labels[composeFilesLabel]
	if value.Name == "" || value.Dir == "" || files == "" {
		return value, "missing_labels"
	}
	if !composeProjectName.MatchString(value.Name) || !filepath.IsAbs(value.Dir) || strings.ContainsRune(value.Dir, 0) {
		return value, "invalid_labels"
	}
	value.Files = strings.Split(files, ",")
	for _, file := range value.Files {
		if !filepath.IsAbs(file) || strings.ContainsRune(file, 0) {
			return value, "invalid_labels"
		}
	}
	return value, ""
}

func selectionsEqual(a, b composeSelection) bool {
	return a.Name == b.Name && a.Dir == b.Dir && stringSlicesEqual(a.Files, b.Files)
}

// inferComposeStacks retains visibility even when labels cannot certify a selection.
func inferComposeStacks(containers []DockerContainer) []protocol.DockerComposeStack {
	type accumulator struct {
		stack     protocol.DockerComposeStack
		selection composeSelection
		running   int
		names     map[string]bool
	}
	stacks := make(map[string]*accumulator)
	for _, container := range containers {
		project := container.Labels[composeProjectLabel]
		if project == "" {
			continue
		}
		selection, invalid := selectionFromLabels(container.Labels)
		acc := stacks[project]
		if acc == nil {
			stack := protocol.DockerComposeStack{Name: project, ConfigDir: selection.Dir, ConfigFiles: append([]string(nil), selection.Files...), SelectionError: invalid}
			// Deprecated directory projection for old Hubs; never a claim this file exists.
			if selection.Dir != "" {
				stack.ConfigFile = selection.Dir + "/docker-compose.yml"
			}
			acc = &accumulator{stack: stack, selection: selection, names: make(map[string]bool)}
			stacks[project] = acc
		} else if invalid != "" || !selectionsEqual(acc.selection, selection) {
			acc.stack.SelectionError = "conflicting_labels"
		}
		name := ContainerName(container.Names)
		if name != "" && !acc.names[name] {
			acc.names[name] = true
			acc.stack.Containers = append(acc.stack.Containers, name)
		}
		if container.State == "running" {
			acc.running++
		}
	}
	result := make([]protocol.DockerComposeStack, 0, len(stacks))
	for _, acc := range stacks {
		sort.Strings(acc.stack.Containers)
		acc.stack.Status = fmt.Sprintf("running(%d)", acc.running)
		result = append(result, acc.stack)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func inferCompleteComposeStacks(containers []DockerContainer, incomplete bool) []protocol.DockerComposeStack {
	stacks := inferComposeStacks(containers)
	if incomplete {
		for i := range stacks {
			stacks[i].SelectionError = "incomplete_inventory"
		}
	}
	return stacks
}

func (c *dockerClient) composeProjectContainers(ctx context.Context, project string) ([]DockerContainer, error) {
	filters, _ := json.Marshal(map[string][]string{"label": {composeProjectLabel + "=" + project}})
	request, err := c.newRequest(ctx, http.MethodGet, c.baseURL+"/containers/json?all=1&filters="+url.QueryEscape(string(filters)), nil)
	if err != nil {
		return nil, err
	}
	client := c.httpClient
	if request.URL.Scheme == "https" {
		// The trust probe and selection must stay on the captured HTTPS endpoint.
		// Clone only this request's client; do not change inventory or HTTP policy.
		guarded := http.Client{}
		if client != nil {
			guarded = *client
		}
		guarded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &guarded
	}
	response, err := c.doRequest(client, request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Compose selection inventory returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, composeInventoryLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > composeInventoryLimit {
		return nil, fmt.Errorf("Compose selection inventory exceeds response bound")
	}
	var rows []DockerContainer
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 || len(rows) > maxContainersPerHost {
		return nil, fmt.Errorf("Compose selection inventory is missing or incomplete")
	}
	for _, row := range rows {
		if row.Labels[composeProjectLabel] != project {
			return nil, fmt.Errorf("Compose selection inventory returned a different project")
		}
	}
	return rows, nil
}

func (dc *DockerCollector) resolveComposeSelection(ctx context.Context, req protocol.DockerComposeActionData, versioned bool) (composeSelection, error) {
	if !composeProjectName.MatchString(req.StackName) {
		return composeSelection{}, fmt.Errorf("invalid native Compose project name")
	}
	rows, err := dc.client.composeProjectContainers(ctx, req.StackName)
	if err != nil {
		return composeSelection{}, err
	}
	stacks := inferComposeStacks(rows)
	if len(stacks) != 1 || stacks[0].SelectionError != "" {
		return composeSelection{}, fmt.Errorf("Compose project labels are missing or inconsistent")
	}
	stack := stacks[0]
	selected := composeSelection{Name: stack.Name, Dir: stack.ConfigDir, Files: stack.ConfigFiles}
	if selected.Dir != req.ConfigDir || (versioned && !stringSlicesEqual(selected.Files, req.ConfigFiles)) {
		return composeSelection{}, fmt.Errorf("Compose selection changed; refresh and resubmit the action")
	}
	if err := validateComposeFiles(selected); err != nil {
		return composeSelection{}, err
	}
	return selected, nil
}

func validateComposeFiles(selected composeSelection) error {
	directory, err := os.Stat(selected.Dir)
	if err != nil || !directory.IsDir() {
		return fmt.Errorf("Compose project directory is unavailable")
	}
	for _, file := range selected.Files {
		info, err := os.Stat(file)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("Compose config file is not a regular file")
		}
		source, err := os.Open(file) // #nosec G304 -- absolute Compose file named by the project labels; only opened to prove it is readable.
		if err != nil {
			return fmt.Errorf("Compose config file is unavailable")
		}
		info, err = source.Stat()
		closeErr := source.Close()
		if err != nil || closeErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("Compose config file is not a readable regular file")
		}
	}
	return nil
}
