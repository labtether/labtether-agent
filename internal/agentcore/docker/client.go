package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const dockerUnixScheme = "unix://"

// dockerClient is a lightweight Docker Engine API client using raw HTTP.
type dockerClient struct {
	httpClient *http.Client
	baseURL    string // "http://localhost" for unix socket, or full URL for TCP
	unixPath   string // non-empty when using a unix domain socket endpoint
}

// newDockerClient creates a client for the given Docker socket path or TCP URL.
// For unix sockets, pass the socket path (e.g., "/var/run/docker.sock").
// For TCP URLs (used in testing with httptest), pass the full URL.
func NewDockerClient(endpoint string) *dockerClient {
	endpoint = strings.TrimSpace(endpoint)
	if stripped, ok := TrimDockerUnixScheme(endpoint); ok {
		endpoint = stripped
	}
	lowerEndpoint := strings.ToLower(endpoint)
	if strings.HasPrefix(lowerEndpoint, "http://") || strings.HasPrefix(lowerEndpoint, "https://") {
		// TCP URL (used for testing with httptest)
		return &dockerClient{
			httpClient: &http.Client{Timeout: 30 * time.Second},
			baseURL:    strings.TrimRight(endpoint, "/"),
		}
	}
	// Unix socket
	return &dockerClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.DialTimeout("unix", endpoint, 5*time.Second)
				},
			},
		},
		baseURL:  "http://localhost",
		unixPath: endpoint,
	}
}

func TrimDockerUnixScheme(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < len(dockerUnixScheme) {
		return trimmed, false
	}
	if strings.EqualFold(trimmed[:len(dockerUnixScheme)], dockerUnixScheme) {
		return strings.TrimSpace(trimmed[len(dockerUnixScheme):]), true
	}
	return trimmed, false
}

func (c *dockerClient) newRequest(ctx context.Context, method, requestURL string, body io.Reader) (*http.Request, error) {
	if c != nil && strings.TrimSpace(c.unixPath) != "" {
		// #nosec G107 -- unix socket transport never leaves local host networking.
		return http.NewRequestWithContext(ctx, method, requestURL, body)
	}
	return securityruntime.NewOutboundRequestWithContext(ctx, method, requestURL, body)
}

func (c *dockerClient) doRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	if client == nil {
		client = c.httpClient
	}
	if c != nil && strings.TrimSpace(c.unixPath) != "" {
		// #nosec G107 G704 -- unix socket transport is local IPC, not remote network egress.
		return client.Do(req)
	}
	return securityruntime.DoOutboundRequest(client, req)
}

func (c *dockerClient) post(ctx context.Context, path string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodPost, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(c.httpClient, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker API POST %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (c *dockerClient) doDelete(ctx context.Context, path string) error {
	req, err := c.newRequest(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.doRequest(c.httpClient, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, copyErr := io.Copy(io.Discard, resp.Body); copyErr != nil {
		return copyErr
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("docker API DELETE %s returned %d", path, resp.StatusCode)
	}
	return nil
}

func dockerPathSegment(value string) string {
	return neturl.PathEscape(strings.TrimSpace(value))
}

func (c *dockerClient) startContainer(ctx context.Context, id string) error {
	_, err := c.post(ctx, "/containers/"+dockerPathSegment(id)+"/start")
	return err
}

func (c *dockerClient) stopContainer(ctx context.Context, id string, timeout int) error {
	query := neturl.Values{}
	query.Set("t", strconv.Itoa(timeout))
	_, err := c.post(ctx, "/containers/"+dockerPathSegment(id)+"/stop?"+query.Encode())
	return err
}

func (c *dockerClient) restartContainer(ctx context.Context, id string, timeout int) error {
	query := neturl.Values{}
	query.Set("t", strconv.Itoa(timeout))
	_, err := c.post(ctx, "/containers/"+dockerPathSegment(id)+"/restart?"+query.Encode())
	return err
}

func (c *dockerClient) killContainer(ctx context.Context, id string, signal string) error {
	path := "/containers/" + dockerPathSegment(id) + "/kill"
	if signal != "" {
		query := neturl.Values{}
		query.Set("signal", signal)
		path += "?" + query.Encode()
	}
	_, err := c.post(ctx, path)
	return err
}

func (c *dockerClient) removeContainer(ctx context.Context, id string, force bool) error {
	query := neturl.Values{}
	query.Set("force", strconv.FormatBool(force))
	path := "/containers/" + dockerPathSegment(id) + "?" + query.Encode()
	return c.doDelete(ctx, path)
}

func (c *dockerClient) pauseContainer(ctx context.Context, id string) error {
	_, err := c.post(ctx, "/containers/"+dockerPathSegment(id)+"/pause")
	return err
}

func (c *dockerClient) unpauseContainer(ctx context.Context, id string) error {
	_, err := c.post(ctx, "/containers/"+dockerPathSegment(id)+"/unpause")
	return err
}

func (c *dockerClient) pullImage(ctx context.Context, imageRef string) error {
	query := neturl.Values{}
	query.Set("fromImage", strings.TrimSpace(imageRef))
	_, err := c.post(ctx, "/images/create?"+query.Encode())
	return err
}

func (c *dockerClient) removeImage(ctx context.Context, id string, force bool) error {
	query := neturl.Values{}
	query.Set("force", strconv.FormatBool(force))
	path := "/images/" + dockerPathSegment(id) + "?" + query.Encode()
	return c.doDelete(ctx, path)
}

func (c *dockerClient) createContainer(ctx context.Context, req DockerContainerCreateRequest) (string, error) {
	image := strings.TrimSpace(req.Image)
	if image == "" {
		return "", fmt.Errorf("image is required")
	}

	body := map[string]any{
		"Image": image,
	}
	if len(req.Command) > 0 {
		body["Cmd"] = req.Command
	}
	if len(req.Environment) > 0 {
		body["Env"] = req.Environment
	}
	if len(req.PortBindings) > 0 {
		exposed := map[string]map[string]any{}
		hostConfigBindings := map[string][]map[string]string{}
		for _, binding := range req.PortBindings {
			containerPort := strings.TrimSpace(binding.ContainerPort)
			hostPort := strings.TrimSpace(binding.HostPort)
			if containerPort == "" || hostPort == "" {
				continue
			}
			protocol := strings.TrimSpace(binding.Protocol)
			if protocol == "" {
				protocol = "tcp"
			}
			portKey := fmt.Sprintf("%s/%s", containerPort, strings.ToLower(protocol))
			exposed[portKey] = map[string]any{}
			hostConfigBindings[portKey] = append(hostConfigBindings[portKey], map[string]string{
				"HostPort": hostPort,
			})
		}
		if len(exposed) > 0 {
			body["ExposedPorts"] = exposed
		}
		if len(hostConfigBindings) > 0 {
			body["HostConfig"] = map[string]any{
				"PortBindings": hostConfigBindings,
			}
		}
	}

	jsonBody, _ := json.Marshal(body)
	path := "/containers/create"
	if name := strings.TrimSpace(req.Name); name != "" {
		path += "?name=" + neturl.QueryEscape(name)
	}

	httpReq, err := c.newRequest(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.doRequest(c.httpClient, httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("container create returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", err
	}
	if strings.TrimSpace(parsed.ID) == "" {
		return "", fmt.Errorf("container create returned empty container id")
	}
	return strings.TrimSpace(parsed.ID), nil
}

func (c *dockerClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(c.httpClient, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker API %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (c *dockerClient) ping(ctx context.Context) error {
	_, err := c.get(ctx, "/_ping")
	return err
}

func (c *dockerClient) version(ctx context.Context) (DockerVersionResponse, error) {
	data, err := c.get(ctx, "/version")
	if err != nil {
		return DockerVersionResponse{}, err
	}
	var v DockerVersionResponse
	err = json.Unmarshal(data, &v)
	return v, err
}

func (c *dockerClient) listContainers(ctx context.Context) ([]DockerContainer, error) {
	data, err := c.get(ctx, "/containers/json?all=1")
	if err != nil {
		return nil, err
	}
	var containers []DockerContainer
	err = json.Unmarshal(data, &containers)
	return containers, err
}

func (c *dockerClient) listImages(ctx context.Context) ([]DockerImage, error) {
	data, err := c.get(ctx, "/images/json")
	if err != nil {
		return nil, err
	}
	var images []DockerImage
	err = json.Unmarshal(data, &images)
	return images, err
}

func (c *dockerClient) listNetworks(ctx context.Context) ([]DockerNetwork, error) {
	data, err := c.get(ctx, "/networks")
	if err != nil {
		return nil, err
	}
	var networks []DockerNetwork
	err = json.Unmarshal(data, &networks)
	return networks, err
}

func (c *dockerClient) listVolumes(ctx context.Context) ([]DockerVolume, error) {
	data, err := c.get(ctx, "/volumes")
	if err != nil {
		return nil, err
	}
	var resp DockerVolumesResponse
	err = json.Unmarshal(data, &resp)
	return resp.Volumes, err
}

// streamEvents opens GET /events and sends parsed events to the channel.
// Blocks until the context is cancelled or the connection drops.
func (c *dockerClient) streamEvents(ctx context.Context, ch chan<- DockerEvent) error {
	req, err := c.newRequest(ctx, http.MethodGet, c.baseURL+"/events", nil)
	if err != nil {
		return err
	}
	// Use a separate client without timeout for long-lived streaming.
	streamClient := &http.Client{Transport: c.httpClient.Transport}
	resp, err := c.doRequest(streamClient, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	for {
		var event DockerEvent
		if err := decoder.Decode(&event); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case ch <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// containerStats fetches one-shot stats for a container.
func (c *dockerClient) containerStats(ctx context.Context, containerID string) (DockerStatsResponse, error) {
	query := neturl.Values{}
	query.Set("stream", "false")
	data, err := c.get(ctx, "/containers/"+dockerPathSegment(containerID)+"/stats?"+query.Encode())
	if err != nil {
		return DockerStatsResponse{}, err
	}
	var stats DockerStatsResponse
	err = json.Unmarshal(data, &stats)
	return stats, err
}

// createExec creates an exec instance in a container. Returns the exec ID.
func (c *dockerClient) createExec(ctx context.Context, containerID string, cmd []string, tty bool) (string, error) {
	body := map[string]any{
		"AttachStdin":  true,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          tty,
		"Cmd":          cmd,
	}
	jsonBody, _ := json.Marshal(body)
	req, err := c.newRequest(ctx, http.MethodPost,
		c.baseURL+"/containers/"+dockerPathSegment(containerID)+"/exec", bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doRequest(c.httpClient, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("exec create returned %d: %s", resp.StatusCode, string(respBody))
	}
	var result struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	return result.ID, nil
}

// containerLogs fetches container logs. Returns the response body for streaming.
func (c *dockerClient) containerLogs(ctx context.Context, containerID string, tail int, follow, timestamps bool) (io.ReadCloser, error) {
	query := neturl.Values{}
	query.Set("stdout", "1")
	query.Set("stderr", "1")
	query.Set("tail", strconv.Itoa(tail))
	query.Set("follow", strconv.FormatBool(follow))
	query.Set("timestamps", strconv.FormatBool(timestamps))
	path := "/containers/" + dockerPathSegment(containerID) + "/logs?" + query.Encode()
	req, err := c.newRequest(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	// Use a client without timeout for long-lived log streaming.
	streamClient := &http.Client{Transport: c.httpClient.Transport}
	resp, err := c.doRequest(streamClient, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if closeErr := resp.Body.Close(); closeErr != nil {
			return nil, fmt.Errorf("logs returned %d: %s (close body: %v)", resp.StatusCode, string(body), closeErr)
		}
		return nil, fmt.Errorf("logs returned %d: %s", resp.StatusCode, string(body))
	}
	return resp.Body, nil
}
