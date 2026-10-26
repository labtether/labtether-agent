package docker

import (
	"context"
	"errors"
	"strings"
)

const maxDockerActionLogBytes = 2 * 1024 * 1024

// A bounded action response is complete or fails visibly. Never report a valid
// prefix as success when framing, transport, or response-size checks fail.
func (c *dockerClient) collectContainerLogs(ctx context.Context, id string, tail int, timestamps bool) (string, error) {
	tty, err := c.containerLogTTY(ctx, id)
	if err != nil {
		return "", err
	}
	body, err := c.containerLogs(ctx, id, tail, false, timestamps)
	if err != nil {
		return "", err
	}
	defer body.Close()
	var output strings.Builder
	err = streamDockerLogLines(ctx, body, tty, func(_ string, line string) error {
		if len(line)+1 > maxDockerActionLogBytes-output.Len() {
			return errors.New("Docker log action output exceeds 2 MiB; request fewer lines")
		}
		output.WriteString(line)
		output.WriteByte('\n')
		return nil
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output.String()), nil
}
