package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const maxDockerLogLineBytes = 64 * 1024

// Inspect the actual TTY configuration: raw terminal text must never be guessed
// from its leading bytes, and malformed binary frames must not become text.
func (c *dockerClient) containerLogTTY(ctx context.Context, id string) (bool, error) {
	raw, err := c.get(ctx, "/containers/"+url.PathEscape(strings.TrimSpace(id))+"/json")
	if err != nil {
		return false, err
	}
	var inspected struct {
		Config *struct {
			TTY *bool `json:"Tty"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(raw, &inspected); err != nil {
		return false, fmt.Errorf("read container TTY configuration: %w", err)
	}
	if inspected.Config == nil || inspected.Config.TTY == nil {
		return false, errors.New("container inspect did not include TTY configuration")
	}
	return *inspected.Config.TTY, nil
}

type dockerLogLineBuffer struct {
	data     []byte
	sequence uint64
}

// Docker frames can contain several lines, one partial line, or binary headers
// whose length bytes contain newline. Parse framing before splitting text.
func streamDockerLogLines(ctx context.Context, reader io.Reader, tty bool, send func(string, string) error) error {
	if tty {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), maxDockerLogLineBytes+2)
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(scanner.Bytes()) > maxDockerLogLineBytes {
				return errors.New("Docker log line exceeds 64 KiB")
			}
			if err := send("stdout", scanner.Text()); err != nil {
				return err
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read Docker TTY logs: %w", err)
		}
		return ctx.Err()
	}
	lines := map[byte]*dockerLogLineBuffer{1: {}, 2: {}}
	var sequence uint64
	emit := func(stream byte, data []byte) error {
		pending := lines[stream]
		for len(data) > 0 {
			index := bytes.IndexByte(data, '\n')
			count := len(data)
			if index >= 0 {
				count = index
			}
			if len(pending.data)+count > maxDockerLogLineBytes {
				return errors.New("Docker log line exceeds 64 KiB")
			}
			if len(pending.data) == 0 {
				sequence++
				pending.sequence = sequence
			}
			pending.data = append(pending.data, data[:count]...)
			if index < 0 {
				return nil
			}
			streamName := "stdout"
			if stream == 2 {
				streamName = "stderr"
			}
			if err := send(streamName, strings.TrimSuffix(string(pending.data), "\r")); err != nil {
				return err
			}
			pending.data = pending.data[:0]
			data = data[count+1:]
		}
		return nil
	}
	var header [8]byte
	buffer := make([]byte, 16*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := io.ReadFull(reader, header[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("truncated Docker log header: %w", err)
		}
		stream := header[0]
		if stream > 3 || header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return errors.New("invalid Docker log frame header")
		}
		size := int64(binary.BigEndian.Uint32(header[4:]))
		if stream == 3 {
			data, err := io.ReadAll(io.LimitReader(reader, min(size, 4096)))
			if err != nil {
				return fmt.Errorf("read Docker daemon error: %w", err)
			}
			if int64(len(data)) < min(size, 4096) {
				return errors.New("truncated Docker daemon error frame")
			}
			return fmt.Errorf("Docker daemon: %s", string(data))
		}
		if stream == 0 {
			stream = 1
		}
		for size > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			count := int(min(size, int64(len(buffer))))
			if _, err := io.ReadFull(reader, buffer[:count]); err != nil {
				return fmt.Errorf("truncated Docker log payload: %w", err)
			}
			if err := emit(stream, buffer[:count]); err != nil {
				return err
			}
			size -= int64(count)
		}
	}
	order := []byte{1, 2}
	if lines[2].sequence < lines[1].sequence {
		order[0], order[1] = 2, 1
	}
	for _, stream := range order {
		if len(lines[stream].data) > 0 {
			streamName := "stdout"
			if stream == 2 {
				streamName = "stderr"
			}
			if err := send(streamName, strings.TrimSuffix(string(lines[stream].data), "\r")); err != nil {
				return err
			}
		}
	}
	return nil
}
