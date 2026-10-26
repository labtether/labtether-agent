package remoteaccess

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const maxWebRTCX11KeymapBytes = 512 * 1024

var x11KeymapSymbol = regexp.MustCompile(`^\s*(0x[0-9a-fA-F]+)\s+\(([^()]*)\)`)

type webRTCInputResolver func(context.Context, WebRTCInputEvent) (WebRTCInputEvent, error)

// Resolve against the current server map on each new logical key press. The
// shared owner retains this physical code for repeats, key-up and cleanup, so
// a layout change cannot redirect the release to a different physical key.
func resolveWebRTCX11Input(ctx context.Context, event WebRTCInputEvent, display, xauthPath string) (WebRTCInputEvent, error) {
	if event.Type != "keydown" && event.Type != "keyup" {
		return event, nil
	}
	if event.x11Keycode != 0 {
		return event, nil
	}
	key, ok := X11KeyArgument(event)
	if !ok {
		return event, fmt.Errorf("unsupported X11 %s event", event.Type)
	}
	if strings.TrimSpace(display) == "" {
		display = ":0"
	}
	output, err := runWebRTCInputCommandOutputContext(ctx, "xmodmap", BuildX11ClientEnv(display, xauthPath), maxWebRTCX11KeymapBytes, "-pk")
	if err != nil {
		return event, fmt.Errorf("read X11 keymap: %w", err)
	}
	code, err := resolveX11Keycode(output, key)
	if err != nil {
		return event, err
	}
	event.x11Keycode = code
	return event, nil
}

// xmodmap -pk prints both numeric keysyms and their names. Numeric comparison
// merges a legacy hexadecimal keysym with its named alias without maintaining
// a second, incomplete copy of X11's symbol table.
func resolveX11Keycode(output []byte, key string) (uint8, error) {
	if len(output) > maxWebRTCX11KeymapBytes {
		return 0, fmt.Errorf("X11 keymap exceeds output limit")
	}
	var numeric uint64
	var numericKey bool
	if strings.HasPrefix(key, "0x") {
		var err error
		numeric, err = strconv.ParseUint(key[2:], 16, 32)
		numericKey = err == nil
	} else if len(key) == 1 {
		numeric, numericKey = uint64(key[0]), true
	}
	bestCode, bestColumn := 0, 65
	seen := make(map[int]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Buffer(make([]byte, 4096), 128*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "There are ") {
			continue
		}
		fields := strings.Fields(line)
		if fields[0] == "KeyCode" || fields[0] == "Value" {
			continue
		}
		code, err := strconv.Atoi(fields[0])
		if err != nil || code < 8 || code > 255 || seen[code] {
			return 0, fmt.Errorf("invalid X11 keymap keycode row")
		}
		seen[code] = true
		rest := strings.TrimSpace(line[len(fields[0]):])
		for column := 0; rest != ""; column++ {
			match := x11KeymapSymbol.FindStringSubmatch(rest)
			if match == nil || column >= 64 {
				return 0, fmt.Errorf("invalid X11 keymap symbol row")
			}
			symbol, err := strconv.ParseUint(match[1][2:], 16, 32)
			if err != nil {
				return 0, fmt.Errorf("invalid X11 numeric keysym")
			}
			name := match[2] // xmodmap uses the two-word name "no name" for unknown symbols.
			rest = strings.TrimSpace(rest[len(match[0]):])
			if symbol == 0 || (name != key && (!numericKey || numeric != symbol)) {
				continue
			}
			if column < bestColumn || (column == bestColumn && code < bestCode) {
				bestCode, bestColumn = code, column
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("invalid X11 keymap output: %w", err)
	}
	if bestCode == 0 {
		return 0, fmt.Errorf("unsupported X11 keysym %q in current server keymap", key)
	}
	return uint8(bestCode), nil
}

func x11RawKeyArgument(event WebRTCInputEvent) (string, error) {
	if event.x11Keycode < 8 {
		return "", fmt.Errorf("X11 key has no resolved physical keycode")
	}
	return strconv.Itoa(int(event.x11Keycode)), nil
}
