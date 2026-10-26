// Package x11input implements the agent's isolated, typed XTEST key helper.
package x11input

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

const CommandFlag = "--labtether-internal-x11-input"
const PolicyName = "labtether-x11-input"
const MaxKeys = 256

type Request struct {
	Press bool
	Keys  []byte
}

// Dispatch must run before normal agent configuration and enrollment. Invalid
// internal requests are handled errors, never a request to start another agent.
func Dispatch(args []string, run func(Request) error) (bool, error) {
	if len(args) == 0 || !strings.HasPrefix(args[0], "--labtether-internal-") {
		return false, nil
	}
	if args[0] != CommandFlag {
		return true, fmt.Errorf("unknown internal helper")
	}
	request, err := Parse(args[1:])
	if err != nil {
		return true, err
	}
	return true, run(request)
}

func Parse(args []string) (Request, error) {
	var request Request
	if len(args) < 2 || len(args) > MaxKeys+1 {
		return request, fmt.Errorf("X11 helper requires 1 to %d keycodes", MaxKeys)
	}
	if args[0] != "down" && args[0] != "up" {
		return request, fmt.Errorf("invalid X11 key operation")
	}
	request.Press = args[0] == "down"
	for _, value := range args[1:] {
		code, err := strconv.ParseUint(value, 10, 8)
		if err != nil || code < 8 || strconv.FormatUint(code, 10) != value {
			return Request{}, fmt.Errorf("invalid X11 physical keycode")
		}
		request.Keys = append(request.Keys, byte(code))
	}
	return request, nil
}

// NewCommand can re-execute only this binary with validated typed arguments.
// The logical policy name lets a custom executable allowlist deny this helper.
func NewCommand(args ...string) (*exec.Cmd, error) {
	if _, err := Parse(args); err != nil {
		return nil, err
	}
	if err := securityruntime.ValidateExecBinary(PolicyName); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate X11 helper executable: %w", err)
	}
	return exec.Command(executable, append([]string{CommandFlag}, args...)...), nil // #nosec G204 -- Only this executable and validated physical keycodes can be passed.
}
