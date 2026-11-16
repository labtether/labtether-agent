//go:build darwin

package netid

import (
	"context"
	"net"
	"time"

	"github.com/labtether/labtether-agent/internal/securityruntime"
)

// hardwareMACs asks networksetup for each hardware port's address. On macOS
// 27 it returns the real address of physical ports even when the agent's own
// interface list is redacted; a virtual port such as bridge0 can still come
// back as the placeholder, which parseHardwarePorts drops. For Wi-Fi this is
// the port's own address, which is not the one the network sees when Private
// Wi-Fi Address is on.
var hardwareMACs = func() map[string]net.HardwareAddr {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := securityruntime.AgentPathCommandContextOutput(ctx, "/usr/sbin/networksetup", "-listallhardwareports")
	if err != nil {
		return nil
	}
	return parseHardwarePorts(string(out))
}
