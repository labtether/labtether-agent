//go:build !darwin

package netid

import "net"

// hardwareMACs is nil outside macOS: Linux and Windows return real addresses
// in the interface list, so MACResolver leaves them unchanged.
var hardwareMACs func() map[string]net.HardwareAddr
