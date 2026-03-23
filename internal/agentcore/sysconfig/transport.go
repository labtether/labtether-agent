package sysconfig

import "github.com/labtether/protocol"

// MessageSender abstracts the agent-to-hub send capability so this package
// does not depend on the concrete wsTransport type in the parent agentcore package.
type MessageSender interface {
	Send(msg protocol.Message) error
}
