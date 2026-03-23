package docker

import (
	"context"

	"github.com/labtether/protocol"
)

// Transport abstracts the agent-to-hub communication channel so this package
// does not depend on the concrete wsTransport type in the parent agentcore package.
type Transport interface {
	Connect(ctx context.Context) error
	Send(msg protocol.Message) error
	Receive() (protocol.Message, error)
	Close()
	Connected() bool
}
