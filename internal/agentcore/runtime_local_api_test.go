package agentcore

import (
	"context"
	"net"
	"testing"
	"time"
)

// Another program (or any local user) holding the local API port used to make
// Run return the bind error, which main treats as fatal. The agent must keep
// running until shutdown instead.
func TestRuntimeRunKeepsGoingWhenLocalAPIPortIsBusy(t *testing.T) {
	t.Setenv(envAgentLocalBindAddress, "")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer busy.Close()
	_, port, err := net.SplitHostPort(busy.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}

	rt := NewRuntime(RuntimeConfig{
		Name:              "test-agent",
		Port:              port,
		CollectInterval:   time.Hour,
		HeartbeatInterval: time.Hour,
	}, stubProvider{}, noopHeartbeatPublisher{})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := rt.Run(ctx); err != nil {
		t.Fatalf("Run returned %v; a busy local API port must not stop the agent", err)
	}
	if ctx.Err() == nil {
		t.Fatal("Run returned before shutdown")
	}
}
