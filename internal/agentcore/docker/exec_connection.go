package docker

import (
	"context"
	"net"
)

type contextExecConnection struct {
	net.Conn
	stop func() bool
}

func bindDockerExecConnection(ctx context.Context, conn net.Conn) net.Conn {
	return &contextExecConnection{Conn: conn, stop: context.AfterFunc(ctx, func() { _ = conn.Close() })}
}
func (conn *contextExecConnection) Close() error { conn.stop(); return conn.Conn.Close() }
