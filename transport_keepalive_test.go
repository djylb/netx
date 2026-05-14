//go:build !windows

package netx

import (
	"testing"
)

func TestSetTcpKeepAliveParamsSuccess(t *testing.T) {
	client, _, cleanup := tcpPair(t)
	defer cleanup()

	if err := SetTcpKeepAliveParams(client, 10, 3, 5); err != nil {
		t.Fatalf("expected keepalive params set successfully, got error: %v", err)
	}
}

func TestSetTcpKeepAliveParamsOnClosedConn(t *testing.T) {
	client, _, cleanup := tcpPair(t)
	defer cleanup()

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if err := SetTcpKeepAliveParams(client, 10, 3, 5); err == nil {
		t.Fatal("expected error on closed connection, got nil")
	}
}
