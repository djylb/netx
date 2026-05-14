//go:build !windows

package netx

import (
	"testing"
	"time"
)

func TestSetTCPKeepAliveSuccess(t *testing.T) {
	client, _, cleanup := tcpPair(t)
	defer cleanup()

	if err := SetTCPKeepAlive(client, TCPKeepAliveConfig{Idle: 10 * time.Second, Interval: 3 * time.Second, Count: 5}); err != nil {
		t.Fatalf("expected keepalive params set successfully, got error: %v", err)
	}
}

func TestSetTCPKeepAliveOnClosedConn(t *testing.T) {
	client, _, cleanup := tcpPair(t)
	defer cleanup()

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if err := SetTCPKeepAlive(client, TCPKeepAliveConfig{Idle: 10 * time.Second, Interval: 3 * time.Second, Count: 5}); err == nil {
		t.Fatal("expected error on closed connection, got nil")
	}
}
