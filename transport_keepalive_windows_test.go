//go:build windows

package netx

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestSetTCPKeepAliveRejectsInvalidValuesOnWindows(t *testing.T) {
	client, _, cleanup := tcpPair(t)
	defer cleanup()

	if err := SetTCPKeepAlive(client, TCPKeepAliveConfig{Interval: 3 * time.Second, Count: 1}); !errors.Is(err, ErrInvalidTCPKeepAliveConfig) {
		t.Fatalf("idle=0 error = %v, want %v", err, ErrInvalidTCPKeepAliveConfig)
	}
	if err := SetTCPKeepAlive(client, TCPKeepAliveConfig{Idle: 10 * time.Second, Interval: -time.Second, Count: 1}); !errors.Is(err, ErrInvalidTCPKeepAliveConfig) {
		t.Fatalf("interval=-1 error = %v, want %v", err, ErrInvalidTCPKeepAliveConfig)
	}
	if err := SetTCPKeepAlive(client, TCPKeepAliveConfig{Idle: 10 * time.Second, Interval: 3 * time.Second}); !errors.Is(err, ErrInvalidTCPKeepAliveConfig) {
		t.Fatalf("count=0 error = %v, want %v", err, ErrInvalidTCPKeepAliveConfig)
	}
}

func TestSetTCPKeepAliveRejectsNilConnOnWindows(t *testing.T) {
	if err := SetTCPKeepAlive(nil, TCPKeepAliveConfig{Idle: 10 * time.Second, Interval: 3 * time.Second, Count: 1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil conn error = %v, want %v", err, net.ErrClosed)
	}
}

func TestSetTCPKeepAliveSuccessOnWindows(t *testing.T) {
	client, _, cleanup := tcpPair(t)
	defer cleanup()

	if err := SetTCPKeepAlive(client, TCPKeepAliveConfig{Idle: 10 * time.Second, Interval: 3 * time.Second, Count: 1}); err != nil {
		t.Fatalf("SetTCPKeepAlive() error = %v", err)
	}
}
