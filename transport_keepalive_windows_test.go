//go:build windows

package netx

import (
	"errors"
	"net"
	"testing"
)

func TestSetTcpKeepAliveParamsRejectsInvalidValuesOnWindows(t *testing.T) {
	client, _, cleanup := tcpPair(t)
	defer cleanup()

	if err := SetTcpKeepAliveParams(client, 0, 3, 1); !errors.Is(err, errInvalidKeepAliveParams) {
		t.Fatalf("idle=0 error = %v, want %v", err, errInvalidKeepAliveParams)
	}
	if err := SetTcpKeepAliveParams(client, 10, -1, 1); !errors.Is(err, errInvalidKeepAliveParams) {
		t.Fatalf("intvl=-1 error = %v, want %v", err, errInvalidKeepAliveParams)
	}
	if err := SetTcpKeepAliveParams(client, 10, 3, 0); !errors.Is(err, errInvalidKeepAliveParams) {
		t.Fatalf("probes=0 error = %v, want %v", err, errInvalidKeepAliveParams)
	}
}

func TestSetTcpKeepAliveParamsRejectsNilConnOnWindows(t *testing.T) {
	if err := SetTcpKeepAliveParams(nil, 10, 3, 1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil conn error = %v, want %v", err, net.ErrClosed)
	}
}

func TestSetTcpKeepAliveParamsSuccessOnWindows(t *testing.T) {
	client, _, cleanup := tcpPair(t)
	defer cleanup()

	if err := SetTcpKeepAliveParams(client, 10, 3, 1); err != nil {
		t.Fatalf("SetTcpKeepAliveParams() error = %v", err)
	}
}
