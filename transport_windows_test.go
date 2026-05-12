//go:build windows

package netx

import (
	"errors"
	"net"
	"testing"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	acceptCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			errCh <- net.InvalidAddrError("accepted connection is not *net.TCPConn")
			_ = conn.Close()
			return
		}
		acceptCh <- tcpConn
	}()

	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	client, ok := clientRaw.(*net.TCPConn)
	if !ok {
		_ = clientRaw.Close()
		t.Fatal("dialed connection is not *net.TCPConn")
	}

	var server *net.TCPConn
	select {
	case server = <-acceptCh:
	case err = <-errCh:
		_ = client.Close()
		t.Fatalf("accept tcp: %v", err)
	}

	cleanup := func() {
		_ = client.Close()
		_ = server.Close()
		_ = ln.Close()
	}
	return client, server, cleanup
}

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
