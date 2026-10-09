package netx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func TestPrefixConnReplaysPrefix(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		_, _ = server.Write([]byte("world"))
		_ = server.Close()
	}()

	c := NewPrefixConn(client, []byte("hello "))
	buf := make([]byte, 3)
	var got []byte
	for {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if string(got) != "hello world" {
		t.Fatalf("read %q, want %q", got, "hello world")
	}
	if RawConnOf(c) != client {
		t.Fatalf("RawConnOf() = %v, want the wrapped conn", RawConnOf(c))
	}
	if !errors.Is(c.CloseWrite(), errors.ErrUnsupported) {
		t.Fatal("CloseWrite() on a pipe should be unsupported")
	}
}

func TestPrefixConnWriteToUsesWrappedConn(t *testing.T) {
	a, b := tcpPair(t)
	defer func() { _ = a.Close() }()
	go func() {
		_, _ = b.Write([]byte(" tail"))
		_ = b.Close()
	}()

	c := NewPrefixConn(a, []byte("head"))
	var out bytes.Buffer
	n, err := c.WriteTo(&out)
	if err != nil || n != 9 || out.String() != "head tail" {
		t.Fatalf("WriteTo() = %d, %v, %q", n, err, out.String())
	}
	if n, err := NewPrefixConn(a, nil).Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("Read() after EOF = %d, %v", n, err)
	}
}

func TestWrappersForwardCloseWrite(t *testing.T) {
	for name, wrap := range map[string]func(net.Conn) net.Conn{
		"TimeoutConn":      func(c net.Conn) net.Conn { return NewTimeoutConn(c, 0) },
		"AddrOverrideConn": func(c net.Conn) net.Conn { return NewAddrOverrideConn(c, nil, nil) },
		"FramedConn":       func(c net.Conn) net.Conn { return NewFramedConn(c) },
		"TeeConn":          func(c net.Conn) net.Conn { return NewTeeConn(c, 0) },
		"PrefixConn":       func(c net.Conn) net.Conn { return NewPrefixConn(c, []byte("x")) },
		"ObserveConn": func(c net.Conn) net.Conn {
			return ObserveConn(c, TrafficObserver{OnWrite: func(int64) error { return nil }})
		},
		"WrapConn": func(c net.Conn) net.Conn { return WrapConn(c, c) },
	} {
		t.Run(name, func(t *testing.T) {
			a, b := tcpPair(t)
			defer func() { _ = a.Close() }()
			defer func() { _ = b.Close() }()
			c := wrap(a).(interface{ CloseWrite() error })
			if err := c.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite() error = %v", err)
			}
			if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("peer Read() error = %v, want EOF", err)
			}
			// The other direction still works.
			go func() { _, _ = b.Write([]byte("k")) }()
			if _, err := io.ReadFull(a, make([]byte, 1)); err != nil {
				t.Fatalf("Read() after CloseWrite error = %v", err)
			}
		})
	}
}

func TestIsClosed(t *testing.T) {
	for _, err := range []error{
		net.ErrClosed,
		&net.OpError{Op: "read", Err: net.ErrClosed},
		io.ErrClosedPipe,
		errors.New("read tcp 127.0.0.1:1: use of closed network connection"),
	} {
		if !IsClosed(err) || NetErrorKind(err) != "closed" {
			t.Errorf("IsClosed(%v) = false or kind %q", err, NetErrorKind(err))
		}
	}
	for _, err := range []error{nil, io.EOF, errors.New("boom")} {
		if IsClosed(err) {
			t.Errorf("IsClosed(%v) = true", err)
		}
	}
}
