package wsconn

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// newTestConn is NewConn for options that are valid.
func newTestConn(conn net.Conn, br *bufio.Reader, client bool, opts *Options) *Conn {
	c, err := NewConn(conn, br, client, opts)
	if err != nil {
		panic(err)
	}
	return c
}

// Negative settings that have no meaning fail Validate, NewConn and the
// handshakes; a negative ReadLimit or HandshakeTimeout lifts the limit.
func TestNegativeSettings(t *testing.T) {
	for _, o := range []ClientOptions{
		{Options: Options{ReadBufferSize: -1}},
		{Options: Options{Compression: &Compression{Threshold: -1}}},
	} {
		if err := o.Validate(); err == nil {
			t.Errorf("%+v valid", o)
		}
		if err := (&ServerOptions{Options: o.Options, HandshakeTimeout: o.HandshakeTimeout}).Validate(); err == nil {
			t.Errorf("server %+v valid", o)
		}
	}
	if err := (&ClientOptions{Options: Options{ReadLimit: -1, CloseTimeout: -1}, HandshakeTimeout: -1}).Validate(); err != nil {
		t.Error(err)
	}
	bad := Options{ReadBufferSize: -1}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	if _, err := NewConn(a, nil, false, &bad); err == nil {
		t.Error("NewConn")
	}
	if _, _, err := Client(t.Context(), a, "ws://x/", &ClientOptions{Options: bad}); err == nil {
		t.Error("Client")
	}
	if _, err := Accept(t.Context(), a, &ServerOptions{Options: bad}); err == nil {
		t.Error("Accept")
	}
}

// A zero compression threshold is 128 bytes; 1 compresses every message
// but empty ones.
func TestCompressionThreshold(t *testing.T) {
	if d := (&Compression{}).config(); d.threshold != 128 {
		t.Errorf("zero: %d", d.threshold)
	}
	if d := (&Compression{Threshold: 1}).config(); d.threshold != 1 {
		t.Errorf("1: %d", d.threshold)
	}
}

// Negative buffer and header sizes fail Validate.
func TestNegativeSizes(t *testing.T) {
	if (&Options{ReadBufferSize: -1}).Validate() == nil {
		t.Error("ReadBufferSize")
	}
	if (&ClientOptions{MaxHeaderBytes: -1}).Validate() == nil || (&ServerOptions{MaxHeaderBytes: -1}).Validate() == nil {
		t.Error("MaxHeaderBytes")
	}
}

// A negative close timeout means none: Close still completes the closing
// handshake with a peer that answers.
func TestNegativeCloseTimeout(t *testing.T) {
	srv, cli := pair(t, &ServerOptions{Options: Options{CloseTimeout: -1}}, &ClientOptions{Options: Options{CloseTimeout: -1}, HandshakeTimeout: -1})
	go func() { _, _, _ = srv.ReadMessage() }()
	done := make(chan error, 1)
	go func() { done <- cli.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish")
	}
}
