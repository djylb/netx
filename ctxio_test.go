package netx

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoWithContext(t *testing.T) {
	a, b := tcpPair(t)
	// Success clears the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	if err := DoWithContext(ctx, a, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	cancel()
	// A deadline ends a blocked read with the context's error.
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := DoWithContext(ctx, a, func() error {
		_, err := a.Read(make([]byte, 1))
		return err
	})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: error = %v", err)
	}
	// Cancelling interrupts too. A failure leaves the deadline set.
	_ = a.SetDeadline(time.Time{})
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if err := DoWithContext(ctx, a, func() error {
		_, err := a.Read(make([]byte, 1))
		return err
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: error = %v", err)
	}
	// fn's own error comes back; the connection stays usable once cleared.
	errOwn := errors.New("bad reply")
	if err := DoWithContext(context.Background(), a, func() error { return errOwn }); !errors.Is(err, errOwn) {
		t.Fatalf("own error = %v", err)
	}
	_ = a.SetDeadline(time.Time{})
	go func() { _, _ = b.Write([]byte("x")) }()
	if _, err := io.ReadFull(a, make([]byte, 1)); err != nil {
		t.Fatalf("connection unusable after DoWithContext: %v", err)
	}
	// A connection without deadlines is closed to interrupt it.
	p, q := net.Pipe()
	defer func() { _ = q.Close() }()
	nd := &noDeadlinePipe{p}
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if err := DoWithContext(ctx, nd, func() error {
		_, err := nd.Read(make([]byte, 1))
		return err
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("no deadlines: error = %v", err)
	}
}

type noDeadlinePipe struct{ net.Conn }

func (noDeadlinePipe) SetDeadline(time.Time) error { return errors.ErrUnsupported }

// tlsShaped has the methods by which CloseBeneathTLS knows a TLS connection
// of another implementation.
type tlsShaped struct {
	net.Conn
}

func (c tlsShaped) NetConn() net.Conn                        { return c.Conn }
func (c tlsShaped) HandshakeContext(_ context.Context) error { return nil }

// borrower has a NetConn method but no handshake: what it returns is not its
// own to close.
type borrower struct {
	net.Conn
}

func (c borrower) NetConn() net.Conn { return c.Conn }

func TestCloseBeneathTLS(t *testing.T) {
	isClosed := func(c net.Conn) bool {
		_, err := c.Write([]byte{0})
		return errors.Is(err, io.ErrClosedPipe)
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	go func() { _, _ = io.Copy(io.Discard, b) }()
	CloseBeneathTLS(borrower{a})
	if isClosed(a) {
		t.Fatal("closed the connection beneath a wrapper without a handshake")
	}
	CloseBeneathTLS(tlsShaped{a})
	if !isClosed(a) {
		t.Fatal("left the connection beneath a TLS-shaped connection open")
	}
	var nilTLS *tls.Conn
	CloseBeneathTLS(nilTLS) // must not panic
	CloseBeneathTLS(nil)
}

// closeCounter counts Close calls.
type closeCounter struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeCounter) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// DoHandshake closes c on failure, after closing the connection beneath a
// TLS c when the exchange timed out, and leaves it open on success;
// DoWithContext leaves it open and clears its deadline either way.
func TestDoHandshakeOwnership(t *testing.T) {
	errFail := errors.New("fail")
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := &closeCounter{Conn: a}
	if err := DoWithContext(context.Background(), c, func() error { return errFail }); !errors.Is(err, errFail) || c.closes.Load() != 0 {
		t.Fatalf("DoWithContext() = %v with %d closes, want fn's error and c open", err, c.closes.Load())
	}
	if err := DoHandshake(context.Background(), c, func() error { return nil }); err != nil || c.closes.Load() != 0 {
		t.Fatalf("DoHandshake() = %v with %d closes, want success and c open", err, c.closes.Load())
	}
	if err := DoHandshake(context.Background(), c, func() error { return errFail }); !errors.Is(err, errFail) || c.closes.Load() != 1 {
		t.Fatalf("DoHandshake() = %v with %d closes, want fn's error and c closed", err, c.closes.Load())
	}

	raw, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	shaped := &closeCounter{Conn: tlsShaped{raw}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := DoHandshake(ctx, shaped, func() error {
		_, err := raw.Read(make([]byte, 1)) // the peer never writes
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) || shaped.closes.Load() != 1 {
		t.Fatalf("DoHandshake() = %v with %d closes, want the deadline and c closed", err, shaped.closes.Load())
	}
	if _, err := raw.Write([]byte{0}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("connection beneath a TLS c after a timeout: Write() = %v, want it closed", err)
	}
}
