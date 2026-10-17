package netx

import (
	"context"
	"errors"
	"io"
	"net"
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
