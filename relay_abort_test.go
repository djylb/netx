package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// readReset reads c to its end and fails unless the end is a reset.
func readReset(t *testing.T, label string, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadAll(c)
	if !IsConnReset(err) {
		t.Fatalf("%s: read to the end = %v, want a reset", label, err)
	}
}

// relayPairs starts a Relay between client and backend through two TCP
// pairs, the backend's end passed through wrap, and returns its result.
func relayPairs(t *testing.T, ctx context.Context, wrap func(net.Conn) net.Conn, opts ...RelayOption) (client, backend net.Conn, done <-chan error) {
	t.Helper()
	client, relayA := tcpPair(t)
	relayB, backend := tcpPair(t)
	ch := make(chan error, 1)
	go func() {
		_, _, err := Relay(ctx, relayA, wrap(relayB), opts...)
		ch <- err
	}()
	return client, backend, ch
}

func plain(c net.Conn) net.Conn { return c }

func timeoutWrap(c net.Conn) net.Conn { return NewTimeoutConn(c, 10*time.Second) }

// A reset from one peer reaches the other as a reset, not as an end of
// data, also beneath a wrapper.
func TestRelayPassesResetOn(t *testing.T) {
	for name, wrap := range map[string]func(net.Conn) net.Conn{"plain": plain, "wrapped": timeoutWrap} {
		t.Run(name, func(t *testing.T) {
			client, backend, done := relayPairs(t, context.Background(), wrap, WithRelayHalfClose())
			if _, err := backend.Write([]byte("partial")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len("partial"))
			if _, err := io.ReadFull(client, buf); err != nil {
				t.Fatal(err)
			}
			_ = backend.(*net.TCPConn).SetLinger(0)
			_ = backend.Close()
			readReset(t, "client", client)
			if err := <-done; err == nil {
				t.Fatal("Relay after a reset = nil error")
			}
		})
	}
}

// An error of a hook in one direction resets both peers.
func TestRelayErrorResetsBothPeers(t *testing.T) {
	errCut := errors.New("allowance used up")
	flow := &RelayFlow{Done: func(int64) error { return errCut }}
	for name, wrap := range map[string]func(net.Conn) net.Conn{"plain": plain, "wrapped": timeoutWrap} {
		t.Run(name, func(t *testing.T) {
			client, backend, done := relayPairs(t, context.Background(), wrap, WithRelayHalfClose(), WithRelayFlows(flow, nil))
			if _, err := client.Write([]byte("upload")); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, errCut) {
				t.Fatalf("Relay = %v, want %v", err, errCut)
			}
			readReset(t, "client", client)
			readReset(t, "backend", backend)
		})
	}
}

// The end of the context resets both peers.
func TestRelayContextResetsBothPeers(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	errKick := errors.New("kicked")
	client, backend, done := relayPairs(t, ctx, plain, WithRelayHalfClose())
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(backend, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	cancel(errKick)
	if err := <-done; !errors.Is(err, errKick) {
		t.Fatalf("Relay = %v, want %v", err, errKick)
	}
	readReset(t, "client", client)
	readReset(t, "backend", backend)
}

// A normal end still closes with FIN: both peers read EOF.
func TestRelayEOFClosesGracefully(t *testing.T) {
	client, backend, done := relayPairs(t, context.Background(), plain)
	_ = client.(*net.TCPConn).CloseWrite()
	if err := <-done; err != nil {
		t.Fatalf("Relay = %v", err)
	}
	for label, c := range map[string]net.Conn{"client": client, "backend": backend} {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadAll(c); err != nil {
			t.Fatalf("%s: read to the end = %v, want EOF", label, err)
		}
	}
}

// abortEnd is an end that records Abort and Close.
type abortEnd struct {
	cause   error
	closed  chan struct{}
	mu      sync.Mutex
	aborts  int
	closes  int
	closeMu sync.Once
}

func newAbortEnd() *abortEnd { return &abortEnd{closed: make(chan struct{})} }

func (e *abortEnd) Read([]byte) (int, error) {
	<-e.closed
	return 0, net.ErrClosed
}
func (e *abortEnd) Write(p []byte) (int, error) { return len(p), nil }
func (e *abortEnd) Close() error {
	e.mu.Lock()
	e.closes++
	e.mu.Unlock()
	e.closeMu.Do(func() { close(e.closed) })
	return nil
}
func (e *abortEnd) Abort(cause error) {
	e.mu.Lock()
	e.aborts++
	e.cause = cause
	e.mu.Unlock()
	e.closeMu.Do(func() { close(e.closed) })
}

func (e *abortEnd) counts() (aborts, closes int, cause error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.aborts, e.closes, e.cause
}

// An Aborter end is aborted with the cause, also beneath a wrapper of this
// package and a RelayEnd, instead of closed; a normal end closes it.
func TestRelayAbortsAborters(t *testing.T) {
	errKick := errors.New("kicked")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errKick)
	a, b := newAbortEnd(), newAbortEnd()
	inner := newAbortEnd()
	wrapped := WrapConn(inner, nil)
	if _, _, err := Relay(ctx, a, &RelayEnd{Reader: wrapped, Writer: b}); !errors.Is(err, errKick) {
		t.Fatalf("Relay = %v, want %v", err, errKick)
	}
	for label, e := range map[string]*abortEnd{"a": a, "beneath a wrapper": inner, "b": b} {
		if aborts, _, cause := e.counts(); aborts != 1 || !errors.Is(cause, errKick) {
			t.Fatalf("%s: %d Aborts with %v, want 1 with %v", label, aborts, cause, errKick)
		}
	}
	if _, closes, _ := a.counts(); closes != 0 {
		t.Fatalf("aborted end closed %d times, want 0", closes)
	}
}

// AbortFunc replaces what a RelayEnd's Abort does.
func TestRelayEndAbortFunc(t *testing.T) {
	var got error
	cause := errors.New("cut")
	e := &RelayEnd{AbortFunc: func(c error) { got = c }, CloseFunc: func() error { t.Fatal("Close called"); return nil }}
	Abort(e, cause)
	if !errors.Is(got, cause) {
		t.Fatalf("AbortFunc got %v, want %v", got, cause)
	}
}

// Abort resets a TCP connection beneath wrappers and tolerates nil.
func TestAbortResetsTCP(t *testing.T) {
	Abort(nil, nil)
	Abort((*net.TCPConn)(nil), nil)
	local, peer := tcpPair(t)
	Abort(NewTimeoutConn(local, time.Minute), errors.New("cut"))
	readReset(t, "peer", peer)
}
