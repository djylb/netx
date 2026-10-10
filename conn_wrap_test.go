package netx

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type countedCloseConn struct {
	mu         sync.Mutex
	closeCalls int
}

func (c *countedCloseConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *countedCloseConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *countedCloseConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *countedCloseConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *countedCloseConn) SetDeadline(time.Time) error      { return nil }
func (c *countedCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countedCloseConn) SetWriteDeadline(time.Time) error { return nil }

func (c *countedCloseConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCalls++
	if c.closeCalls > 1 {
		return net.ErrClosed
	}
	return nil
}

func (c *countedCloseConn) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCalls
}

func TestWrapConnCloseAvoidsDoubleClosingObservedConn(t *testing.T) {
	base := &countedCloseConn{}
	wrapped := ObserveConn(base, TrafficObserver{
		OnRead: func(int64) error { return nil },
	})

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if calls := base.Calls(); calls != 1 {
		t.Fatalf("base Close() calls = %d, want 1", calls)
	}
}

func TestWrapConnClosesWrappedOnlyByDefault(t *testing.T) {
	rwc := &countedCloseConn{}
	parent := &countedCloseConn{}
	wrapped := WrapConn(rwc, parent)

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if calls := rwc.Calls(); calls != 1 {
		t.Fatalf("rwc Close() calls = %d, want 1", calls)
	}
	if calls := parent.Calls(); calls != 0 {
		t.Fatalf("parent Close() calls = %d, want 0", calls)
	}
}

func TestWrapConnWithParentCloseClosesWrappedAndParent(t *testing.T) {
	rwc := &countedCloseConn{}
	parent := &countedCloseConn{}
	wrapped := WrapConn(rwc, parent, WithParentClose())

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if calls := rwc.Calls(); calls != 1 {
		t.Fatalf("rwc Close() calls = %d, want 1", calls)
	}
	if calls := parent.Calls(); calls != 1 {
		t.Fatalf("parent Close() calls = %d, want 1", calls)
	}
}

func TestWrapConnWithParentCloseAvoidsDoubleClosingRawWrapper(t *testing.T) {
	base := &countedCloseConn{}
	wrapped := WrapConn(&rawClosingRWC{raw: base}, base, WithParentClose())

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if calls := base.Calls(); calls != 1 {
		t.Fatalf("base Close() calls = %d, want 1", calls)
	}
}

type rawClosingRWC struct {
	raw net.Conn
}

func (r *rawClosingRWC) Read(p []byte) (int, error) {
	if r.raw == nil {
		return 0, net.ErrClosed
	}
	return r.raw.Read(p)
}

func (r *rawClosingRWC) Write(p []byte) (int, error) {
	if r.raw == nil {
		return 0, net.ErrClosed
	}
	return r.raw.Write(p)
}

func (r *rawClosingRWC) Close() error {
	if r.raw == nil {
		return nil
	}
	return r.raw.Close()
}

func (r *rawClosingRWC) RawConn() net.Conn {
	if r == nil {
		return nil
	}
	return r.raw
}

type rawProviderOnly struct {
	raw net.Conn
}

func (r rawProviderOnly) RawConn() net.Conn {
	return r.raw
}

func TestRawConnOfRecursivelyUnwrapsProviders(t *testing.T) {
	base := &countedCloseConn{}
	provider := rawProviderOnly{
		raw: NewTimeoutConn(base, time.Second),
	}

	if got := RawConnOf(provider); got != base {
		t.Fatalf("RawConnOf() = %v, want base conn", got)
	}
}

func TestWrappedConnHelpersHandleNilState(t *testing.T) {
	var nilWrapped *wrappedConn
	assertClosedConnState(t, "nil", nilWrapped)

	malformed := &wrappedConn{}
	assertClosedConnState(t, "malformed", malformed)
}

func TestAddrOverrideConnHelpersHandleNilState(t *testing.T) {
	var nilConn *AddrOverrideConn
	assertClosedRawConnState(t, "nil", nilConn)

	malformed := &AddrOverrideConn{}
	assertClosedRawConnState(t, "malformed", malformed)
}

// pipeCloseCounter counts Close calls on one end of a net.Pipe.
type pipeCloseCounter struct {
	net.Conn
	mu    sync.Mutex
	calls int
}

func (c *pipeCloseCounter) Close() error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *pipeCloseCounter) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func newPipeCloseCounter(t *testing.T) *pipeCloseCounter {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return &pipeCloseCounter{Conn: client}
}

func TestRawConnOfUnwrapsNetConn(t *testing.T) {
	base := newPipeCloseCounter(t)
	tlsConn := tls.Client(base, &tls.Config{InsecureSkipVerify: true})

	if got := RawConnOf(tlsConn); got != base {
		t.Fatalf("RawConnOf(*tls.Conn) = %T, want base conn", got)
	}
	if got := RawConnOf(NewTimeoutConn(tlsConn, time.Second)); got != base {
		t.Fatalf("RawConnOf(TimeoutConn(*tls.Conn)) = %T, want base conn", got)
	}
	if got := RawConnOf((*tls.Conn)(nil)); got != nil {
		t.Fatalf("RawConnOf(nil *tls.Conn) = %v, want nil", got)
	}
	if got := NewTimeoutConn((*tls.Conn)(nil), time.Second).RawConn(); got != nil {
		t.Fatalf("TimeoutConn(nil *tls.Conn).RawConn() = %v, want nil", got)
	}
}

func TestWrapConnWithParentCloseAvoidsDoubleClosingTLSParent(t *testing.T) {
	base := newPipeCloseCounter(t)
	wrapped := WrapConn(tls.Client(base, &tls.Config{InsecureSkipVerify: true}), base, WithParentClose())

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if calls := base.Calls(); calls != 1 {
		t.Fatalf("base Close() calls = %d, want 1", calls)
	}
}

func TestWrapConnWithParentCloseAvoidsDoubleClosingParentBelowTLS(t *testing.T) {
	base := &countedCloseConn{}
	parent := NewTimeoutConn(base, time.Second)
	wrapped := WrapConn(tls.Client(parent, &tls.Config{InsecureSkipVerify: true}), parent, WithParentClose())

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if calls := base.Calls(); calls != 1 {
		t.Fatalf("base Close() calls = %d, want 1", calls)
	}
}

func TestWrapConnWithParentCloseIgnoresParentClosedThroughRWC(t *testing.T) {
	t.Run("sibling wrapper", func(t *testing.T) {
		base := &countedCloseConn{}
		wrapped := WrapConn(NewTimeoutConn(base, time.Second), NewAddrOverrideConn(base, nil, nil), WithParentClose())

		if err := wrapped.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		// The parent is a different wrapper, so its own Close must still run.
		if calls := base.Calls(); calls != 2 {
			t.Fatalf("base Close() calls = %d, want 2", calls)
		}
	})

	t.Run("tls parent", func(t *testing.T) {
		base := &countedCloseConn{}
		tlsConn := tls.Client(base, &tls.Config{InsecureSkipVerify: true})
		wrapped := WrapConn(NewTimeoutConn(tlsConn, time.Second), tlsConn, WithParentClose())

		if err := wrapped.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if calls := base.Calls(); calls != 1 {
			t.Fatalf("base Close() calls = %d, want 1", calls)
		}
	})
}

// cyclicRawConn exposes a RawConn chain that loops back on itself.
type cyclicRawConn struct {
	countedCloseConn
	next net.Conn
}

func (c *cyclicRawConn) RawConn() net.Conn { return c.next }

func TestRawConnOfStopsOnCyclicProviders(t *testing.T) {
	a := &cyclicRawConn{}
	b := &cyclicRawConn{next: a}
	a.next = b

	if got := RawConnOf(a); got == nil {
		t.Fatal("RawConnOf(cycle) = nil, want a conn from the cycle")
	}
	parent := &countedCloseConn{}
	if err := WrapConn(a, parent, WithParentClose()).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if calls := parent.Calls(); calls != 1 {
		t.Fatalf("parent Close() calls = %d, want 1", calls)
	}
}

// selfConn is a comparable struct type whose interface field holds a value
// that is not comparable, and whose RawConn returns a value of its own type.
type selfConn struct {
	net.Conn
	tag any
}

func (c selfConn) RawConn() net.Conn { return selfConn{Conn: c.Conn, tag: c.tag} }

func TestRawConnOfHandlesUncomparableValues(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := selfConn{Conn: a, tag: []byte("not comparable")}
	if got := RawConnOf(c); got == nil {
		t.Fatal("RawConnOf() = nil")
	}
	w := WrapConn(c, c, WithParentClose())
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
