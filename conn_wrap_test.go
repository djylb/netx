package netx

import (
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
