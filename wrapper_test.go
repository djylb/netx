package netx

import (
	"errors"
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
	wrapped := WrapNetConnWithTrafficObserver(base, TrafficObserver{
		OnRead: func(int64) error { return nil },
	})

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if calls := base.Calls(); calls != 1 {
		t.Fatalf("base Close() calls = %d, want 1", calls)
	}
}

func TestWrapConnCloseAvoidsDoubleClosingRawWrapper(t *testing.T) {
	base := &countedCloseConn{}
	wrapped := WrapConn(&rawClosingRWC{raw: base}, base)

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

func (r *rawClosingRWC) GetRawConn() net.Conn {
	if r == nil {
		return nil
	}
	return r.raw
}

func TestWrappedConnHelpersHandleNilState(t *testing.T) {
	var nilWrapped *wrappedConn
	if _, err := nilWrapped.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := nilWrapped.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilWrapped.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilWrapped.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilWrapped.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if got := nilWrapped.LocalAddr(); got != nil {
		t.Fatalf("nil LocalAddr() = %v, want nil", got)
	}
	if got := nilWrapped.RemoteAddr(); got != nil {
		t.Fatalf("nil RemoteAddr() = %v, want nil", got)
	}

	malformed := &wrappedConn{}
	if _, err := malformed.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := malformed.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if got := malformed.LocalAddr(); got != nil {
		t.Fatalf("malformed LocalAddr() = %v, want nil", got)
	}
	if got := malformed.RemoteAddr(); got != nil {
		t.Fatalf("malformed RemoteAddr() = %v, want nil", got)
	}
}

func TestAddrOverrideConnHelpersHandleNilState(t *testing.T) {
	var nilConn *AddrOverrideConn
	if got := nilConn.GetRawConn(); got != nil {
		t.Fatalf("nil GetRawConn() = %v, want nil", got)
	}
	if got := nilConn.LocalAddr(); got != nil {
		t.Fatalf("nil LocalAddr() = %v, want nil", got)
	}
	if got := nilConn.RemoteAddr(); got != nil {
		t.Fatalf("nil RemoteAddr() = %v, want nil", got)
	}
	if _, err := nilConn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := nilConn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.Close(); err != nil {
		t.Fatalf("nil Close() error = %v, want nil", err)
	}

	malformed := &AddrOverrideConn{}
	if got := malformed.GetRawConn(); got != nil {
		t.Fatalf("malformed GetRawConn() = %v, want nil", got)
	}
	if got := malformed.LocalAddr(); got != nil {
		t.Fatalf("malformed LocalAddr() = %v, want nil", got)
	}
	if got := malformed.RemoteAddr(); got != nil {
		t.Fatalf("malformed RemoteAddr() = %v, want nil", got)
	}
	if _, err := malformed.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := malformed.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.Close(); err != nil {
		t.Fatalf("malformed Close() error = %v, want nil", err)
	}
}
