package netx

import (
	"errors"
	"io"
	"net"
	"reflect"
	"time"
)

type wrappedConn struct {
	rwc         io.ReadWriteCloser
	parent      net.Conn
	closeParent bool
}

type wrapOptions struct {
	closeParent bool
}

// RawConnProvider is implemented by wrappers that can expose their underlying net.Conn.
// RawConnOf also follows the standard library's NetConn() net.Conn method, as
// implemented by *tls.Conn.
type RawConnProvider interface {
	RawConn() net.Conn
}

// WrapOption configures WrapConn.
type WrapOption func(*wrapOptions)

// WithParentClose makes WrapConn close parent after closing rwc.
// parent is skipped when rwc unwraps to it through RawConn or NetConn, and
// net.ErrClosed from parent is ignored because rwc may already have closed it.
func WithParentClose() WrapOption {
	return func(o *wrapOptions) {
		o.closeParent = true
	}
}

// RawConnOf returns v's underlying net.Conn when it is available.
// It follows RawConn() and NetConn() chains to the innermost connection.
func RawConnOf(v any) net.Conn {
	return rawConnOf(v)
}

// WrapConn exposes rwc as a net.Conn using parent for addresses and deadlines.
// Closing the returned connection closes rwc. Use WithParentClose to also close parent.
func WrapConn(rwc io.ReadWriteCloser, parent net.Conn, opts ...WrapOption) net.Conn {
	cfg := newWrapOptions(opts)
	if parent == nil {
		parent = rawConnOf(rwc)
	}
	return &wrappedConn{rwc: rwc, parent: parent, closeParent: cfg.closeParent}
}

func newWrapOptions(opts []WrapOption) wrapOptions {
	var cfg wrapOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

func (w *wrappedConn) Read(b []byte) (int, error) {
	if w == nil || w.rwc == nil {
		return 0, net.ErrClosed
	}
	return w.rwc.Read(b)
}

func (w *wrappedConn) Write(b []byte) (int, error) {
	if w == nil || w.rwc == nil {
		return 0, net.ErrClosed
	}
	return w.rwc.Write(b)
}

func (w *wrappedConn) Close() error {
	if w == nil {
		return nil
	}
	var err1, err2 error
	if w.rwc != nil {
		err1 = w.rwc.Close()
	}
	if w.closeParent && w.parent != nil && !sameWrappedParent(w.rwc, w.parent) {
		// rwc may wrap parent without exposing it, so parent can already be closed.
		if err2 = w.parent.Close(); errors.Is(err2, net.ErrClosed) {
			err2 = nil
		}
	}
	return errors.Join(err1, err2)
}

// CloseWrite shuts down the writing side of rwc; see TimeoutConn.CloseWrite.
func (w *wrappedConn) CloseWrite() error {
	if w == nil || w.rwc == nil {
		return net.ErrClosed
	}
	return closeWrite(w.rwc)
}

func (w *wrappedConn) LocalAddr() net.Addr {
	if w == nil || w.parent == nil {
		return nil
	}
	return w.parent.LocalAddr()
}

func (w *wrappedConn) RemoteAddr() net.Addr {
	if w == nil || w.parent == nil {
		return nil
	}
	return w.parent.RemoteAddr()
}

func (w *wrappedConn) SetDeadline(t time.Time) error {
	if w == nil || w.parent == nil {
		return net.ErrClosed
	}
	return w.parent.SetDeadline(t)
}

func (w *wrappedConn) SetReadDeadline(t time.Time) error {
	if w == nil || w.parent == nil {
		return net.ErrClosed
	}
	return w.parent.SetReadDeadline(t)
}

func (w *wrappedConn) SetWriteDeadline(t time.Time) error {
	if w == nil || w.parent == nil {
		return net.ErrClosed
	}
	return w.parent.SetWriteDeadline(t)
}

func (w *wrappedConn) RawConn() net.Conn {
	if w == nil {
		return nil
	}
	if raw := rawConnOf(w.parent); raw != nil {
		return raw
	}
	return rawConnOf(w.rwc)
}

func rawConnOf(v any) net.Conn {
	return rawConnOfDepth(v, 0)
}

// maxUnwrapDepth bounds RawConn/NetConn chains so cyclic wrappers cannot loop forever.
const maxUnwrapDepth = 16

// nextConn returns the connection that v wraps, if v exposes one.
// The returned connection is borrowed; inspecting it does not transfer ownership.
func nextConn(v any) (net.Conn, bool) {
	switch getter := v.(type) {
	case RawConnProvider:
		return getter.RawConn(), true
	case interface{ NetConn() net.Conn }:
		// *tls.Conn.NetConn does not accept a nil receiver.
		if rv := reflect.ValueOf(getter); rv.Kind() == reflect.Pointer && rv.IsNil() {
			return nil, true
		}
		return getter.NetConn(), true
	}
	return nil, false
}

func rawConnOfDepth(v any, depth int) net.Conn {
	if v == nil {
		return nil
	}
	// Unwrapping only borrows connections; their owner remains responsible for closing them.
	//noinspection GoResourceLeak
	if raw, ok := nextConn(v); ok {
		if raw == nil {
			return nil
		}
		if conn, ok := v.(net.Conn); ok && sameNetConn(raw, conn) {
			return raw
		}
		if depth >= maxUnwrapDepth {
			return raw
		}
		if unwrapped := rawConnOfDepth(raw, depth+1); unwrapped != nil {
			return unwrapped
		}
		return raw
	}
	if conn, ok := v.(net.Conn); ok {
		return conn
	}
	return nil
}

// sameWrappedParent reports whether parent is rwc itself or any connection
// reachable from rwc through RawConn or NetConn, so closing rwc closes parent.
func sameWrappedParent(rwc io.ReadWriteCloser, parent net.Conn) bool {
	if rwc == nil || parent == nil {
		return false
	}
	var cur any = rwc
	for depth := 0; depth <= maxUnwrapDepth; depth++ {
		conn, isConn := cur.(net.Conn)
		if isConn && sameNetConn(conn, parent) {
			return true
		}
		// This ownership check must not close the borrowed connection.
		//noinspection GoResourceLeak
		next, ok := nextConn(cur)
		if !ok || next == nil || (isConn && sameNetConn(next, conn)) {
			return false
		}
		cur = next
	}
	return false
}

func sameNetConn(a, b net.Conn) bool {
	if a == nil || b == nil {
		return false
	}
	av := reflect.ValueOf(a)
	bv := reflect.ValueOf(b)
	// Value.Comparable also looks at the values in interface fields, which
	// Type.Comparable does not and on which Equal would panic.
	if av.Type() != bv.Type() || !av.Comparable() || !bv.Comparable() {
		return false
	}
	return av.Equal(bv)
}
