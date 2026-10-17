package netx

import (
	"errors"
	"io"
	"net"
	"reflect"
	"slices"
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

// WrapOption configures WrapConn.
type WrapOption func(*wrapOptions)

// WithWrapParentClose makes WrapConn close parent after closing rwc.
// parent is skipped when rwc unwraps to it through NetConn, and
// net.ErrClosed from parent is ignored because rwc may already have closed it.
func WithWrapParentClose() WrapOption {
	return func(o *wrapOptions) {
		o.closeParent = true
	}
}

// InnermostConn returns the innermost connection beneath v: it follows the
// wrappers of this package and the NetConn() net.Conn methods of others,
// such as *tls.Conn's, which return the connection one layer down. It
// returns v itself when v wraps nothing, and nil for a nil connection, also
// a nil pointer such as a nil *net.TCPConn, and for a value that is not a
// connection. The connection is borrowed: v's owner still closes it.
func InnermostConn(v any) net.Conn {
	return rawConnOf(v)
}

// ConnAs returns the first connection of type T in the chain beneath v, v
// included, as errors.As does for errors: through the wrappers of this
// package and NetConn methods, such as to find the *tls.Conn or
// *TimeoutConn beneath other wrappers.
func ConnAs[T any](v any) (T, bool) {
	var seen [8]any
	return connAs[T](v, 0, seen[:0])
}

func connAs[T any](v any, depth int, seen []any) (T, bool) {
	var zero T
	if v == nil || isNilPointer(v) {
		return zero, false
	}
	if t, ok := v.(T); ok {
		return t, true
	}
	if first, second, ok := layersOf(v); ok {
		if slices.Contains(seen, v) {
			return zero, false
		}
		seen = append(seen, v)
		for _, inner := range [...]any{first, second} {
			if t, ok := connAs[T](inner, depth, seen); ok {
				return t, true
			}
		}
		return zero, false
	}
	// Only looked at, not owned.
	//noinspection GoResourceLeak
	next, ok := nextConn(v)
	if !ok || next == nil || depth >= maxUnwrapDepth {
		return zero, false
	}
	if conn, isConn := v.(net.Conn); isConn && sameNetConn(next, conn) {
		return zero, false
	}
	return connAs[T](next, depth+1, seen)
}

// WrapConn exposes rwc as a net.Conn using parent for addresses and deadlines.
// A nil parent is rwc itself when it is a net.Conn, so that its own wrappers
// keep their addresses and deadlines, and otherwise the connection beneath it.
// Closing the returned connection closes rwc. Use WithWrapParentClose to also close parent.
func WrapConn(rwc io.ReadWriteCloser, parent net.Conn, opts ...WrapOption) net.Conn {
	cfg := newWrapOptions(opts)
	if parent == nil {
		if c, ok := rwc.(net.Conn); ok {
			parent = c
		} else {
			// Borrowed: closing the result closes rwc, and parent only with
			// WithWrapParentClose.
			//noinspection GoResourceLeak
			parent = rawConnOf(rwc)
		}
	}
	if isNilPointer(parent) {
		parent = nil
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

func (w *wrappedConn) innerReader() io.Reader {
	if w == nil {
		return nil
	}
	return w.rwc
}

// NetConn returns the connection whose addresses and deadlines w uses.
func (w *wrappedConn) NetConn() net.Conn {
	if w == nil {
		return nil
	}
	return w.parent
}

func rawConnOf(v any) net.Conn {
	var seen [8]any
	return rawConnOfDepth(v, 0, seen[:0])
}

// maxUnwrapDepth bounds NetConn chains so cyclic wrappers cannot loop forever.
const maxUnwrapDepth = 16

// nextConn returns the connection that v wraps, if v exposes one.
// The returned connection is borrowed; inspecting it does not transfer ownership.
func nextConn(v any) (net.Conn, bool) {
	switch getter := v.(type) {
	case interface{ NetConn() net.Conn }:
		// *tls.Conn.NetConn does not accept a nil receiver.
		if isNilPointer(getter) {
			return nil, true
		}
		return getter.NetConn(), true
	}
	return nil, false
}

// isNilPointer reports whether v is a nil pointer in a non-nil interface,
// such as a nil *net.TCPConn passed as a net.Conn.
func isNilPointer(v any) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// layersOf returns what a wrapper of this package wraps, one layer down and
// in the order unwrapping looks at it, without their NetConn methods, so that
// a cycle through them is seen and both sides of a WrapConn are looked at.
// Only these types match, not types that embed them and may have a NetConn
// of their own.
func layersOf(v any) (first, second any, ok bool) {
	switch c := v.(type) {
	case *PrefixConn:
		if c != nil {
			return c.conn, nil, true
		}
	case *AddrOverrideConn:
		if c != nil {
			return c.conn, nil, true
		}
	case *TimeoutConn:
		if c != nil {
			return c.conn, nil, true
		}
	case *FramedConn:
		if c != nil {
			return c.conn, nil, true
		}
	case *RecordingConn:
		if c != nil {
			return c.conn(), nil, true
		}
	case *observedReadWriteCloser:
		if c != nil {
			return c.rwc, nil, true
		}
	case *wrappedConn:
		if c != nil {
			return c.parent, c.rwc, true
		}
	case *trackedConn:
		if c != nil {
			return c.conn, nil, true
		}
	default:
		return nil, nil, false
	}
	return nil, nil, true // a nil wrapper
}

// rawConnOfDepth unwraps v. depth counts the NetConn calls of
// other packages' wrappers, which may return a new wrapper each time, and
// seen holds this package's wrappers on the way, whose fields a caller may
// have pointed back at them; either way a cycle stops.
func rawConnOfDepth(v any, depth int, seen []any) net.Conn {
	if v == nil {
		return nil
	}
	if first, second, ok := layersOf(v); ok {
		if slices.Contains(seen, v) {
			c, _ := v.(net.Conn)
			return c
		}
		seen = append(seen, v)
		for _, inner := range [...]any{first, second} {
			if raw := rawConnOfDepth(inner, depth, seen); raw != nil {
				return raw
			}
		}
		return nil
	}
	// Unwrapping only borrows connections; their owner remains responsible for closing them.
	//noinspection GoResourceLeak
	if raw, ok := nextConn(v); ok {
		if raw == nil || isNilPointer(raw) {
			return nil
		}
		if conn, ok := v.(net.Conn); ok && sameNetConn(raw, conn) {
			return raw
		}
		if depth >= maxUnwrapDepth {
			return raw
		}
		if unwrapped := rawConnOfDepth(raw, depth+1, seen); unwrapped != nil {
			return unwrapped
		}
		return raw
	}
	if conn, ok := v.(net.Conn); ok && !isNilPointer(conn) {
		return conn
	}
	return nil
}

// sameWrappedParent reports whether parent is rwc itself or any connection
// reachable from rwc through NetConn, so closing rwc closes parent.
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
