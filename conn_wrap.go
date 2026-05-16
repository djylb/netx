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
type RawConnProvider interface {
	RawConn() net.Conn
}

// WrapOption configures WrapConn.
type WrapOption func(*wrapOptions)

// WithParentClose makes WrapConn close parent after closing rwc.
func WithParentClose() WrapOption {
	return func(o *wrapOptions) {
		o.closeParent = true
	}
}

// RawConnOf returns v's underlying net.Conn when it is available.
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
		err2 = w.parent.Close()
	}
	return errors.Join(err1, err2)
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

func rawConnOfDepth(v any, depth int) net.Conn {
	if v == nil {
		return nil
	}
	if getter, ok := v.(interface{ RawConn() net.Conn }); ok {
		raw := getter.RawConn()
		if raw == nil {
			return nil
		}
		if conn, ok := v.(net.Conn); ok && sameNetConn(raw, conn) {
			return raw
		}
		if depth >= 16 {
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

func sameWrappedParent(rwc io.ReadWriteCloser, parent net.Conn) bool {
	if rwc == nil || parent == nil {
		return false
	}
	if conn, ok := rwc.(net.Conn); ok && sameNetConn(conn, parent) {
		return true
	}
	return sameNetConn(rawConnOf(rwc), parent)
}

func sameNetConn(a, b net.Conn) bool {
	if a == nil || b == nil {
		return false
	}
	av := reflect.ValueOf(a)
	bv := reflect.ValueOf(b)
	if av.Type() != bv.Type() || !av.Type().Comparable() {
		return false
	}
	return av.Equal(bv)
}
