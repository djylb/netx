package netx

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/djylb/netx/internal/netutil"
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
// parent is skipped when rwc already owns it, and
// net.ErrClosed from parent is ignored because rwc may already have closed it.
func WithWrapParentClose() WrapOption {
	return func(o *wrapOptions) {
		o.closeParent = true
	}
}

// WrapConn exposes rwc as a net.Conn using parent for addresses and deadlines.
// A nil parent is rwc itself when it is a net.Conn, so that its own wrappers
// keep their addresses and deadlines, and otherwise the connection beneath it.
// Closing the returned connection closes rwc. Use WithWrapParentClose to also close parent.
// When rwc is a ReadNotifier, so is the returned connection.
func WrapConn(rwc io.ReadWriteCloser, parent net.Conn, opts ...WrapOption) net.Conn {
	var cfg wrapOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if netutil.IsNilPointer(rwc) {
		rwc = nil
	}
	if parent == nil || netutil.IsNilPointer(parent) {
		if c, ok := rwc.(net.Conn); ok {
			parent = c
		} else {
			// Borrowed: closing the result closes rwc, and parent only with
			// WithWrapParentClose.
			//goland:noinspection GoResourceLeak
			parent = InnermostConn(rwc)
		}
	}
	w := &wrappedConn{rwc: rwc, parent: parent, closeParent: cfg.closeParent}
	if n, ok := rwc.(ReadNotifier); ok && !netutil.IsNilPointer(n) {
		return &wrappedNotifyConn{wrappedConn: w, n: n}
	}
	return w
}

// wrappedNotifyConn is a WrapConn over an rwc that is a ReadNotifier: it is
// one too, so that a Relay reads it without a goroutine per direction.
// Reads go to rwc, as its TryRead and NotifyReadable do.
type wrappedNotifyConn struct {
	*wrappedConn
	n ReadNotifier
}

// TryRead reads from rwc without blocking; see ReadNotifier.
func (w *wrappedNotifyConn) TryRead(p []byte) (int, error) { return w.n.TryRead(p) }

// NotifyReadable calls f once rwc is readable; see ReadNotifier.
func (w *wrappedNotifyConn) NotifyReadable(f func()) (stop func() bool) {
	return w.n.NotifyReadable(f)
}

func (w *wrappedNotifyConn) netxLayer() layerInfo {
	info := w.wrappedConn.netxLayer()
	info.self = w
	return info
}

// rw returns what reads and writes go to, or noConn.
func (w *wrappedConn) rw() io.ReadWriteCloser {
	if w == nil || w.rwc == nil {
		return noConn
	}
	return w.rwc
}

// conn returns the connection of the addresses and deadlines, or noConn.
func (w *wrappedConn) conn() net.Conn {
	if w == nil {
		return noConn
	}
	return orClosed(w.parent)
}

func (w *wrappedConn) Read(b []byte) (int, error)         { return w.rw().Read(b) }
func (w *wrappedConn) Write(b []byte) (int, error)        { return w.rw().Write(b) }
func (w *wrappedConn) LocalAddr() net.Addr                { return w.conn().LocalAddr() }
func (w *wrappedConn) RemoteAddr() net.Addr               { return w.conn().RemoteAddr() }
func (w *wrappedConn) SetDeadline(t time.Time) error      { return w.conn().SetDeadline(t) }
func (w *wrappedConn) SetReadDeadline(t time.Time) error  { return w.conn().SetReadDeadline(t) }
func (w *wrappedConn) SetWriteDeadline(t time.Time) error { return w.conn().SetWriteDeadline(t) }

// CloseWrite shuts down the writing side of rwc; see TimeoutConn.CloseWrite.
func (w *wrappedConn) CloseWrite() error { return closeWrite(w.rw()) }

func (w *wrappedConn) Close() error {
	if w == nil {
		return net.ErrClosed
	}
	var err1, err2 error
	parent := w.separateParent()
	if w.rwc != nil {
		err1 = w.rwc.Close()
	}
	if parent != nil {
		// rwc may wrap parent without exposing it, so parent can already be closed.
		if err2 = parent.Close(); errors.Is(err2, net.ErrClosed) {
			err2 = nil
		}
	}
	return errors.Join(err1, err2)
}

func (w *wrappedConn) separateParent() net.Conn {
	if w.closeParent && w.parent != nil && !sameWrappedParent(w.rwc, w.parent) {
		return w.parent
	}
	return nil
}

// NetConn returns the connection whose addresses and deadlines w uses.
func (w *wrappedConn) NetConn() net.Conn {
	if w == nil {
		return nil
	}
	return w.parent
}

func (w *wrappedConn) netxLayer() layerInfo {
	info := layerInfo{self: w, kind: layerWraps | layerReads}
	if w != nil {
		info.conn, info.rwc = w.parent, w.rwc
		info.borrowParent = !w.closeParent
	}
	return info
}

// sameWrappedParent reports whether closing rwc also closes parent.
func sameWrappedParent(rwc io.ReadWriteCloser, parent net.Conn) bool {
	return netutil.WalkOwned(rwc, func(v any) bool { return netutil.Same(v, parent) })
}

// NetxOwned describes the children closed with this layer.
func (w *wrappedNotifyConn) NetxOwned() OwnedLayers { return w.netxLayer().owned() }

// NetxOwned describes the children closed with this layer.
func (w *wrappedConn) NetxOwned() OwnedLayers { return w.netxLayer().owned() }
