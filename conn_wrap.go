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
// parent is skipped when rwc unwraps to it through NetConn, and
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
func WrapConn(rwc io.ReadWriteCloser, parent net.Conn, opts ...WrapOption) net.Conn {
	var cfg wrapOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if parent == nil {
		if c, ok := rwc.(net.Conn); ok {
			parent = c
		} else {
			// Borrowed: closing the result closes rwc, and parent only with
			// WithWrapParentClose.
			//noinspection GoResourceLeak
			parent = InnermostConn(rwc)
		}
	}
	if netutil.IsNilPointer(parent) {
		parent = nil
	}
	return &wrappedConn{rwc: rwc, parent: parent, closeParent: cfg.closeParent}
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
	}
	return info
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
