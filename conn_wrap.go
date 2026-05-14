package netx

import (
	"errors"
	"io"
	"net"
	"time"
)

type wrappedConn struct {
	rwc         io.ReadWriteCloser
	parent      net.Conn
	closeParent bool
}

// RawConnProvider is implemented by wrappers that can expose their underlying net.Conn.
type RawConnProvider interface {
	RawConn() net.Conn
}

// RawConnOf returns v's underlying net.Conn when it is available.
func RawConnOf(v any) net.Conn {
	return rawConnOf(v)
}

// WrapConn exposes rwc as a net.Conn using parent for addresses and deadlines.
// Closing the returned connection closes rwc and parent.
func WrapConn(rwc io.ReadWriteCloser, parent net.Conn) net.Conn {
	return wrapConnWithCloseMode(rwc, parent, true)
}

// WrapConnWithoutParentClose is like WrapConn but leaves parent open when closed.
// Use it when rwc already owns parent and closes it itself.
func WrapConnWithoutParentClose(rwc io.ReadWriteCloser, parent net.Conn) net.Conn {
	return wrapConnWithoutParentClose(rwc, parent)
}

func wrapConnWithoutParentClose(rwc io.ReadWriteCloser, parent net.Conn) net.Conn {
	return wrapConnWithCloseMode(rwc, parent, false)
}

func wrapConnWithCloseMode(rwc io.ReadWriteCloser, parent net.Conn, closeParent bool) net.Conn {
	return &wrappedConn{rwc: rwc, parent: parent, closeParent: closeParent}
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
	if w.closeParent && w.parent != nil {
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
	if v == nil {
		return nil
	}
	if getter, ok := v.(interface{ RawConn() net.Conn }); ok {
		return getter.RawConn()
	}
	if conn, ok := v.(net.Conn); ok {
		return conn
	}
	return nil
}
