package netx

import (
	"errors"
	"io"
	"net"
)

type observedReadWriteCloser struct {
	rwc     io.ReadWriteCloser
	onRead  func(int64) error
	onWrite func(int64) error
}

// ObserveConn wraps conn and reports the bytes of each successful read to
// onRead and of each write to onWrite, either of which may be nil. An error
// from one is joined to the error of that Read or Write, so that it can end
// the connection's use, such as when an allowance runs out. With neither,
// conn is returned as it is.
//
// To count and pace a Relay, use WithRelayFlows instead: a Relay cannot
// splice through, or wait for data without a buffer on, a connection that
// ObserveConn wraps.
func ObserveConn(conn net.Conn, onRead, onWrite func(n int64) error) net.Conn {
	if conn == nil || (onRead == nil && onWrite == nil) {
		return conn
	}
	return WrapConn(&observedReadWriteCloser{rwc: conn, onRead: onRead, onWrite: onWrite}, conn)
}

// inner returns the wrapped value, or noConn.
func (c *observedReadWriteCloser) inner() io.ReadWriteCloser {
	if c == nil || c.rwc == nil {
		return noConn
	}
	return c.rwc
}

func (c *observedReadWriteCloser) Read(p []byte) (int, error) {
	if c == nil || c.rwc == nil {
		return 0, net.ErrClosed
	}
	n, err := c.rwc.Read(p)
	return observe(c.onRead, n, err)
}

func (c *observedReadWriteCloser) Write(p []byte) (int, error) {
	if c == nil || c.rwc == nil {
		return 0, net.ErrClosed
	}
	n, err := c.rwc.Write(p)
	return observe(c.onWrite, n, err)
}

// observe reports the n bytes of a Read or Write to fn, if set, and joins
// its error to err.
func observe(fn func(int64) error, n int, err error) (int, error) {
	if fn != nil && n > 0 {
		if observeErr := fn(int64(n)); observeErr != nil {
			return n, errors.Join(err, observeErr)
		}
	}
	return n, err
}

func (c *observedReadWriteCloser) Close() error      { return c.inner().Close() }
func (c *observedReadWriteCloser) CloseWrite() error { return closeWrite(c.inner()) }

// NetConn returns the connection that c wraps, if it is one.
func (c *observedReadWriteCloser) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	conn, _ := c.rwc.(net.Conn)
	return conn
}

func (c *observedReadWriteCloser) netxLayer() layerInfo {
	info := layerInfo{self: c, kind: layerWraps | layerReads}
	if c != nil {
		info.rwc = c.rwc
	}
	return info
}
