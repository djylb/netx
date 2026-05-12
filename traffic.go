package netx

import (
	"io"
	"net"
)

type ByteObserver func(int64) error

type TrafficObserver struct {
	OnRead  ByteObserver
	OnWrite ByteObserver
}

type observedReadWriteCloser struct {
	rwc     io.ReadWriteCloser
	onRead  ByteObserver
	onWrite ByteObserver
}

func WrapReadWriteCloserWithTrafficObserver(rwc io.ReadWriteCloser, observer TrafficObserver) io.ReadWriteCloser {
	if rwc == nil || (observer.OnRead == nil && observer.OnWrite == nil) {
		return rwc
	}
	return &observedReadWriteCloser{
		rwc:     rwc,
		onRead:  observer.OnRead,
		onWrite: observer.OnWrite,
	}
}

func WrapNetConnWithTrafficObserver(conn net.Conn, observer TrafficObserver) net.Conn {
	if conn == nil || (observer.OnRead == nil && observer.OnWrite == nil) {
		return conn
	}
	return WrapConn(WrapReadWriteCloserWithTrafficObserver(conn, observer), conn)
}

func (c *observedReadWriteCloser) Read(p []byte) (int, error) {
	if c == nil || c.rwc == nil {
		return 0, net.ErrClosed
	}
	n, err := c.rwc.Read(p)
	if c.onRead != nil && n > 0 {
		if observeErr := c.onRead(int64(n)); observeErr != nil {
			return n, observeErr
		}
	}
	return n, err
}

func (c *observedReadWriteCloser) Write(p []byte) (int, error) {
	if c == nil || c.rwc == nil {
		return 0, net.ErrClosed
	}
	n, err := c.rwc.Write(p)
	if c.onWrite != nil && n > 0 {
		if observeErr := c.onWrite(int64(n)); observeErr != nil {
			return n, observeErr
		}
	}
	return n, err
}

func (c *observedReadWriteCloser) Close() error {
	if c == nil || c.rwc == nil {
		return nil
	}
	return c.rwc.Close()
}

func (c *observedReadWriteCloser) GetRawConn() net.Conn {
	if c == nil {
		return nil
	}
	return rawConnOf(c.rwc)
}
