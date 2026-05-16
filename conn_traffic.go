package netx

import (
	"errors"
	"io"
	"net"
)

// ByteObserver observes byte counts for successful reads or writes.
type ByteObserver func(int64) error

// TrafficObserver contains optional read and write observers.
type TrafficObserver struct {
	OnRead  ByteObserver
	OnWrite ByteObserver
}

type observedReadWriteCloser struct {
	rwc     io.ReadWriteCloser
	onRead  ByteObserver
	onWrite ByteObserver
}

// ObserveReadWriteCloser wraps rwc and reports transferred byte counts.
func ObserveReadWriteCloser(rwc io.ReadWriteCloser, observer TrafficObserver) io.ReadWriteCloser {
	if rwc == nil || (observer.OnRead == nil && observer.OnWrite == nil) {
		return rwc
	}
	return &observedReadWriteCloser{
		rwc:     rwc,
		onRead:  observer.OnRead,
		onWrite: observer.OnWrite,
	}
}

// ObserveConn wraps conn and reports transferred byte counts.
func ObserveConn(conn net.Conn, observer TrafficObserver) net.Conn {
	if conn == nil || (observer.OnRead == nil && observer.OnWrite == nil) {
		return conn
	}
	return WrapConn(ObserveReadWriteCloser(conn, observer), conn)
}

func (c *observedReadWriteCloser) Read(p []byte) (int, error) {
	if c == nil || c.rwc == nil {
		return 0, net.ErrClosed
	}
	n, err := c.rwc.Read(p)
	if c.onRead != nil && n > 0 {
		if observeErr := c.onRead(int64(n)); observeErr != nil {
			return n, errors.Join(err, observeErr)
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
			return n, errors.Join(err, observeErr)
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

func (c *observedReadWriteCloser) RawConn() net.Conn {
	if c == nil {
		return nil
	}
	return rawConnOf(c.rwc)
}
