package netx

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PrefixConn is a net.Conn whose reads return a prefix before the data of the
// connection it wraps. It hands a connection on after bytes were already read
// from it, for example to sniff the protocol. Writes, deadlines and addresses
// go to the wrapped connection.
type PrefixConn struct {
	conn    net.Conn
	mu      sync.Mutex
	prefix  []byte
	drained atomic.Bool // prefix fully consumed; reads skip the lock
}

// Peek reads the first bytes of c, at most n, as for sniffing the protocol
// of a connection before it is handed on, and returns them with a
// connection that replays them before the rest of c. It returns after the
// first read that brings data, so a peer whose first message is shorter
// than n does not stall it; use PeekFull for exactly n bytes. ctx bounds the
// wait as DoWithContext does: its deadline becomes c's, and c's deadline is
// cleared again once bytes have come. The error is that of the read, or
// ctx's; the returned connection is valid also then.
//
// On a connection whose Reads return one datagram each, such as one of a
// PacketListener, Peek reads the first datagram whole, returns up to n of its
// bytes, and the returned connection replays the whole datagram, so that
// sniffing does not cut it short.
func Peek(ctx context.Context, c net.Conn, n int) (net.Conn, []byte, error) {
	return peek(ctx, c, n, func(b []byte) (int, error) {
		for {
			m, err := c.Read(b)
			if m > 0 || err != nil || len(b) == 0 {
				return m, err
			}
		}
	})
}

// PeekFull is Peek reading exactly n bytes, or fewer if a read fails first.
// On a datagram connection it reads one datagram, as Peek does.
func PeekFull(ctx context.Context, c net.Conn, n int) (net.Conn, []byte, error) {
	if datagramReader(c) {
		return Peek(ctx, c, n)
	}
	return peek(ctx, c, n, func(b []byte) (int, error) { return io.ReadFull(c, b) })
}

func peek(ctx context.Context, c net.Conn, n int, read func([]byte) (int, error)) (net.Conn, []byte, error) {
	n = max(n, 0)
	size := n
	if datagramReader(c) {
		size = relayDatagramBufSize // the whole datagram
	}
	b := make([]byte, size)
	var m int
	err := DoWithContext(ctx, c, func() error {
		var err error
		m, err = read(b)
		return err
	})
	b = b[:m]
	if m == 0 {
		return c, nil, err
	}
	return NewPrefixConn(c, b), b[:min(m, n)], err
}

// NewPrefixConn returns c with prefix replayed before its own data. prefix is
// not copied and must not be modified afterwards.
func NewPrefixConn(c net.Conn, prefix []byte) *PrefixConn {
	pc := &PrefixConn{conn: c, prefix: prefix}
	pc.drained.Store(len(prefix) == 0)
	return pc
}

func (c *PrefixConn) Read(b []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	if !c.drained.Load() {
		c.mu.Lock()
		if len(c.prefix) > 0 {
			n := copy(b, c.prefix)
			c.prefix = c.prefix[n:]
			if len(c.prefix) == 0 {
				c.prefix = nil
				c.drained.Store(true)
			}
			c.mu.Unlock()
			return n, nil
		}
		// A PrefixConn made without NewPrefixConn starts with none.
		c.drained.Store(true)
		c.mu.Unlock()
	}
	return c.conn.Read(b)
}

func (c *PrefixConn) Write(b []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	return c.conn.Write(b)
}

func (c *PrefixConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *PrefixConn) LocalAddr() net.Addr {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

func (c *PrefixConn) RemoteAddr() net.Addr {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

func (c *PrefixConn) SetDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetDeadline(t)
}

func (c *PrefixConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetReadDeadline(t)
}

func (c *PrefixConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetWriteDeadline(t)
}

// WriteTo writes the rest of the prefix to w and then copies the wrapped
// connection to w, through its own WriteTo when it has one, so a
// *net.TCPConn can still splice.
func (c *PrefixConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	prefix := c.prefix
	c.prefix = nil
	c.drained.Store(true)
	c.mu.Unlock()

	n, err := writeAll(w, prefix)
	if err != nil {
		return int64(n), err
	}
	m, err := io.Copy(w, c.conn)
	return int64(n) + m, err
}

// CloseWrite shuts down the writing side of the wrapped connection; see
// TimeoutConn.CloseWrite.
func (c *PrefixConn) CloseWrite() error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return closeWrite(c.conn)
}

func (c *PrefixConn) innerReader() io.Reader {
	if c == nil {
		return nil
	}
	return c.conn
}

// NetConn returns the connection that c wraps, as *tls.Conn's NetConn does;
// see InnermostConn and ConnAs. Reading it directly skips the rest of the
// prefix.
func (c *PrefixConn) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.conn
}
