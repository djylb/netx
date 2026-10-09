package netx

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// PrefixConn is a net.Conn whose reads return a prefix before the data of the
// connection it wraps. It hands a connection on after bytes were already read
// from it, for example to sniff the protocol. Writes, deadlines and addresses
// go to the wrapped connection.
type PrefixConn struct {
	net.Conn
	mu      sync.Mutex
	prefix  []byte
	drained atomic.Bool // prefix fully consumed; reads skip the lock
}

// NewPrefixConn returns c with prefix replayed before its own data. prefix is
// not copied and must not be modified afterwards.
func NewPrefixConn(c net.Conn, prefix []byte) *PrefixConn {
	pc := &PrefixConn{Conn: c, prefix: prefix}
	pc.drained.Store(len(prefix) == 0)
	return pc
}

func (c *PrefixConn) Read(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
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
		c.mu.Unlock()
	}
	return c.Conn.Read(b)
}

// WriteTo writes the rest of the prefix to w and then copies the wrapped
// connection to w, through its own WriteTo when it has one, so a
// *net.TCPConn can still splice.
func (c *PrefixConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.Conn == nil {
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
	m, err := io.Copy(w, c.Conn)
	return int64(n) + m, err
}

// CloseWrite shuts down the writing side of the wrapped connection; see
// TimeoutConn.CloseWrite.
func (c *PrefixConn) CloseWrite() error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return closeWrite(c.Conn)
}

// RawConn returns the innermost connection beneath c; see RawConnProvider.
// Reading it directly skips the rest of the prefix.
func (c *PrefixConn) RawConn() net.Conn {
	if c == nil {
		return nil
	}
	return rawConnOf(c.Conn)
}
