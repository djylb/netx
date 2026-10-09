package proxy

import (
	"context"
	"net"
	"time"
)

// handshake runs fn on c with ctx's deadline as the connection deadline and
// interrupts its I/O when ctx is canceled. On success it clears the
// deadline; on failure it closes c and prefers ctx's error.
func handshake(ctx context.Context, c net.Conn, fn func() (net.Conn, error)) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() {
		_ = c.SetDeadline(time.Unix(1, 0))
	})
	out, err := fn()
	if !stop() && err == nil {
		// ctx ended after fn returned and has already poisoned the deadline.
		err = ctx.Err()
	}
	if err == nil {
		err = c.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = c.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return out, nil
}

// prefixConn returns bytes the handshake read past its last message before
// reading from the connection.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *prefixConn) RawConn() net.Conn {
	return c.Conn
}
