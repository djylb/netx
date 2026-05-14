package netx

import (
	"io"
	"net"
	"time"
)

// ConnACK is the fixed acknowledgement payload used by WriteACK and ReadACK.
const ConnACK = "ACK"

// WriteACK writes ConnACK with a temporary write deadline.
func WriteACK(c net.Conn, timeout time.Duration) error {
	if c == nil {
		return net.ErrClosed
	}
	timeout = normalizeLinkTimeout(timeout)
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	_, err := c.Write([]byte(ConnACK))
	_ = c.SetWriteDeadline(time.Time{})
	return err
}

// ReadACK reads ConnACK with a temporary read deadline.
func ReadACK(c net.Conn, timeout time.Duration) error {
	if c == nil {
		return net.ErrClosed
	}
	timeout = normalizeLinkTimeout(timeout)
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, len(ConnACK))
	_, err := io.ReadFull(c, buf)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	if string(buf) != ConnACK {
		return io.ErrUnexpectedEOF
	}
	return nil
}
