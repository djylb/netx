package netx

import (
	"io"
	"net"
	"time"
)

const ConnACK = "ACK"

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
