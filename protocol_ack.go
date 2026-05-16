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
	if err := setWriteDeadline(c, timeout); err != nil {
		return err
	}
	buf := [len(ConnACK)]byte{'A', 'C', 'K'}
	err := writeAll(c, buf[:])
	return clearWriteDeadline(c, err)
}

// ReadACK reads ConnACK with a temporary read deadline.
func ReadACK(c net.Conn, timeout time.Duration) error {
	if c == nil {
		return net.ErrClosed
	}
	if err := setReadDeadline(c, timeout); err != nil {
		return err
	}
	var buf [len(ConnACK)]byte
	_, err := io.ReadFull(c, buf[:])
	if err != nil {
		return clearReadDeadline(c, err)
	}
	if buf != [len(ConnACK)]byte{'A', 'C', 'K'} {
		return clearReadDeadline(c, io.ErrUnexpectedEOF)
	}
	return clearReadDeadline(c, nil)
}
