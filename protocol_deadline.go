package netx

import (
	"errors"
	"net"
	"time"
)

func setReadDeadline(c net.Conn, timeout time.Duration) error {
	return c.SetReadDeadline(time.Now().Add(normalizeLinkTimeout(timeout)))
}

func clearReadDeadline(c net.Conn, err error) error {
	return errors.Join(err, c.SetReadDeadline(time.Time{}))
}

func setWriteDeadline(c net.Conn, timeout time.Duration) error {
	return c.SetWriteDeadline(time.Now().Add(normalizeLinkTimeout(timeout)))
}

func clearWriteDeadline(c net.Conn, err error) error {
	return errors.Join(err, c.SetWriteDeadline(time.Time{}))
}
