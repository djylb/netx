package netx

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

// ConnectResultStatus is the compact status code exchanged after dialing a target.
type ConnectResultStatus byte

const (
	connectResultFrameVersion byte = 1

	ConnectResultOK ConnectResultStatus = iota
	ConnectResultConnectionRefused
	ConnectResultHostUnreachable
	ConnectResultNetworkUnreachable
	ConnectResultNotAllowed
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	ConnectResultServerFailure ConnectResultStatus = 255
)

// WriteConnectResult writes a connect result frame with a temporary write deadline.
func WriteConnectResult(c net.Conn, status ConnectResultStatus, timeout time.Duration) error {
	if c == nil {
		return net.ErrClosed
	}
	timeout = normalizeLinkTimeout(timeout)
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	_, err := c.Write([]byte{connectResultFrameVersion, byte(status)})
	_ = c.SetWriteDeadline(time.Time{})
	return err
}

// ReadConnectResult reads a connect result frame with a temporary read deadline.
func ReadConnectResult(c net.Conn, timeout time.Duration) (ConnectResultStatus, error) {
	if c == nil {
		return ConnectResultServerFailure, net.ErrClosed
	}
	timeout = normalizeLinkTimeout(timeout)
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	var buf [2]byte
	_, err := io.ReadFull(c, buf[:])
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		return ConnectResultServerFailure, err
	}
	if buf[0] != connectResultFrameVersion {
		return ConnectResultServerFailure, io.ErrUnexpectedEOF
	}
	return ConnectResultStatus(buf[1]), nil
}

// DialConnectResult maps a dial error to a ConnectResultStatus.
func DialConnectResult(err error) ConnectResultStatus {
	if err == nil {
		return ConnectResultOK
	}
	if IsTimeout(err) {
		return ConnectResultNetworkUnreachable
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ConnectResultHostUnreachable
	}

	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return ConnectResultConnectionRefused
	case errors.Is(err, syscall.EHOSTUNREACH):
		return ConnectResultHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		return ConnectResultNetworkUnreachable
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return ConnectResultNotAllowed
	}

	msg := normalizeNetErrorText(err)
	switch {
	case strings.Contains(msg, "connectionrefused"),
		strings.Contains(msg, "activelyrefusedit"):
		return ConnectResultConnectionRefused
	case strings.Contains(msg, "nosuchhost"),
		strings.Contains(msg, "nameorservicenotknown"),
		strings.Contains(msg, "temporaryfailureinnameresolution"),
		strings.Contains(msg, "servermisbehaving"),
		strings.Contains(msg, "hostunreachable"),
		strings.Contains(msg, "noroutetohost"):
		return ConnectResultHostUnreachable
	case strings.Contains(msg, "networkisunreachable"):
		return ConnectResultNetworkUnreachable
	case strings.Contains(msg, "permissiondenied"),
		strings.Contains(msg, "accessisdenied"):
		return ConnectResultNotAllowed
	default:
		return ConnectResultServerFailure
	}
}
