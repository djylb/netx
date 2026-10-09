package socks5

import (
	"errors"
	"net"

	"github.com/djylb/netx"
)

// ReplyFor returns the SOCKS5 reply code that reports err to a client: the
// Reply of a *ReplyError (ReplyGeneralFailure if that is ReplySucceeded),
// ReplySucceeded for nil, and otherwise the closest
// code for a failed dial, such as ReplyConnectionRefused or
// ReplyHostUnreachable, or ReplyGeneralFailure. SOCKS4 codes in a *ReplyError,
// as from an upstream SOCKS4 Dialer, are translated: the identd failures to
// ReplyNotAllowed and others to ReplyGeneralFailure.
func ReplyFor(err error) Reply {
	var replyErr *ReplyError
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		return ReplySucceeded
	case errors.As(err, &replyErr):
		switch rep := replyErr.Reply; {
		case rep == ReplySucceeded: // an error must not report success
			return ReplyGeneralFailure
		case rep <= ReplyAddrTypeNotSupported:
			return rep
		case rep == Reply4IdentdUnreached, rep == Reply4IdentdMismatch:
			return ReplyNotAllowed
		default:
			return ReplyGeneralFailure
		}
	case netx.IsConnRefused(err):
		return ReplyConnectionRefused
	case netx.IsNetworkUnreachable(err):
		return ReplyNetworkUnreachable
	case netx.IsHostUnreachable(err), errors.As(err, &dnsErr), netx.IsTimeout(err):
		return ReplyHostUnreachable
	case netx.IsPermissionDenied(err):
		return ReplyNotAllowed
	default:
		return ReplyGeneralFailure
	}
}
