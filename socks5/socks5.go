// Package socks5 implements SOCKS version 5 (RFC 1928) with
// username/password authentication (RFC 1929): a message codec for clients
// and servers, and a configurable Server.
//
// The codec functions read one message from an io.Reader or write one message
// to an io.Writer in a single Write call, so they work over any connection and
// leave timeouts and policy to the caller. A server handshake reads the
// client's methods, selects one, optionally authenticates, then reads the
// request and writes a reply:
//
//	methods, err := socks5.ReadMethods(conn)        // then socks5.WriteMethod
//	user, pass, err := socks5.ReadUserPass(conn)    // then socks5.WriteUserPassStatus
//	cmd, dst, err := socks5.ReadRequest(conn)       // then socks5.WriteReply
//
// A client mirrors it with WriteMethods, ReadMethod, WriteUserPass,
// ReadUserPassStatus, WriteRequest and ReadReply. ReadRequest4,
// WriteRequest4, WriteReply4 and ReadReply4 handle SOCKS4 and SOCKS4a. ParseDatagram and
// AppendDatagram handle the header of UDP ASSOCIATE datagrams. Reserved
// fields and the username/password version byte are not checked on receipt,
// for compatibility with non-standard peers.
//
// Dialer dials TCP connections through a SOCKS5, SOCKS4 or SOCKS4a proxy.
// Server serves CONNECT, UDP ASSOCIATE and, optionally, SOCKS4 and SOCKS4a
// clients. Both run over any net.Conn, so SOCKS over TLS only needs a TLS
// listener for the server, or a TLS dialer as the Dialer's Forward. Authentication, access control, dialing, relaying, the outbound
// side of UDP associations and the advertised addresses are all replaceable,
// and UDP associations can share one fixed port or get a socket each.
package socks5

import (
	"errors"
	"strconv"
)

// Version is the SOCKS protocol version byte.
const Version = 5

const userPassVersion = 1 // sent in username/password messages; not checked on receipt

// Command is the command of a client request.
type Command byte

// Commands defined by RFC 1928.
const (
	CmdConnect      Command = 1
	CmdBind         Command = 2
	CmdUDPAssociate Command = 3
)

func (c Command) String() string {
	switch c {
	case CmdConnect:
		return "connect"
	case CmdBind:
		return "bind"
	case CmdUDPAssociate:
		return "udp associate"
	default:
		return "command " + strconv.Itoa(int(c))
	}
}

// Method is an authentication method.
type Method byte

// Methods defined by RFC 1928.
const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodUserPass     Method = 0x02
	MethodNoAcceptable Method = 0xFF
)

func (m Method) String() string {
	switch m {
	case MethodNoAuth:
		return "no authentication"
	case MethodGSSAPI:
		return "gssapi"
	case MethodUserPass:
		return "username/password"
	case MethodNoAcceptable:
		return "no acceptable methods"
	default:
		return "method " + strconv.Itoa(int(m))
	}
}

// Reply is the status field of a server reply.
type Reply byte

// Replies defined by RFC 1928.
const (
	ReplySucceeded            Reply = 0
	ReplyGeneralFailure       Reply = 1
	ReplyNotAllowed           Reply = 2
	ReplyNetworkUnreachable   Reply = 3
	ReplyHostUnreachable      Reply = 4
	ReplyConnectionRefused    Reply = 5
	ReplyTTLExpired           Reply = 6
	ReplyCommandNotSupported  Reply = 7
	ReplyAddrTypeNotSupported Reply = 8
)

func (r Reply) String() string {
	switch r {
	case ReplySucceeded:
		return "succeeded"
	case ReplyGeneralFailure:
		return "general server failure"
	case ReplyNotAllowed:
		return "connection not allowed by ruleset"
	case ReplyNetworkUnreachable:
		return "network unreachable"
	case ReplyHostUnreachable:
		return "host unreachable"
	case ReplyConnectionRefused:
		return "connection refused"
	case ReplyTTLExpired:
		return "TTL expired"
	case ReplyCommandNotSupported:
		return "command not supported"
	case ReplyAddrTypeNotSupported:
		return "address type not supported"
	case Reply4Granted:
		return "request granted"
	case Reply4Rejected:
		return "request rejected or failed"
	case Reply4IdentdUnreached:
		return "identd unreachable"
	case Reply4IdentdMismatch:
		return "identd user ID mismatch"
	default:
		return "reply " + strconv.Itoa(int(r))
	}
}

// ReplyError is returned by ReadReply and ReadReply4 when the server reply is
// not a success. Reply holds the code as sent, a SOCKS4 one for ReadReply4.
type ReplyError struct {
	Reply Reply
}

func (e *ReplyError) Error() string {
	return "socks5: " + e.Reply.String()
}

var (
	// ErrVersion reports a message whose version byte is not 5.
	ErrVersion = errors.New("socks5: unsupported version")
	// ErrMalformed reports a message that violates the protocol.
	ErrMalformed = errors.New("socks5: malformed message")
	// ErrAddrType reports an address type other than IPv4, IPv6 or domain
	// name. A server answers it with ReplyAddrTypeNotSupported.
	ErrAddrType = errors.New("socks5: unsupported address type")
	// ErrInvalidAddr reports an address that cannot be encoded or parsed.
	ErrInvalidAddr = errors.New("socks5: invalid address")
	// ErrNoAcceptableMethod is returned by ReadMethod when the server accepts
	// none of the offered methods.
	ErrNoAcceptableMethod = errors.New("socks5: no acceptable authentication method")
	// ErrAuthFailed is returned by ReadUserPassStatus when the server rejects
	// the credentials.
	ErrAuthFailed = errors.New("socks5: authentication failed")
	// ErrFragmented is returned by ParseDatagram for a datagram fragment.
	ErrFragmented = errors.New("socks5: fragmented datagram")
)
