// Package wsconn implements the WebSocket protocol (RFC 6455) for tunnels,
// proxies and message channels: the opening handshake on both sides, a
// message API, and a net.Conn that carries a byte stream over binary
// messages. permessage-deflate (RFC 7692) is optional.
//
// A server accepts a connection whose request it reads itself, with Accept,
// or one whose request was already read, with AcceptRequest; a client runs
// the handshake over a connection it dialed, with Client, or dials with a
// Dialer. The subpackage wshttp upgrades the requests of a net/http
// handler. This package uses neither net/http nor crypto/tls, which would
// add megabytes to a program: it reads handshakes with httphead, and a
// Dialer reaches wss URLs through a TLS dialer of the caller's choice, such
// as a tlsconn.Dialer.
//
// # Concurrency
//
// A Conn has one reader: NextReader, ReadMessage, AppendMessage, the
// readers that NextReader returns and the Read of a StreamConn must not be
// called concurrently with each other. Pings, pongs and the closing
// handshake that the peer starts are answered while reading, so a
// connection that is written to but never read answers no pings and never
// sees the peer's close frame.
//
// Writes may come from any number of goroutines: WriteMessage, NextWriter,
// Ping, Pong and Close are serialised frame by frame, and the frames of one
// message are never interleaved with those of another. A writer from
// NextWriter holds the connection's messages until it is closed, while
// control frames, such as the reader's automatic pongs, still go out
// between its frames. Automatic pongs never wait for a write in progress:
// they are queued and sent by the writer that holds the connection, so a
// stalled writer cannot stall the reader. With no write in progress the
// reader writes the pong itself, bounded by the close timeout and the read
// deadline, and drops it if it does not go out in time, so that a peer
// that pings but never reads cannot hold the reader. Such a peer stalls
// the writers, though: servers need write deadlines as well as read
// deadlines.
//
// CloseWrite sends a close frame and leaves the closing handshake to the
// reader, as a half-close of the writing direction.
//
// Close sends a close frame and waits, up to Options.CloseTimeout, for the
// peer's, reading and discarding messages if no read is in progress, so
// that the connection does not end with a reset that could lose data in
// flight; then it closes the connection beneath.
//
// # Strictness
//
// Received frames are checked as RFC 6455 requires: reserved bits and
// opcodes, the masking direction, control frames of at most 125 bytes
// that are not fragmented, the order of fragments, close codes and UTF-8
// in text messages and close reasons. A violation is answered with a close
// frame carrying 1002, 1007 or, over Options.ReadLimit, 1009, and ends the
// connection. Extended payload lengths need not be minimal, and a peer
// that closes the connection without a close frame ends a StreamConn's
// stream like a close frame does, when it does so between frames.
package wsconn

import (
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"
)

// MessageType is the type of a data message.
type MessageType int

const (
	// Text messages hold UTF-8 text.
	Text MessageType = 1
	// Binary messages hold any bytes.
	Binary MessageType = 2
)

func (t MessageType) String() string {
	switch t {
	case Text:
		return "text"
	case Binary:
		return "binary"
	}
	return "MessageType(" + strconv.Itoa(int(t)) + ")"
}

// StatusCode is the status code of a close frame (RFC 6455, section 7.4).
type StatusCode uint16

// Status codes. NoStatusReceived, AbnormalClosure and TLSHandshake are
// never sent: they report a close frame without a code, a connection that
// ended without a close frame, and a failed TLS handshake.
const (
	StatusNormalClosure      StatusCode = 1000
	StatusGoingAway          StatusCode = 1001
	StatusProtocolError      StatusCode = 1002
	StatusUnsupportedData    StatusCode = 1003
	StatusNoStatusReceived   StatusCode = 1005
	StatusAbnormalClosure    StatusCode = 1006
	StatusInvalidPayload     StatusCode = 1007
	StatusPolicyViolation    StatusCode = 1008
	StatusMessageTooBig      StatusCode = 1009
	StatusMandatoryExtension StatusCode = 1010
	StatusInternalError      StatusCode = 1011
	StatusServiceRestart     StatusCode = 1012
	StatusTryAgainLater      StatusCode = 1013
	StatusBadGateway         StatusCode = 1014
	StatusTLSHandshake       StatusCode = 1015
)

// Sendable reports whether code may be sent in a close frame: a code of
// 1000 to 1014 other than 1004, 1005 and 1006, which RFC 6455 and the IANA
// registry define, or one of 3000 to 4999, which are registered for
// libraries and applications or private.
func (code StatusCode) Sendable() bool {
	switch {
	case code >= 1000 && code <= 1014:
		return code != 1004 && code != 1005 && code != 1006
	case code >= 3000 && code <= 4999:
		return true
	}
	return false
}

// CloseError is the close frame of the peer, which reads return once it
// arrived, or a close frame without a code as StatusNoStatusReceived.
type CloseError struct {
	Code   StatusCode
	Reason string
}

func (e *CloseError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("wsconn: closed by peer with status %d", e.Code)
	}
	return fmt.Sprintf("wsconn: closed by peer with status %d: %s", e.Code, e.Reason)
}

// Errors of reading a connection. A connection fails on each of them, after
// sending a close frame with the matching status.
var (
	// ErrProtocol reports a frame that violates RFC 6455 or the negotiated
	// extension (status 1002).
	ErrProtocol = errors.New("wsconn: protocol error")
	// ErrInvalidUTF8 reports a text message or a close reason that is not
	// UTF-8 (status 1007).
	ErrInvalidUTF8 = errors.New("wsconn: invalid UTF-8")
	// ErrMessageTooLarge reports a message over the read limit (status
	// 1009).
	ErrMessageTooLarge = errors.New("wsconn: message too large")
)

// ErrHandshake is matched by the errors of an opening handshake that the
// peer or the request failed, which are *HandshakeError.
var ErrHandshake = errors.New("wsconn: handshake failed")

// Default bounds.
const (
	// DefaultReadLimit bounds messages when Options.ReadLimit is zero. It
	// is small because a compressed message of a few kilobytes can inflate
	// to it: deflate reaches about 1000:1.
	DefaultReadLimit = 4 << 20
	// DefaultReadBufferSize is the read buffer size when
	// Options.ReadBufferSize is zero.
	DefaultReadBufferSize = 4096
	// DefaultCloseTimeout bounds the closing handshake when
	// Options.CloseTimeout is zero.
	DefaultCloseTimeout = 5 * time.Second
	// DefaultHandshakeTimeout bounds an opening handshake whose context has
	// no deadline.
	DefaultHandshakeTimeout = 10 * time.Second
	// DefaultMaxHeaderBytes bounds the head of a handshake request or
	// response when MaxHeaderBytes is zero.
	DefaultMaxHeaderBytes = 32 << 10
)

// minReadBufferSize holds the largest frame header with a control frame's
// payload, which are read at once, so that a read cut short by a deadline
// leaves no frame half read.
const minReadBufferSize = 256

// Options are the settings of a connection that both sides share.
type Options struct {
	// ReadLimit bounds the size of a message that NextReader, ReadMessage
	// and AppendMessage read, after decompression: a larger message fails
	// the connection with ErrMessageTooLarge and status 1009. Zero means
	// DefaultReadLimit (4 MiB) and a negative limit none; with compression
	// a peer needs about a thousandth of the limit to make a message that
	// large. A StreamConn reads messages without a limit, as it holds none
	// of them in memory.
	ReadLimit int64
	// ReadBufferSize is the size of the read buffer; zero means
	// DefaultReadBufferSize, and sizes below 256 bytes mean 256. A
	// connection whose handshake left a buffer, such as an upgraded HTTP
	// request's, keeps that buffer.
	ReadBufferSize int
	// CloseTimeout bounds the closing handshake: sending the close frame
	// and waiting for the peer's, and on a client then waiting for the
	// server to end the connection beneath, which the server does at once.
	// Zero means DefaultCloseTimeout. When negative, Close does not wait
	// for the peer: it sends a close frame only when no write is in
	// progress, within the timeout's magnitude, and closes the connection
	// beneath.
	CloseTimeout time.Duration
	// OnPing and OnPong, if set, are called by the reader with the payload
	// of each ping and pong, which is valid only during the call; a ping
	// is answered with a pong all the same. They run on the reader's
	// goroutine, as when extending a read deadline, and must not read;
	// a Close from them waits the whole close timeout.
	OnPing func(c *Conn, data []byte)
	OnPong func(c *Conn, data []byte)
	// Compression, if set, offers or accepts permessage-deflate.
	Compression *Compression
}

func (o *Options) readLimit() int64 {
	switch {
	case o.ReadLimit == 0:
		return DefaultReadLimit
	case o.ReadLimit < 0:
		return -1
	}
	return o.ReadLimit
}

func (o *Options) readBufferSize() int {
	switch {
	case o.ReadBufferSize == 0:
		return DefaultReadBufferSize
	case o.ReadBufferSize < minReadBufferSize:
		return minReadBufferSize
	}
	return o.ReadBufferSize
}

func (o *Options) closeTimeout() time.Duration {
	if o.CloseTimeout == 0 {
		return DefaultCloseTimeout
	}
	return o.CloseTimeout
}

// protocolError fails a connection with ErrProtocol and a description.
func protocolError(msg string) error { return fmt.Errorf("%w: %s", ErrProtocol, msg) }

// validCloseReason reports whether reason fits a close frame with a code.
func validCloseReason(reason string) bool {
	return len(reason) <= maxControlPayload-2 && utf8.ValidString(reason)
}
