// Package httpproxy implements an HTTP proxy server: CONNECT tunnels and
// forwarding of absolute-form requests such as "GET http://host/path", over
// any net.Conn, with optional Basic proxy authentication.
//
// Server has the shape of socks5.Server, so that one policy serves both
// protocols on one port: the same hooks (Auth, Allow, Handle, Dial,
// RelayOptions, OnError) with the same signatures over this package's
// Request, the destination as a netx.Addr normalised in the same way, the
// authenticated identity in Request.User, a BasicAuth whose Check has the
// signature of socks5.UserPassAuth.Check, and the same Serve, ServeConn,
// Shutdown and Close. It serves any net.Conn, such as a TLS connection or a
// netx.PrefixConn carrying bytes already read to choose the protocol.
//
// Request heads are parsed with the httphead package, without net/http,
// which would link crypto/tls and the HTTP/2 machinery into every program
// that uses this one. Connections to targets are kept for later requests,
// and bodies of a known length are spliced on Linux, as tunnels are.
package httpproxy

import (
	"errors"
	"net"
	"strconv"

	"github.com/djylb/netx"
)

// StatusError is an error with the HTTP status code that reports it to the
// client, such as 403 Forbidden from Allow. Err, if not nil, is the cause.
type StatusError struct {
	Code int
	Err  error
}

func (e *StatusError) Error() string {
	s := "httpproxy: " + strconv.Itoa(e.Code) + " " + StatusText(e.Code)
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *StatusError) Unwrap() error { return e.Err }

// Errors of authentication, answered with 407 Proxy Authentication Required
// and the authenticator's challenge.
var (
	// ErrAuthRequired is returned by an Authenticator for a request without
	// credentials, which clients send first to learn the scheme. A Server
	// does not pass it to OnError.
	ErrAuthRequired = errors.New("httpproxy: proxy authentication required")
	// ErrAuthFailed is returned by an Authenticator for wrong or malformed
	// credentials.
	ErrAuthFailed = errors.New("httpproxy: proxy authentication failed")
)

// StatusFor returns the status code that reports err to a client: the Code
// of a *StatusError (500 if it is not an error code), 407 for
// ErrAuthRequired and ErrAuthFailed, and otherwise the closest code for a
// failed dial: 504 Gateway Timeout for a timeout, 403 Forbidden for a
// permission error, and 502 Bad Gateway for the others, such as a refused
// connection, an unreachable host or a failed name lookup.
func StatusFor(err error) int {
	var se *StatusError
	switch {
	case err == nil:
		return 200
	case errors.As(err, &se):
		if se.Code < 400 || se.Code > 599 {
			return 500
		}
		return se.Code
	case errors.Is(err, ErrAuthRequired), errors.Is(err, ErrAuthFailed):
		return 407
	case netx.IsTimeout(err):
		return 504
	case netx.IsPermissionDenied(err):
		return 403
	default:
		return 502
	}
}

// StatusText returns the reason phrase of the status codes that a Server
// sends, and of the other common ones, or "" for codes it does not know.
func StatusText(code int) string {
	switch code {
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 200:
		return "OK"
	case 204:
		return "No Content"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 407:
		return "Proxy Authentication Required"
	case 408:
		return "Request Timeout"
	case 411:
		return "Length Required"
	case 413:
		return "Content Too Large"
	case 414:
		return "URI Too Long"
	case 417:
		return "Expectation Failed"
	case 429:
		return "Too Many Requests"
	case 431:
		return "Request Header Fields Too Large"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	case 505:
		return "HTTP Version Not Supported"
	}
	return ""
}

// isClosedRead reports whether err ends a wait for a request without a
// failure: the client closed or reset an idle connection.
func isClosedRead(err error) bool {
	return errors.Is(err, net.ErrClosed) || netx.IsConnReset(err) || netx.IsConnAborted(err) || netx.IsBrokenPipe(err)
}
