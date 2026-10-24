package wsconn

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/netx/httphead"
)

// HandshakeError is an opening handshake that failed for a reason of HTTP
// or of the protocol. It matches ErrHandshake.
type HandshakeError struct {
	// Status is the HTTP status: on a server the one it answers with, on a
	// client the one it got, or 0 for a response that was malformed.
	Status int
	// Msg describes the failure.
	Msg string
	// Response is the response a client got, if any.
	Response *httphead.Response
}

func (e *HandshakeError) Error() string {
	if e.Status != 0 {
		return "wsconn: handshake failed with status " + strconv.Itoa(e.Status) + ": " + e.Msg
	}
	return "wsconn: handshake failed: " + e.Msg
}

func (e *HandshakeError) Unwrap() error { return ErrHandshake }

func handshakeError(status int, msg string) *HandshakeError {
	return &HandshakeError{Status: status, Msg: msg}
}

// ServerOptions configure the server side of a connection.
type ServerOptions struct {
	Options
	// Subprotocols are the subprotocols the server speaks, by preference:
	// the first of them that the client offers is chosen. Without a match
	// the connection has no subprotocol.
	Subprotocols []string
	// CheckOrigin decides on the request, typically on its Origin field;
	// an error refuses it, with the status of a *HandshakeError from 400 to
	// 599, or else 403 Forbidden. Nil accepts requests without an Origin field and those
	// whose origin's host is the request's Host, as browsers send for
	// pages of the same site. Clients other than browsers seldom send an
	// Origin; AnyOrigin accepts every request.
	CheckOrigin func(req *httphead.Request) error
	// Header holds fields added to the 101 response, such as Set-Cookie.
	Header httphead.Header
	// HandshakeTimeout bounds Accept and AcceptRequest when their context
	// has no deadline; zero means DefaultHandshakeTimeout, and a negative
	// timeout leaves them unbounded.
	HandshakeTimeout time.Duration
	// MaxHeaderBytes bounds the request head that Accept reads; zero means
	// DefaultMaxHeaderBytes.
	MaxHeaderBytes int
}

// AnyOrigin is a ServerOptions.CheckOrigin that accepts every request.
func AnyOrigin(_ *httphead.Request) error { return nil }

// Handshake is a request that CheckRequest accepted, ready for the 101
// response.
type Handshake struct {
	// Request is the request.
	Request *httphead.Request
	// Subprotocol is the chosen subprotocol, or "".
	Subprotocol string
	// Compressed tells whether permessage-deflate was accepted.
	Compressed bool
	// ExtendedConnect tells whether the request is an HTTP/2 extended
	// CONNECT (RFC 8441), to be answered with 200 and ResponseHeader.
	ExtendedConnect bool

	opts       *ServerOptions
	accept     string
	extensions string // the Sec-WebSocket-Extensions value
}

// CheckRequest checks an opening handshake request (RFC 6455, section
// 4.2.1), its origin, and negotiates its subprotocol and compression. It
// returns a *HandshakeError with the status to answer with, such as 400 or
// 426 Upgrade Required for a version other than 13, which needs a
// Sec-WebSocket-Version: 13 field in the answer. opts may be nil.
//
// Field names and tokens are matched case-insensitively; the request must
// be a GET of HTTP/1.1 or later, with Upgrade: websocket, Connection:
// Upgrade, Sec-WebSocket-Version: 13 and a Sec-WebSocket-Key of 16 bytes.
// A missing Host field is tolerated.
//
// A request of HTTP/2's extended CONNECT (RFC 8441) is a CONNECT request
// whose fields hold the pseudo-field ":protocol", as net/http presents it,
// which no HTTP/1 request can hold: it must be websocket, with
// Sec-WebSocket-Version: 13; a Sec-WebSocket-Key, which RFC 8441 does not
// use, is ignored. Such a handshake is answered with 200 and the fields of
// ResponseHeader, over the request's stream.
func CheckRequest(req *httphead.Request, opts *ServerOptions) (*Handshake, error) {
	if opts == nil {
		opts = &ServerOptions{}
	}
	h := &req.Header
	if req.Method == "CONNECT" && h.Has(":protocol") {
		switch {
		case !strings.EqualFold(httphead.TrimOWS(h.Get(":protocol")), "websocket") || h.Count(":protocol") != 1:
			return nil, handshakeError(400, "extended CONNECT for a protocol other than websocket")
		case httphead.TrimOWS(h.Get("Sec-WebSocket-Version")) != "13" || h.Count("Sec-WebSocket-Version") != 1:
			return nil, handshakeError(426, "unsupported Sec-WebSocket-Version")
		}
		return negotiate(&Handshake{Request: req, ExtendedConnect: true, opts: opts})
	}
	switch {
	case req.Method != "GET":
		return nil, handshakeError(405, "method "+req.Method+", not GET")
	case req.Minor < 1:
		return nil, handshakeError(505, "HTTP/1.0 request")
	case !h.HasToken("Upgrade", "websocket"):
		return nil, handshakeError(426, "no Upgrade: websocket field")
	case !h.HasToken("Connection", "upgrade"):
		return nil, handshakeError(400, "no Connection: Upgrade field")
	case httphead.TrimOWS(h.Get("Sec-WebSocket-Version")) != "13" || h.Count("Sec-WebSocket-Version") != 1:
		return nil, handshakeError(426, "unsupported Sec-WebSocket-Version")
	}
	key := httphead.TrimOWS(h.Get("Sec-WebSocket-Key"))
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 || h.Count("Sec-WebSocket-Key") != 1 {
		return nil, handshakeError(400, "invalid Sec-WebSocket-Key")
	}
	return negotiate(&Handshake{Request: req, opts: opts, accept: AcceptKey(key)})
}

// negotiate checks the origin of a handshake and picks its subprotocol
// and compression.
func negotiate(hs *Handshake) (*Handshake, error) {
	req, opts, h := hs.Request, hs.opts, &hs.Request.Header
	check := opts.CheckOrigin
	if check == nil {
		check = sameOrigin
	}
	if err := check(req); err != nil {
		var he *HandshakeError
		if errors.As(err, &he) && he.Status >= 400 && he.Status <= 599 {
			return nil, he
		}
		return nil, handshakeError(403, err.Error())
	}
	if len(opts.Subprotocols) > 0 {
		offered := tokenList(h, "Sec-WebSocket-Protocol")
		for _, p := range opts.Subprotocols {
			if slices.Contains(offered, p) {
				hs.Subprotocol = p
				break
			}
		}
	}
	if opts.Compression != nil {
		hs.extensions, hs.Compressed = acceptDeflate(h)
	}
	return hs, nil
}

// sameOrigin is the default CheckOrigin.
func sameOrigin(req *httphead.Request) error {
	origin := req.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	u, err := url.Parse(origin)
	if err == nil && u.Host != "" && strings.EqualFold(u.Host, req.Header.Get("Host")) {
		return nil
	}
	return handshakeError(403, "origin "+strconv.Quote(origin)+" is not the request's host")
}

// tokenList returns the comma-separated elements of the fields named name.
func tokenList(h *httphead.Header, name string) []string {
	var list []string
	for _, v := range h.Values(name) {
		for t := range httphead.Tokens(v) {
			list = append(list, t)
		}
	}
	return list
}

// ResponseHeader returns the fields of the response that are the
// handshake's: Sec-WebSocket-Protocol and Sec-WebSocket-Extensions if
// negotiated, then ServerOptions.Header; for an HTTP/2 handshake, which
// answers with 200 and these fields.
func (hs *Handshake) ResponseHeader() httphead.Header {
	var h httphead.Header
	if hs.Subprotocol != "" {
		h = append(h, httphead.Field{Name: "Sec-WebSocket-Protocol", Value: hs.Subprotocol})
	}
	if hs.Compressed {
		h = append(h, httphead.Field{Name: "Sec-WebSocket-Extensions", Value: hs.extensions})
	}
	return append(h, hs.opts.Header...)
}

// errExtendedConnect is returned for HTTP/1 responses to an HTTP/2
// handshake.
var errExtendedConnect = errors.New("wsconn: an HTTP/2 handshake is answered with 200 and ResponseHeader")

// AppendResponse appends the 101 response head to b. It fails when a field
// of ServerOptions.Header cannot be sent, and for an HTTP/2 handshake.
func (hs *Handshake) AppendResponse(b []byte) ([]byte, error) {
	if hs.ExtendedConnect {
		return b, errExtendedConnect
	}
	b = append(b, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "...)
	b = append(b, hs.accept...)
	b = append(b, "\r\n"...)
	if hs.Subprotocol != "" {
		b = append(b, "Sec-WebSocket-Protocol: "...)
		b = append(b, hs.Subprotocol...)
		b = append(b, "\r\n"...)
	}
	if hs.Compressed {
		b = append(b, "Sec-WebSocket-Extensions: "...)
		b = append(b, hs.extensions...)
		b = append(b, "\r\n"...)
	}
	b, err := hs.opts.Header.AppendTo(b)
	if err != nil {
		return b, err
	}
	return append(b, "\r\n"...), nil
}

// Accept sends the 101 response over conn and returns the connection. br,
// if not nil, is the buffered reader that the request was read from, which
// may hold frames the client sent at once. ctx bounds the write as in
// Accept. On failure conn is closed.
func (hs *Handshake) Accept(ctx context.Context, conn net.Conn, br *bufio.Reader) (*Conn, error) {
	resp, err := hs.AppendResponse(nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	err = doHandshake(ctx, conn, hs.opts.HandshakeTimeout, func() error {
		_, err := conn.Write(resp)
		return err
	})
	if err != nil {
		return nil, err
	}
	return hs.conn(conn, br), nil
}

// NewConn returns the connection over conn after the response was sent by
// other means, such as the 200 response of an HTTP/2 handshake over its
// stream; br, if not nil, is the buffered reader over conn.
func (hs *Handshake) NewConn(conn net.Conn, br *bufio.Reader) *Conn { return hs.conn(conn, br) }

func (hs *Handshake) conn(conn net.Conn, br *bufio.Reader) *Conn {
	var dc *deflateConfig
	if hs.Compressed {
		dc = hs.opts.Compression.config()
	}
	c := newConn(conn, br, false, &hs.opts.Options, dc)
	c.subprotocol = hs.Subprotocol
	c.request = hs.Request
	return c
}

// Accept reads an opening handshake request from conn and answers it, and
// returns the connection. A request that CheckRequest refuses is answered
// with its status. ctx bounds the handshake, as does
// ServerOptions.HandshakeTimeout when ctx has no deadline; on failure conn
// is closed. opts may be nil.
//
// To serve WebSocket next to other protocols on one port, read the request
// first and call AcceptRequest when it is an upgrade.
func Accept(ctx context.Context, conn net.Conn, opts *ServerOptions) (*Conn, error) {
	if opts == nil {
		opts = &ServerOptions{}
	}
	var c *Conn
	err := doHandshake(ctx, conn, opts.HandshakeTimeout, func() error {
		br := bufio.NewReaderSize(conn, opts.readBufferSize())
		limit := opts.MaxHeaderBytes
		if limit <= 0 {
			limit = DefaultMaxHeaderBytes
		}
		head, err := httphead.Read(br, nil, limit)
		if err != nil {
			if errors.Is(err, httphead.ErrTooLarge) {
				return reject(conn, handshakeError(431, "request head too large"))
			}
			return err
		}
		req, err := httphead.ParseRequest(string(head), nil)
		if err != nil {
			status := 400
			if errors.Is(err, httphead.ErrVersion) {
				status = 505
			}
			return reject(conn, handshakeError(status, err.Error()))
		}
		c, err = accept(conn, br, &req, opts)
		return err
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// AcceptRequest answers the opening handshake request req, which was read
// from conn, and returns the connection; br, if not nil, is the buffered
// reader that req was read from. It is Accept for a request read already.
func AcceptRequest(ctx context.Context, conn net.Conn, br *bufio.Reader, req *httphead.Request, opts *ServerOptions) (*Conn, error) {
	if opts == nil {
		opts = &ServerOptions{}
	}
	var c *Conn
	err := doHandshake(ctx, conn, opts.HandshakeTimeout, func() error {
		var err error
		c, err = accept(conn, br, req, opts)
		return err
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func accept(conn net.Conn, br *bufio.Reader, req *httphead.Request, opts *ServerOptions) (*Conn, error) {
	hs, err := CheckRequest(req, opts)
	if err != nil {
		var he *HandshakeError
		if errors.As(err, &he) {
			return nil, reject(conn, he)
		}
		return nil, err
	}
	resp, err := hs.AppendResponse(nil)
	if err != nil {
		return nil, reject(conn, handshakeError(500, err.Error()))
	}
	if _, err := conn.Write(resp); err != nil {
		return nil, err
	}
	return hs.conn(conn, br), nil
}

// reject answers with e's status and returns e.
func reject(conn net.Conn, e *HandshakeError) error {
	b := make([]byte, 0, 160+len(e.Msg))
	b = append(b, "HTTP/1.1 "...)
	b = strconv.AppendInt(b, int64(e.Status), 10)
	b = append(b, ' ')
	b = append(b, statusText(e.Status)...)
	b = append(b, "\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n"...)
	if e.Status == 426 {
		b = append(b, "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"...)
	}
	b = append(b, "Content-Length: "...)
	b = strconv.AppendInt(b, int64(len(e.Msg)+1), 10)
	b = append(b, "\r\n\r\n"...)
	b = append(b, e.Msg...)
	b = append(b, '\n')
	_, _ = conn.Write(b)
	return e
}

func statusText(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 405:
		return "Method Not Allowed"
	case 426:
		return "Upgrade Required"
	case 431:
		return "Request Header Fields Too Large"
	case 500:
		return "Internal Server Error"
	case 505:
		return "HTTP Version Not Supported"
	}
	return "Error"
}

// pastDeadline interrupts blocked I/O.
var pastDeadline = time.Unix(1, 0)

// doHandshake runs fn, an exchange on conn, bounded by ctx, or by timeout
// when ctx has no deadline and timeout is not negative (zero meaning
// DefaultHandshakeTimeout). It clears conn's deadline after a success and
// closes conn after a failure, returning ctx's error when ctx ended fn.
func doHandshake(ctx context.Context, conn net.Conn, timeout time.Duration, fn func() error) error {
	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}
	if _, ok := ctx.Deadline(); !ok && timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = conn.SetDeadline(deadline)
	}
	// The interrupt sets the deadline only while fn runs.
	var mu sync.Mutex
	running := true
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if running && conn.SetDeadline(pastDeadline) != nil {
			_ = conn.Close()
		}
	})
	err := fn()
	stop()
	mu.Lock()
	running = false
	mu.Unlock()
	if err == nil {
		_ = conn.SetDeadline(time.Time{})
		return nil
	}
	_ = conn.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if hasDeadline && isTimeout(err) {
		return context.DeadlineExceeded
	}
	return err
}
