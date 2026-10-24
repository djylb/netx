package wsconn

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/internal/netutil"
)

// ClientOptions configure the client side of a connection.
type ClientOptions struct {
	Options
	// Host, if set, is the Host field of the request, rather than the
	// URL's host, as for a server behind a front whose name is dialed.
	Host string
	// Header holds fields added to the request, such as Origin,
	// Authorization or Cookie. It must not hold Host or the fields of the
	// handshake itself: Upgrade, Connection and those that start with
	// Sec-WebSocket-.
	Header httphead.Header
	// Subprotocols are offered by preference in Sec-WebSocket-Protocol.
	Subprotocols []string
	// HandshakeTimeout bounds Client and Dialer.Dial when their context has
	// no deadline; zero means DefaultHandshakeTimeout, and a negative
	// timeout leaves them unbounded.
	HandshakeTimeout time.Duration
	// MaxHeaderBytes bounds the response head; zero means
	// DefaultMaxHeaderBytes.
	MaxHeaderBytes int
}

// Client runs the opening handshake for the ws or wss URL rawURL over
// conn, which reaches its server, over TLS for wss as the caller set up,
// and returns the connection and the server's response. A response other
// than 101 Switching Protocols, or one that does not complete the
// handshake, fails with a *HandshakeError that holds the response. ctx
// bounds the handshake, as does ClientOptions.HandshakeTimeout when ctx
// has no deadline; on failure conn is closed. opts may be nil.
//
// The URL's userinfo, if any, is sent as Basic credentials unless Header
// holds an Authorization field; the fragment is left out. The schemes http
// and https are taken as ws and wss.
func Client(ctx context.Context, conn net.Conn, rawURL string, opts *ClientOptions) (*Conn, *httphead.Response, error) {
	if opts == nil {
		opts = &ClientOptions{}
	}
	u, err := parseURL(rawURL)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	req, key, err := buildRequest(u, opts)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	var c *Conn
	var resp *httphead.Response
	err = doHandshake(ctx, conn, opts.HandshakeTimeout, func() error {
		if _, err := conn.Write(req); err != nil {
			return err
		}
		br := bufio.NewReaderSize(conn, opts.readBufferSize())
		limit := opts.MaxHeaderBytes
		if limit <= 0 {
			limit = DefaultMaxHeaderBytes
		}
		head, err := httphead.Read(br, nil, limit)
		if err != nil {
			if err == io.EOF {
				err = errors.New("wsconn: connection closed before the handshake response")
			}
			return err
		}
		r, err := httphead.ParseResponse(string(head), nil)
		if err != nil {
			return &HandshakeError{Msg: err.Error()}
		}
		resp = &r
		dc, sub, err := checkResponse(resp, key, opts)
		if err != nil {
			return err
		}
		c = newConn(conn, br, true, &opts.Options, dc)
		c.subprotocol = sub
		c.response = resp
		return nil
	})
	if err != nil {
		return nil, resp, err
	}
	return c, resp, nil
}

// parseURL parses a ws, wss, http or https URL with a host.
func parseURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "ws", "wss", "http", "https":
	default:
		return nil, errors.New("wsconn: URL scheme " + u.Scheme + " is not ws or wss")
	}
	if u.Host == "" {
		return nil, errors.New("wsconn: URL without a host")
	}
	return u, nil
}

// secure reports whether u is a wss URL.
func secure(u *url.URL) bool { return u.Scheme == "wss" || u.Scheme == "https" }

// reservedField reports whether a request field is the handshake's own.
func reservedField(name string) bool {
	for _, n := range []string{"Host", "Upgrade", "Connection"} {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return len(name) >= len("Sec-WebSocket-") && strings.EqualFold(name[:len("Sec-WebSocket-")], "Sec-WebSocket-")
}

// buildRequest returns the handshake request for u and its key.
func buildRequest(u *url.URL, opts *ClientOptions) ([]byte, string, error) {
	for _, f := range opts.Header {
		if reservedField(f.Name) {
			return nil, "", errors.New("wsconn: ClientOptions.Header holds " + f.Name)
		}
	}
	var raw [16]byte
	binary.LittleEndian.PutUint64(raw[:], rand.Uint64())
	binary.LittleEndian.PutUint64(raw[8:], rand.Uint64())
	key := base64.StdEncoding.EncodeToString(raw[:])
	target := u.RequestURI()
	for i := 0; i < len(target); i++ {
		if c := target[i]; c <= ' ' || c == 0x7f {
			return nil, "", errors.New("wsconn: URL path or query with a space or control character")
		}
	}
	host := u.Host
	if opts.Host != "" {
		host = opts.Host
	}
	b := make([]byte, 0, 256)
	b = append(b, "GET "...)
	b = append(b, target...)
	b = append(b, " HTTP/1.1\r\nHost: "...)
	b = append(b, host...)
	b = append(b, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "...)
	b = append(b, key...)
	b = append(b, "\r\nSec-WebSocket-Version: 13\r\n"...)
	if len(opts.Subprotocols) > 0 {
		for _, p := range opts.Subprotocols {
			if !httphead.ValidFieldName(p) {
				return nil, "", errors.New("wsconn: subprotocol " + p + " is not a token")
			}
		}
		b = append(b, "Sec-WebSocket-Protocol: "...)
		b = append(b, strings.Join(opts.Subprotocols, ", ")...)
		b = append(b, "\r\n"...)
	}
	if opts.Compression != nil {
		b = append(b, "Sec-WebSocket-Extensions: "+deflateOffer+"\r\n"...)
	}
	if u.User != nil && !opts.Header.Has("Authorization") {
		pass, _ := u.User.Password()
		b = append(b, "Authorization: Basic "...)
		b = append(b, base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass))...)
		b = append(b, "\r\n"...)
	}
	b, err := opts.Header.AppendTo(b)
	if err != nil {
		return nil, "", err
	}
	if !httphead.ValidFieldValue(host) || strings.ContainsAny(host, " \t") {
		return nil, "", errors.New("wsconn: invalid Host " + host)
	}
	return append(b, "\r\n"...), key, nil
}

// checkResponse checks the server's response (RFC 6455, section 4.1).
func checkResponse(resp *httphead.Response, key string, opts *ClientOptions) (*deflateConfig, string, error) {
	fail := func(msg string) error {
		return &HandshakeError{Status: resp.Code, Msg: msg, Response: resp}
	}
	h := &resp.Header
	switch {
	case resp.Code != 101:
		return nil, "", fail("not 101 Switching Protocols")
	case !h.HasToken("Upgrade", "websocket"):
		return nil, "", fail("no Upgrade: websocket field")
	case !h.HasToken("Connection", "upgrade"):
		return nil, "", fail("no Connection: Upgrade field")
	case httphead.TrimOWS(h.Get("Sec-WebSocket-Accept")) != AcceptKey(key):
		return nil, "", fail("wrong Sec-WebSocket-Accept")
	}
	return checkNegotiated(resp, opts)
}

// checkNegotiated checks the subprotocol and extensions of a response.
func checkNegotiated(resp *httphead.Response, opts *ClientOptions) (*deflateConfig, string, error) {
	fail := func(msg string) error {
		return &HandshakeError{Status: resp.Code, Msg: msg, Response: resp}
	}
	h := &resp.Header
	sub := ""
	if protos := tokenList(h, "Sec-WebSocket-Protocol"); len(protos) > 0 {
		if len(protos) > 1 || !slices.Contains(opts.Subprotocols, protos[0]) {
			return nil, "", fail("unrequested subprotocol")
		}
		sub = protos[0]
	}
	compressed, err := checkDeflateResponse(h, opts.Compression != nil)
	if err != nil {
		return nil, "", fail(err.Error())
	}
	var dc *deflateConfig
	if compressed {
		dc = opts.Compression.config()
	}
	return dc, sub, nil
}

// ExtendedConnectHeader returns the fields of an HTTP/2 extended CONNECT
// request (RFC 8441) for the options, after the pseudo-field
// ":protocol: websocket" that the caller sends: Sec-WebSocket-Version,
// Sec-WebSocket-Protocol and Sec-WebSocket-Extensions as offered, then
// Header.
func (o *ClientOptions) ExtendedConnectHeader() (httphead.Header, error) {
	for _, f := range o.Header {
		if reservedField(f.Name) {
			return nil, errors.New("wsconn: ClientOptions.Header holds " + f.Name)
		}
	}
	h := httphead.Header{{Name: "Sec-WebSocket-Version", Value: "13"}}
	if len(o.Subprotocols) > 0 {
		for _, p := range o.Subprotocols {
			if !httphead.ValidFieldName(p) {
				return nil, errors.New("wsconn: subprotocol " + p + " is not a token")
			}
		}
		h = append(h, httphead.Field{Name: "Sec-WebSocket-Protocol", Value: strings.Join(o.Subprotocols, ", ")})
	}
	if o.Compression != nil {
		h = append(h, httphead.Field{Name: "Sec-WebSocket-Extensions", Value: deflateOffer})
	}
	return append(h, o.Header...), nil
}

// ExtendedConnectClient checks the response to an HTTP/2 extended CONNECT
// request with the fields of ExtendedConnectHeader, which must be 200 with
// a subprotocol and extensions that were offered, and returns the client
// connection over conn, the request's stream. On failure conn is closed.
func ExtendedConnectClient(conn net.Conn, resp *httphead.Response, opts *ClientOptions) (*Conn, error) {
	if opts == nil {
		opts = &ClientOptions{}
	}
	if resp.Code != 200 {
		_ = conn.Close()
		return nil, &HandshakeError{Status: resp.Code, Msg: "not 200", Response: resp}
	}
	dc, sub, err := checkNegotiated(resp, opts)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c := newConn(conn, nil, true, &opts.Options, dc)
	c.subprotocol = sub
	c.response = resp
	return c, nil
}

// ContextDialer dials connections. *net.Dialer implements it, as do the
// dialers of tlsconn and proxydial.
type ContextDialer = netutil.ContextDialer

// ErrNoTLSDialer is returned by Dialer.Dial for a wss URL without
// Dialer.TLS.
var ErrNoTLSDialer = errors.New("wsconn: wss URL without a TLS dialer")

// Dialer dials WebSocket connections.
type Dialer struct {
	ClientOptions
	// Forward dials the TCP connections of ws URLs; nil means a zero
	// net.Dialer. It may reach the server through a proxy.
	Forward ContextDialer
	// TLS dials the TLS connections of wss URLs, verifying the server as
	// its configuration says, such as a tlsconn.Dialer, which verifies
	// the certificate for the dialed host by default and whose Forward may
	// be a proxy dialer. Without it wss URLs fail with ErrNoTLSDialer, so
	// that this package does not link crypto/tls.
	TLS ContextDialer
}

// Dial dials rawURL and runs the opening handshake as Client does. ctx, or
// HandshakeTimeout when it has no deadline, bounds the dial and the
// handshakes.
func (d *Dialer) Dial(ctx context.Context, rawURL string) (*Conn, *httphead.Response, error) {
	u, err := parseURL(rawURL)
	if err != nil {
		return nil, nil, err
	}
	timeout := d.HandshakeTimeout
	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}
	if _, ok := ctx.Deadline(); !ok && timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if secure(u) {
			port = "443"
		}
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	var dialer ContextDialer = &net.Dialer{}
	switch {
	case secure(u) && d.TLS == nil:
		return nil, nil, ErrNoTLSDialer
	case secure(u):
		dialer = d.TLS
	case d.Forward != nil:
		dialer = d.Forward
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	return Client(ctx, conn, rawURL, &d.ClientOptions)
}
