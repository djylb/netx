package proxydial

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/djylb/netx"
)

// maxConnectReplyBytes bounds the status line and headers of a CONNECT reply.
const maxConnectReplyBytes = 64 << 10

// HTTPDialer dials through an HTTP proxy with the CONNECT method.
type HTTPDialer struct {
	// ProxyAddr is the proxy's host:port.
	ProxyAddr string
	// Username and Password are sent as Basic Proxy-Authorization (RFC
	// 7617) when either is not empty, unless Header holds a
	// Proxy-Authorization field, which then takes precedence, as for
	// another authentication scheme. Username cannot contain a colon.
	Username string
	Password string
	// TLSConfig, when set, makes the dialer speak TLS to the proxy, as for an
	// https proxy URL. An empty ServerName defaults to the proxy's host.
	TLSConfig *tls.Config
	// Header holds extra fields for the CONNECT request, such as
	// User-Agent or Proxy-Authorization.
	Header textproto.MIMEHeader
	// Forward dials the proxy; nil means a zero net.Dialer.
	Forward netx.ContextDialer
}

// Dial is DialContext with a background context, for code that expects a
// dialer without a context.
func (d *HTTPDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext dials the proxy and runs Handshake on the connection. ctx
// bounds the whole dial, and the returned connection has no deadline set.
// Networks other than tcp, tcp4 and tcp6 give an error matching
// errors.ErrUnsupported.
func (d *HTTPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	req, err := d.request(address)
	if err != nil {
		return nil, err
	}
	forward := forwardOf(d.Forward)
	if d.TLSConfig != nil {
		forward = &tlsDialer{config: d.tlsConfig(), forward: d.Forward}
	}
	c, err := forward.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, err
	}
	var tunnel net.Conn
	if err := handshake(ctx, c, func() (err error) {
		tunnel, err = connect(c, req)
		return err
	}); err != nil {
		return nil, err
	}
	return tunnel, nil
}

// Handshake asks the proxy behind c, an established connection to it, for a
// tunnel to address with a CONNECT request, as DialContext does after
// dialing; ProxyAddr, TLSConfig and Forward are not used. ctx bounds the
// handshake, as netx.DoWithContext does, and on success c has no deadline
// set. A reply other than 2xx is returned as a *ConnectError.
//
// The returned connection is c, or a *netx.PrefixConn over c when the proxy
// sent tunnel bytes along with its reply. On failure c is left open for the
// caller to close; after a timeout or the end of ctx it is unusable, and the
// connection beneath a *tls.Conn is already closed, so that closing it sends
// no close_notify the proxy cannot authenticate.
func (d *HTTPDialer) Handshake(ctx context.Context, c net.Conn, address string) (net.Conn, error) {
	req, err := d.request(address)
	if err != nil {
		return nil, err
	}
	var tunnel net.Conn
	if err := netx.DoWithContext(ctx, c, func() (err error) {
		tunnel, err = connect(c, req)
		return err
	}); err != nil {
		closeBeneathTLS(ctx, c, err)
		return nil, err
	}
	return tunnel, nil
}

// request builds the CONNECT request for address.
func (d *HTTPDialer) request(address string) ([]byte, error) {
	// A space or control character would end the request line early.
	if _, _, err := net.SplitHostPort(address); err != nil || hasControl(address) || strings.Contains(address, " ") {
		return nil, fmt.Errorf("proxydial: invalid target %q", address)
	}
	b := make([]byte, 0, 128)
	b = append(b, "CONNECT "+address+" HTTP/1.1\r\n"...)
	// Header names are case-insensitive, and a key without values sends
	// none.
	hasHost, hasAuth := false, false
	for key, values := range d.Header {
		hasHost = hasHost || strings.EqualFold(key, "Host") && len(values) > 0
		hasAuth = hasAuth || strings.EqualFold(key, "Proxy-Authorization") && len(values) > 0
	}
	if !hasHost {
		b = append(b, "Host: "+address+"\r\n"...)
	}
	if !hasAuth && (d.Username != "" || d.Password != "") {
		// The proxy would split the credentials at the first colon. The
		// error names neither of them.
		if strings.Contains(d.Username, ":") {
			return nil, errors.New("proxydial: Username contains a colon")
		}
		credentials := base64.StdEncoding.EncodeToString([]byte(d.Username + ":" + d.Password))
		b = append(b, "Proxy-Authorization: Basic "+credentials+"\r\n"...)
	}
	for key, values := range d.Header {
		for _, v := range values {
			if key == "" || hasControl(key) || strings.ContainsAny(key, " :") || invalidFieldValue(v) {
				return nil, fmt.Errorf("proxydial: invalid header field %q", key)
			}
			b = append(b, key+": "+v+"\r\n"...)
		}
	}
	return append(b, "\r\n"...), nil
}

func (d *HTTPDialer) tlsConfig() *tls.Config {
	host, _, err := net.SplitHostPort(d.ProxyAddr)
	if err != nil {
		host = d.ProxyAddr // no port, as for a Forward dialer of Unix sockets
	}
	return tlsConfigFor(d.TLSConfig, host)
}

// ConnectError is a proxy's reply other than 2xx to a CONNECT request, such
// as 407 Proxy Authentication Required with its Proxy-Authenticate fields,
// 403 Forbidden or 502 Bad Gateway.
type ConnectError struct {
	// StatusCode is the reply's status code, such as 407.
	StatusCode int
	// Status is the status code and reason phrase, such as
	// "407 Proxy Authentication Required", as the proxy sent them.
	Status string
	// Header holds the reply's header fields.
	Header textproto.MIMEHeader
}

// Error quotes the status, whose text the proxy chooses and which may hold
// control characters.
func (e *ConnectError) Error() string {
	return "proxydial: CONNECT: " + strconv.Quote(e.Status)
}

// connect sends a CONNECT request over c and reads the reply.
func connect(c net.Conn, req []byte) (net.Conn, error) {
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	// Only the status line and headers are parsed: a 2xx reply has no body
	// (RFC 9110, section 9.3.6), and the bytes after it belong to the tunnel.
	br := bufio.NewReader(io.LimitReader(c, maxConnectReplyBytes))
	tp := textproto.NewReader(br)
	code, status, err := readConnectStatus(tp)
	var header textproto.MIMEHeader
	if err == nil {
		header, err = tp.ReadMIMEHeader()
	}
	if err != nil {
		return nil, fmt.Errorf("proxydial: read CONNECT response: %w", err)
	}
	if code/100 != 2 {
		return nil, &ConnectError{StatusCode: code, Status: status, Header: header}
	}
	if n := br.Buffered(); n > 0 {
		prefix, _ := br.Peek(n)
		return netx.NewPrefixConn(c, prefix), nil
	}
	return c, nil
}

// readConnectStatus reads an HTTP/1.x status line and returns the status code
// and the status, such as 200 and "200 Connection established".
func readConnectStatus(tp *textproto.Reader) (int, string, error) {
	line, err := tp.ReadLine()
	if err != nil {
		return 0, "", err
	}
	proto, status, _ := strings.Cut(line, " ")
	code, _, _ := strings.Cut(status, " ")
	if !strings.HasPrefix(proto, "HTTP/1.") || len(code) != 3 || strings.Trim(code, "0123456789") != "" {
		return 0, "", fmt.Errorf("malformed status line %q", line)
	}
	n, _ := strconv.Atoi(code)
	return n, status, nil
}

// invalidFieldValue reports whether v contains a control character other
// than the horizontal tab, which header values may contain (RFC 9110).
func invalidFieldValue(v string) bool {
	return strings.IndexFunc(v, func(r rune) bool { return r != '\t' && (r < ' ' || r == 0x7f) }) >= 0
}

// hasControl reports whether s contains a control character. Spaces, which
// header values may contain, are not.
func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0
}
