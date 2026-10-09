package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"

	"github.com/djylb/netx"
)

// maxConnectReplyBytes bounds the status line and headers of a CONNECT reply.
const maxConnectReplyBytes = 64 << 10

// HTTPDialer dials through an HTTP proxy with the CONNECT method.
type HTTPDialer struct {
	// ProxyAddr is the proxy's host:port.
	ProxyAddr string
	// TLSConfig, when set, makes the dialer speak TLS to the proxy, as for an
	// https proxy URL. An empty ServerName defaults to the proxy's host.
	TLSConfig *tls.Config
	// Header holds extra fields for the CONNECT request, such as
	// Proxy-Authorization or User-Agent.
	Header textproto.MIMEHeader
	// Forward dials the proxy; nil means a zero net.Dialer.
	Forward ContextDialer
}

// Dial is DialContext with a background context, matching the Dialer
// interface of golang.org/x/net/proxy.
func (d *HTTPDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to address through the proxy. ctx bounds the whole
// dial, and the returned connection has no deadline set. Bytes the proxy sends
// right after its reply are kept.
func (d *HTTPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	if _, _, err := net.SplitHostPort(address); err != nil || hasControl(address) {
		return nil, fmt.Errorf("proxy: invalid target %q", address)
	}
	req, err := d.request(address)
	if err != nil {
		return nil, err
	}
	c, err := forwardOf(d.Forward).DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, err
	}
	return handshake(ctx, c, func() (net.Conn, error) {
		conn := c
		if d.TLSConfig != nil {
			tc := tls.Client(c, d.tlsConfig())
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			conn = tc
		}
		return connect(conn, address, req)
	})
}

// request builds the CONNECT request for address.
func (d *HTTPDialer) request(address string) ([]byte, error) {
	b := make([]byte, 0, 128)
	b = append(b, "CONNECT "+address+" HTTP/1.1\r\n"...)
	if _, ok := d.Header["Host"]; !ok {
		b = append(b, "Host: "+address+"\r\n"...)
	}
	for key, values := range d.Header {
		for _, v := range values {
			if key == "" || hasControl(key) || strings.ContainsAny(key, " :") || hasControl(v) {
				return nil, fmt.Errorf("proxy: invalid header field %q", key)
			}
			b = append(b, key+": "+v+"\r\n"...)
		}
	}
	return append(b, "\r\n"...), nil
}

func (d *HTTPDialer) tlsConfig() *tls.Config {
	if d.TLSConfig.ServerName != "" {
		return d.TLSConfig
	}
	cfg := d.TLSConfig.Clone()
	cfg.ServerName, _, _ = net.SplitHostPort(d.ProxyAddr)
	return cfg
}

// connect sends a CONNECT request over c and reads the reply.
func connect(c net.Conn, address string, req []byte) (net.Conn, error) {
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	// Only the status line and headers are parsed: a 2xx reply has no body
	// (RFC 9110, section 9.3.6), and the bytes after it belong to the tunnel.
	br := bufio.NewReader(io.LimitReader(c, maxConnectReplyBytes))
	tp := textproto.NewReader(br)
	status, err := readConnectStatus(tp)
	if err == nil {
		_, err = tp.ReadMIMEHeader()
	}
	if err != nil {
		return nil, fmt.Errorf("proxy: read CONNECT response: %w", err)
	}
	if status[0] != '2' {
		return nil, fmt.Errorf("proxy: CONNECT %s: %s", address, status)
	}
	if n := br.Buffered(); n > 0 {
		prefix, _ := br.Peek(n)
		return netx.NewPrefixConn(c, prefix), nil
	}
	return c, nil
}

// readConnectStatus reads an HTTP/1.x status line and returns the status, such
// as "200 Connection established".
func readConnectStatus(tp *textproto.Reader) (string, error) {
	line, err := tp.ReadLine()
	if err != nil {
		return "", err
	}
	proto, status, _ := strings.Cut(line, " ")
	code, _, _ := strings.Cut(status, " ")
	if !strings.HasPrefix(proto, "HTTP/1.") || len(code) != 3 || strings.Trim(code, "0123456789") != "" {
		return "", fmt.Errorf("malformed status line %q", line)
	}
	return status, nil
}

// hasControl reports whether s contains a space or a control character.
func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0
}
