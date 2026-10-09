package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"strings"
)

// maxConnectReplyBytes bounds the status line and headers of a CONNECT reply.
const maxConnectReplyBytes = 64 << 10

type httpDialer struct {
	proxyAddr  string
	serverName string // set for https proxies
	auth       string // Proxy-Authorization value
	forward    ContextDialer
}

func newHTTPDialer(u *url.URL, useTLS bool, forward ContextDialer) *httpDialer {
	d := &httpDialer{forward: forward}
	if useTLS {
		d.proxyAddr = proxyAddress(u, "443")
		d.serverName = u.Hostname()
	} else {
		d.proxyAddr = proxyAddress(u, "80")
	}
	if u.User != nil {
		password, _ := u.User.Password()
		credentials := u.User.Username() + ":" + password
		d.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	}
	return d
}

func (d *httpDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("proxy: invalid target %q: %w", address, err)
	}
	if strings.IndexFunc(address, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("proxy: invalid target %q", address)
	}
	c, err := d.forward.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, err
	}
	return handshake(ctx, c, func() (net.Conn, error) {
		conn := c
		if d.serverName != "" {
			tc := tls.Client(c, &tls.Config{ServerName: d.serverName})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			conn = tc
		}
		return d.connect(conn, address)
	})
}

// connect sends a CONNECT request for address over c and reads the reply.
func (d *httpDialer) connect(c net.Conn, address string) (net.Conn, error) {
	req := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n"
	if d.auth != "" {
		req += "Proxy-Authorization: " + d.auth + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
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
		return &prefixConn{Conn: c, prefix: prefix}, nil
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
