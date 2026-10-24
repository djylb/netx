package wshttp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/wsconn"
)

// Dialer dials WebSocket over HTTP/2 (RFC 8441): each connection is an
// extended CONNECT stream, and connections to one server share the HTTP/2
// connections of the transport.
type Dialer struct {
	wsconn.ClientOptions
	// Transport sends the extended CONNECT requests over HTTP/2: a
	// RoundTripper that takes the pseudo-field ":protocol" in the request
	// header, such as the Transport of golang.org/x/net/http2 used on its
	// own, over TLS, or unencrypted with AllowHTTP. net/http's Transport
	// refuses it as an invalid field name, so there is no default; from
	// Go 1.27 that Transport of golang.org/x/net/http2 hands requests to
	// net/http's unless built with the http2legacy tag, and refuses it too.
	Transport http.RoundTripper
	// HTTP1, if set, dials the URL over HTTP/1.1 when the HTTP/2 request
	// fails, such as on a server without HTTP/2 or extended CONNECT, or
	// when Transport is nil. Without it no HTTP/1.1 is tried.
	HTTP1 *wsconn.Dialer
}

// ErrNoTransport is returned by Dialer.Dial without a Transport or HTTP1.
var ErrNoTransport = errors.New("wshttp: Dialer without a Transport")

// Dial dials rawURL, a ws or wss URL, with an extended CONNECT and returns
// the connection and the response, which is a *HandshakeError's when the
// server refuses. ctx, or HandshakeTimeout when it has no deadline, bounds
// the handshake, not the connection, and with it also an HTTP/1.1
// attempt: when the request fails and HTTP1 is set, it dials over
// HTTP/1.1. The URL's userinfo, if any, is sent as Basic credentials
// unless Header holds an Authorization field, as over HTTP/1.1.
func (d *Dialer) Dial(ctx context.Context, rawURL string) (*wsconn.Conn, *httphead.Response, error) {
	// One bound for both attempts.
	timeout := d.HandshakeTimeout
	if timeout == 0 {
		timeout = wsconn.DefaultHandshakeTimeout
	}
	if _, ok := ctx.Deadline(); !ok && timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	c, resp, err := d.dial(ctx, rawURL)
	if err == nil || d.HTTP1 == nil || resp != nil || ctx.Err() != nil {
		return c, resp, err
	}
	c, resp, err1 := d.HTTP1.Dial(ctx, rawURL)
	if err1 != nil {
		return nil, resp, fmt.Errorf("wshttp: HTTP/2: %w; HTTP/1.1: %w", err, err1)
	}
	return c, resp, nil
}

func (d *Dialer) dial(ctx context.Context, rawURL string) (*wsconn.Conn, *httphead.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if d.Transport == nil {
		return nil, nil, ErrNoTransport
	}
	switch u.Scheme {
	case "ws", "http":
		u.Scheme = "http"
	case "wss", "https":
		u.Scheme = "https"
	default:
		return nil, nil, errors.New("wshttp: URL scheme " + u.Scheme + " is not ws or wss")
	}
	u.Fragment, u.RawFragment = "", ""
	fields, err := d.ExtendedConnectHeader()
	if err != nil {
		return nil, nil, err
	}
	if u.User != nil {
		// As wsconn.Client does over HTTP/1.1.
		if !d.Header.Has("Authorization") {
			pass, _ := u.User.Password()
			cred := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pass))
			fields = append(fields, httphead.Field{Name: "Authorization", Value: "Basic " + cred})
		}
		u.User = nil
	}
	// The stream outlives ctx, which bounds only the handshake.
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	sc := &clientConn{cancel: cancel}
	streamCtx = httptrace.WithClientTrace(streamCtx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			sc.local, sc.remote = info.Conn.LocalAddr(), info.Conn.RemoteAddr()
		},
	})
	pr, pw := io.Pipe()
	sc.pw = pw
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, u.String(), pr)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.Header[":protocol"] = []string{"websocket"}
	for _, f := range fields {
		req.Header.Add(f.Name, f.Value)
	}
	if d.Host != "" {
		req.Host = d.Host
	}
	stop := context.AfterFunc(ctx, cancel)
	r, err := d.Transport.RoundTrip(req)
	if !stop() {
		if err == nil {
			_ = r.Body.Close()
		}
		_ = pw.Close()
		cancel()
		return nil, nil, ctx.Err()
	}
	if err != nil {
		_ = pw.Close()
		cancel()
		return nil, nil, err
	}
	resp := response(r)
	sc.body = r.Body
	c, err := wsconn.ExtendedConnectClient(sc, resp, &d.ClientOptions)
	if err != nil {
		return nil, resp, err
	}
	return c, resp, nil
}

// response returns r's head as an httphead response.
func response(r *http.Response) *httphead.Response {
	n := 0
	for _, vs := range r.Header {
		n += len(vs)
	}
	h := make(httphead.Header, 0, n)
	for name, vs := range r.Header {
		for _, v := range vs {
			h = append(h, httphead.Field{Name: name, Value: v})
		}
	}
	return &httphead.Response{
		Proto:  r.Proto,
		Minor:  r.ProtoMinor,
		Code:   r.StatusCode,
		Reason: strings.TrimSpace(strings.TrimPrefix(r.Status, fmt.Sprint(r.StatusCode))),
		Header: h,
	}
}

// clientConn is a net.Conn over the stream of an extended CONNECT on the
// client: it writes the request body and reads the response body. Its
// deadlines reset the stream when they expire, as net/http's server does
// on HTTP/2.
type clientConn struct {
	pw            *io.PipeWriter
	body          io.ReadCloser
	cancel        context.CancelFunc
	local, remote net.Addr

	mu      sync.Mutex
	rd, wd  *time.Timer
	expired bool
	once    sync.Once
}

func (c *clientConn) Read(p []byte) (int, error) {
	n, err := c.body.Read(p)
	if err != nil && c.isExpired() {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *clientConn) Write(p []byte) (int, error) {
	if c.isExpired() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.pw.Write(p)
	if err != nil && c.isExpired() {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *clientConn) isExpired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expired
}

// Close ends the request body, which ends the stream on the client's side,
// and the response body, and releases the stream.
func (c *clientConn) Close() error {
	c.once.Do(func() {
		_ = c.pw.Close()
		_ = c.body.Close()
		c.cancel()
		c.mu.Lock()
		for _, t := range []*time.Timer{c.rd, c.wd} {
			if t != nil {
				t.Stop()
			}
		}
		c.mu.Unlock()
	})
	return nil
}

func (c *clientConn) LocalAddr() net.Addr  { return c.local }
func (c *clientConn) RemoteAddr() net.Addr { return c.remote }

func (c *clientConn) SetDeadline(t time.Time) error {
	c.set(&c.rd, t)
	c.set(&c.wd, t)
	return nil
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	c.set(&c.rd, t)
	return nil
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	c.set(&c.wd, t)
	return nil
}

// set arms the timer that resets the stream at t.
func (c *clientConn) set(timer **time.Timer, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if *timer != nil {
		(*timer).Stop()
		*timer = nil
	}
	if t.IsZero() || c.expired {
		return
	}
	if d := time.Until(t); d > 0 {
		// A callback that fires while set replaces its timer finds
		// another timer in place and does nothing.
		var tm *time.Timer
		tm = time.AfterFunc(d, func() {
			c.mu.Lock()
			if *timer != tm {
				c.mu.Unlock()
				return
			}
			c.expired = true
			c.mu.Unlock()
			c.reset()
		})
		*timer = tm
		return
	}
	c.expired = true
	c.reset()
}

// reset resets the stream: a request body that fails makes the transport
// reset it, also while it waits for the body, which ctx does not end.
func (c *clientConn) reset() {
	_ = c.pw.CloseWithError(os.ErrDeadlineExceeded)
	c.cancel()
}
