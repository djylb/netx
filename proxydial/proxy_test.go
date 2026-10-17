package proxydial

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/socks5"
)

// serveOnce accepts one connection on a loopback listener and runs handle.
func serveOnce(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		handle(c)
	}()
	return ln.Addr().String()
}

func mustDialer(t *testing.T, rawURL string) netx.ContextDialer {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	d, err := FromURL(u, nil, nil)
	if err != nil {
		t.Fatalf("FromURL(%s) error = %v", rawURL, err)
	}
	return d
}

func echoAfter(c net.Conn, greeting string) {
	_, _ = io.WriteString(c, greeting)
	_, _ = io.Copy(c, c)
}

//goland:noinspection HttpUrlsUsage
func TestHTTPConnect(t *testing.T) {
	gotReq := make(chan *http.Request, 1)
	addr := serveOnce(t, func(c net.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		gotReq <- req
		// Bytes sent right after the reply must reach the caller.
		echoAfter(c, "HTTP/1.1 200 Connection established\r\n\r\nhello")
	})

	d := mustDialer(t, "http://alice:s3cret@"+addr)
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	req := <-gotReq
	if req.Method != http.MethodConnect || req.Host != "example.com:443" || req.RequestURI != "example.com:443" {
		t.Fatalf("request = %s %s host=%s", req.Method, req.RequestURI, req.Host)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if got := req.Header.Get("Proxy-Authorization"); got != wantAuth {
		t.Fatalf("Proxy-Authorization = %q, want %q", got, wantAuth)
	}

	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("early bytes = %q, %v", buf, err)
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

//goland:noinspection HttpUrlsUsage
func TestHTTPConnectRejected(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	})
	_, err := mustDialer(t, "http://"+addr).DialContext(context.Background(), "tcp", "example.com:80")
	if ce, ok := errors.AsType[*ConnectError](err); !ok || ce.StatusCode != 407 {
		t.Fatalf("DialContext() error = %v, want a 407 ConnectError", err)
	}
}

//goland:noinspection HttpUrlsUsage
func TestHTTPConnectRejectsBadTargets(t *testing.T) {
	// The proxy grants every CONNECT request it gets, so only the target
	// check can fail these dials.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	requests := make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				line, _ := bufio.NewReader(c).ReadString('\n')
				requests <- line
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
			}()
		}
	}()
	d := mustDialer(t, "http://"+ln.Addr().String())
	if c, err := d.DialContext(context.Background(), "tcp", "good.example:80"); err != nil {
		t.Fatalf("DialContext(good target) error = %v", err)
	} else {
		_ = c.Close()
		<-requests
	}
	for _, target := range []string{"no-port", "evil\r\nX-Injected: 1:80", "a b:80", "evil.example HTTP/1.0 x.example:443", "tab\t:80"} {
		if c, err := d.DialContext(context.Background(), "tcp", target); err == nil {
			_ = c.Close()
			t.Errorf("DialContext(%q) succeeded", target)
		}
	}
	select {
	case line := <-requests:
		t.Errorf("bad target reached the proxy: %q", line)
	case <-time.After(100 * time.Millisecond):
	}
}

// noDeadlineConn reports an error for every deadline, as connections without
// deadline support such as SSH channels do.
type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error      { return errors.New("deadline not supported") }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errors.New("deadline not supported") }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errors.New("deadline not supported") }

type noDeadlineDialer struct{}

func (noDeadlineDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return noDeadlineConn{c}, nil
}

func TestHTTPConnectForwardWithoutDeadlines(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			return
		}
		echoAfter(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&HTTPDialer{ProxyAddr: addr, Forward: noDeadlineDialer{}}).DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestHTTPSProxyUsesTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS()
	defer srv.Close()
	_, err := mustDialer(t, "https://"+srv.Listener.Addr().String()).DialContext(context.Background(), "tcp", "example.com:443")
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
		t.Fatalf("DialContext() error = %v, want certificate verification error", err)
	}
}

// socksServer answers one SOCKS5 handshake. It accepts credentials alice/pw
// when user/password authentication is offered.
func socksServer(t *testing.T, reply socks5.Reply, requests chan<- socks5.Addr) string {
	return serveOnce(t, func(c net.Conn) {
		methods, err := socks5.ReadMethods(c)
		if err != nil {
			return
		}
		method := socks5.MethodNoAuth
		for _, m := range methods {
			if m == socks5.MethodUserPass {
				method = m
			}
		}
		_ = socks5.WriteMethod(c, method)
		if method == socks5.MethodUserPass {
			user, pass, err := socks5.ReadUserPass(c)
			if err != nil {
				return
			}
			ok := user == "alice" && pass == "pw"
			_ = socks5.WriteUserPassStatus(c, ok)
			if !ok {
				return
			}
		}
		cmd, dst, err := socks5.ReadRequest(c)
		if err != nil || cmd != socks5.CmdConnect {
			return
		}
		requests <- dst
		_ = socks5.WriteReply(c, reply, socks5.Addr{})
		if reply == socks5.ReplySucceeded {
			echoAfter(c, "")
		}
	})
}

func TestSOCKS5(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		requests := make(chan socks5.Addr, 1)
		addr := socksServer(t, socks5.ReplySucceeded, requests)
		conn, err := mustDialer(t, scheme+"://alice:pw@"+addr).DialContext(context.Background(), "tcp", "example.com:443")
		if err != nil {
			t.Fatalf("%s DialContext() error = %v", scheme, err)
		}
		if got := <-requests; got != (socks5.Addr{Name: "example.com", Port: 443}) {
			t.Fatalf("%s request = %v, want example.com:443 by name", scheme, got)
		}
		_, _ = io.WriteString(conn, "ping")
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%s echo = %q, %v", scheme, buf, err)
		}
		_ = conn.Close()
	}
}

func TestSOCKS5Failures(t *testing.T) {
	requests := make(chan socks5.Addr, 1)
	addr := socksServer(t, socks5.ReplySucceeded, requests)
	_, err := mustDialer(t, "socks5://alice:wrong@"+addr).DialContext(context.Background(), "tcp", "example.com:1")
	if !errors.Is(err, socks5.ErrAuthFailed) {
		t.Fatalf("bad password error = %v, want %v", err, socks5.ErrAuthFailed)
	}

	addr = socksServer(t, socks5.ReplyConnectionRefused, requests)
	_, err = mustDialer(t, "socks5://"+addr).DialContext(context.Background(), "tcp", "192.0.2.1:22")
	var replyErr *socks5.ReplyError
	if !errors.As(err, &replyErr) || replyErr.Reply != socks5.ReplyConnectionRefused {
		t.Fatalf("refused error = %v", err)
	}
	if got := <-requests; got.String() != "192.0.2.1:22" || !got.IP.IsValid() {
		t.Fatalf("request = %v, want IP 192.0.2.1:22", got)
	}

	// The server selects user/password although the client offered none.
	addr = serveOnce(t, func(c net.Conn) {
		if _, err := socks5.ReadMethods(c); err == nil {
			_ = socks5.WriteMethod(c, socks5.MethodUserPass)
		}
	})
	if _, err := mustDialer(t, "socks5://"+addr).DialContext(context.Background(), "tcp", "example.com:1"); err == nil {
		t.Fatal("unoffered method accepted")
	}
}

func TestDialContextEndsStalledHandshake(t *testing.T) {
	// The TLS schemes stall in the TLS handshake.
	for _, scheme := range []string{"http", "socks5", "https", "socks5+tls"} {
		addr := serveOnce(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
		d := mustDialer(t, scheme+"://"+addr)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err := d.DialContext(ctx, "tcp", "example.com:80")
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s timeout error = %v, want %v", scheme, err, context.DeadlineExceeded)
		}

		addr = serveOnce(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
		d = mustDialer(t, scheme+"://"+addr)
		ctx, cancel = context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		if _, err := d.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s cancel error = %v, want %v", scheme, err, context.Canceled)
		}
	}
}

//goland:noinspection HttpUrlsUsage
func TestFromURLErrors(t *testing.T) {
	if _, err := FromURL(nil, nil, nil); err == nil {
		t.Error("FromURL(nil) succeeded")
	}
	for _, raw := range []string{"ftp://proxy:21", "http://", "socks5://:1080", "socks6://proxy", "https+tls://proxy", "ftp+tls://proxy"} {
		u, _ := url.Parse(raw)
		if _, err := FromURL(u, nil, nil); err == nil {
			t.Errorf("FromURL(%s) succeeded", raw)
		}
	}
	d := mustDialer(t, "SOCKS5://proxy")
	if sd, ok := d.(*socks5.Dialer); !ok || sd.ProxyAddr != "proxy:1080" || sd.Username != "" {
		t.Errorf("SOCKS5 default address = %#v", d)
	}
	if sd := mustDialer(t, "socks5h://u:p@proxy:9").(*socks5.Dialer); sd.Username != "u" || sd.Password != "p" || sd.ProxyAddr != "proxy:9" {
		t.Errorf("socks5h credentials = %#v", sd)
	}
	if hd := mustDialer(t, "http://proxy").(*HTTPDialer); hd.ProxyAddr != "proxy:80" || hd.TLSConfig != nil || hd.Header != nil {
		t.Errorf("http defaults = %#v", hd)
	}
	if hd := mustDialer(t, "https://[2001:db8::1]").(*HTTPDialer); hd.ProxyAddr != "[2001:db8::1]:443" || hd.TLSConfig.ServerName != "2001:db8::1" {
		t.Errorf("https defaults = %#v", hd)
	}
	if _, err := d.DialContext(context.Background(), "udp", "example.com:53"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("udp dial error = %v", err)
	}
	if _, err := mustDialer(t, "http://proxy").DialContext(context.Background(), "unix", "/x"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("unix dial error = %v", err)
	}
}

type recordingDialer struct {
	dialed []string
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.dialed = append(d.dialed, address)
	return nil, errors.New("recorded")
}

//goland:noinspection HttpUrlsUsage
func TestFromEnvironment(t *testing.T) {
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	forward := &recordingDialer{}
	d, err := FromEnvironment(forward, nil)
	if err != nil || d != forward {
		t.Fatalf("FromEnvironment(unset) = %v, %v; want forward", d, err)
	}

	t.Setenv("all_proxy", "socks5://proxy.internal:1081")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "localhost, .corp.example, 10.0.0.0/8")
	d, err = FromEnvironment(forward, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"localhost:80", "db.corp.example:5432", "10.1.2.3:22", "example.com:443"} {
		_, _ = d.DialContext(context.Background(), "tcp", target)
	}
	want := []string{"localhost:80", "db.corp.example:5432", "10.1.2.3:22", "proxy.internal:1081"}
	if strings.Join(forward.dialed, " ") != strings.Join(want, " ") {
		t.Fatalf("dialed %v, want %v", forward.dialed, want)
	}

	t.Setenv("no_proxy", "")
	if d, err := FromEnvironment(nil, nil); err != nil {
		t.Fatal(err)
	} else if _, ok := d.(*socks5.Dialer); !ok {
		t.Fatalf("FromEnvironment without NO_PROXY = %T, want *socks5.Dialer", d)
	}

	// A value without a scheme is an http proxy, as for curl.
	for raw, want := range map[string]string{"127.0.0.1:1080": "127.0.0.1:1080", "proxy.local:3128": "proxy.local:3128", "proxy.local": "proxy.local:80"} {
		t.Setenv("ALL_PROXY", raw)
		d, err := FromEnvironment(nil, nil)
		if err != nil {
			t.Fatalf("FromEnvironment(ALL_PROXY=%s) error = %v", raw, err)
		}
		if hd, ok := d.(*HTTPDialer); !ok || hd.ProxyAddr != want {
			t.Fatalf("FromEnvironment(ALL_PROXY=%s) = %#v, want an HTTPDialer for %s", raw, d, want)
		}
	}

	t.Setenv("ALL_PROXY", "gopher://proxy")
	if _, err := FromEnvironment(nil, nil); err == nil {
		t.Fatal("FromEnvironment(bad scheme) succeeded")
	}
	t.Setenv("ALL_PROXY", "http://[::1")
	if _, err := FromEnvironment(nil, nil); err == nil {
		t.Fatal("FromEnvironment(bad URL) succeeded")
	}
}

func TestNoProxy(t *testing.T) {
	np := ParseNoProxy(" Example.COM ,.sub.test,*.wild.test, 192.0.2.1, 198.51.100.0/24, [2001:db8::1]:8443, internal:8080, 2001:db8:1::/48 ,[::1],,")
	tests := map[string]bool{
		"example.com:80":       true,
		"EXAMPLE.com.:80":      true,
		"www.example.com:80":   true,
		"notexample.com:80":    false,
		"sub.test:80":          false,
		"a.sub.test:80":        true,
		"wild.test:80":         false,
		"x.wild.test:80":       true,
		"192.0.2.1:22":         true,
		"192.0.2.2:22":         false,
		"198.51.100.77:22":     true,
		"[::ffff:192.0.2.1]:1": true,
		"[2001:db8::1]:8443":   true,
		"[2001:db8::1]:443":    false,
		"[2001:db8:1::5]:1":    true,
		"internal:8080":        true,
		"internal:80":          false,
		"[::1]:80":             true,
		"[::1]":                true,
		"::1":                  true,
		"other.internal:8080":  true,
		"example.org":          false,
	}
	for address, want := range tests {
		if got := np.Match(address); got != want {
			t.Errorf("match(%q) = %v, want %v", address, got, want)
		}
	}
	if !ParseNoProxy("foo, *").Match("anything:1") {
		t.Error(`"*" does not match everything`)
	}
	if !ParseNoProxy(" , ").empty() || ParseNoProxy("x").empty() {
		t.Error("empty() is wrong")
	}
}

//goland:noinspection HttpUrlsUsage
func TestHTTPConnectReplyParsing(t *testing.T) {
	tests := []struct {
		name    string
		reply   string
		wantErr string // empty for success
	}{
		// A 2xx reply has no body even with Content-Length, so "data" is tunnel data.
		{"content length ignored", "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\ndata", ""},
		{"other 2xx", "HTTP/1.1 204 No Content\r\n\r\ndata", ""},
		{"malformed status", "SSH-2.0-OpenSSH\r\n\r\n", "malformed status line"},
		{"short code", "HTTP/1.1 20 OK\r\n\r\n", "malformed status line"},
		{"redirect", "HTTP/1.1 302 Found\r\nLocation: /\r\n\r\n", "302 Found"},
		{"oversized headers", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", maxConnectReplyBytes) + "\r\n\r\n", "read CONNECT response"},
		{"truncated", "HTTP/1.1 200 OK\r\nX: y", "read CONNECT response"},
	}
	for _, tt := range tests {
		addr := serveOnce(t, func(c net.Conn) {
			if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
				return
			}
			_, _ = io.WriteString(c, tt.reply)
		})
		conn, err := mustDialer(t, "http://"+addr).DialContext(context.Background(), "tcp", "example.com:80")
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%s: error = %v, want %q", tt.name, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: error = %v", tt.name, err)
			continue
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "data" {
			t.Errorf("%s: tunnel read = %q, %v", tt.name, buf, err)
		}
		_ = conn.Close()
	}
}

func TestHTTPDialerConfig(t *testing.T) {
	gotReq := make(chan *http.Request, 1)
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq <- r
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})
	srv.StartTLS()
	defer srv.Close()

	// A custom TLS config reaches the HTTPS proxy, and Header adds fields.
	d := &HTTPDialer{
		ProxyAddr: srv.Listener.Addr().String(),
		TLSConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig,
		Header:    textproto.MIMEHeader{"User-Agent": {"netx-test"}, "X-Trace": {"1", "2"}},
	}
	conn, err := d.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	_ = conn.Close()
	req := <-gotReq
	if req.Method != http.MethodConnect || req.UserAgent() != "netx-test" || len(req.Header["X-Trace"]) != 2 {
		t.Fatalf("request = %s %v", req.Method, req.Header)
	}

	for _, h := range []textproto.MIMEHeader{
		{"X-Bad": {"a\r\nX-Injected: 1"}},
		{"Bad Key": {"v"}},
		{"": {"v"}},
	} {
		d := &HTTPDialer{ProxyAddr: "127.0.0.1:1", Header: h}
		if _, err := d.DialContext(context.Background(), "tcp", "example.com:1"); err == nil || !strings.Contains(err.Error(), "invalid header") {
			t.Errorf("header %q accepted: %v", h, err)
		}
	}
}

func TestFromURLSOCKSVariants(t *testing.T) {
	d := mustDialer(t, "socks4://u:ignored@proxy").(*socks5.Dialer)
	if !d.SOCKS4 || d.Resolver != net.DefaultResolver || d.Username != "u" || d.ProxyAddr != "proxy:1080" || d.Forward != nil {
		t.Errorf("socks4 = %#v", d)
	}
	d = mustDialer(t, "socks4a://proxy:9").(*socks5.Dialer)
	if !d.SOCKS4 || d.Resolver != nil || d.ProxyAddr != "proxy:9" {
		t.Errorf("socks4a = %#v", d)
	}

	forward := &recordingDialer{}
	u, _ := url.Parse("SOCKS5H+TLS://proxy")
	dialer, err := FromURL(u, forward, nil)
	if err != nil {
		t.Fatal(err)
	}
	d = dialer.(*socks5.Dialer)
	td, ok := d.Forward.(*tlsDialer)
	if !ok || d.SOCKS4 || d.ProxyAddr != "proxy:1080" || td.config.ServerName != "proxy" || td.forward != forward {
		t.Errorf("socks5h+tls = %#v, forward %#v", d, d.Forward)
	}
	if d := mustDialer(t, "socks4a+tls://proxy").(*socks5.Dialer); !d.SOCKS4 || d.Resolver != nil {
		t.Errorf("socks4a+tls = %#v", d)
	}
}

// TestSOCKSOverTLS dials through SOCKS5 and SOCKS4a servers behind TLS.
func TestSOCKSOverTLS(t *testing.T) {
	// httptest supplies a certificate for 127.0.0.1 and a client that trusts it.
	cert := httptest.NewUnstartedServer(nil)
	cert.StartTLS()
	roots := cert.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	serverCfg := &tls.Config{Certificates: cert.TLS.Certificates}
	cert.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5.Server{SOCKS4: true}
	go func() { _ = s.Serve(tls.NewListener(ln, serverCfg)) }()
	t.Cleanup(func() { _ = s.Close() })
	target := serveEcho(t)

	for _, scheme := range []string{"socks5+tls", "socks5h+tls", "socks4a+tls"} {
		d := mustDialer(t, scheme+"://"+ln.Addr().String())
		_, err := d.DialContext(context.Background(), "tcp", target)
		if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
			t.Fatalf("%s with system roots error = %v, want a certificate error", scheme, err)
		}

		d.(*socks5.Dialer).Forward.(*tlsDialer).config.RootCAs = roots
		conn, err := d.DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatalf("%s DialContext() error = %v", scheme, err)
		}
		if _, ok := conn.(*tls.Conn); !ok {
			t.Fatalf("%s connection = %T, want *tls.Conn", scheme, conn)
		}
		_, _ = io.WriteString(conn, "ping")
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%s echo = %q, %v", scheme, buf, err)
		}
		_ = conn.Close()
	}
}

// serveEcho starts a TCP echo server.
func serveEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				echoAfter(c, "")
			}()
		}
	}()
	return ln.Addr().String()
}

// The context bounds a dial through a Forward whose connections cannot set
// deadlines.
func TestHTTPDialerContextWithoutDeadlines(t *testing.T) {
	release := make(chan struct{})
	addr := serveOnce(t, func(c net.Conn) {
		go func() {
			<-release
			_ = c.Close()
		}()
		_, _ = io.Copy(io.Discard, c) // reads the request and never answers
	})
	defer close(release)
	d := &HTTPDialer{ProxyAddr: addr, Forward: noDeadlineDialer{}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := d.DialContext(ctx, "tcp", "example.com:443")
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("DialContext() error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DialContext() outlived its context")
	}
}

// Header values may hold tabs; names may not.
func TestHTTPDialerHeaderTabs(t *testing.T) {
	d := &HTTPDialer{Header: map[string][]string{"X-Tab": {"a\tb"}}}
	if req, err := d.request("example.com:443"); err != nil || !strings.Contains(string(req), "X-Tab: a\tb\r\n") {
		t.Fatalf("request() = %q, %v; want the tab kept", req, err)
	}
	d = &HTTPDialer{Header: map[string][]string{"X\tTab": {"v"}}}
	if _, err := d.request("example.com:443"); err == nil {
		t.Fatal("request() accepted a tab in a header name")
	}
}

// The NO_PROXY dialer of FromEnvironment has Dial, as FromURL's dialers do.
func TestFromEnvironmentBypassDialerDial(t *testing.T) {
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	t.Setenv("NO_PROXY", "localhost")
	d, err := FromEnvironment(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.(interface {
		Dial(network, address string) (net.Conn, error)
	}); !ok {
		t.Fatalf("FromEnvironment() = %T without Dial", d)
	}
}

// borrowedParentConn stands for a connection that several netx.WrapConns
// borrow, such as the TCP connection beneath SSH channels.
type borrowedParentConn struct {
	noDeadlineConn
	closed atomic.Bool
}

func (c *borrowedParentConn) Close() error {
	c.closed.Store(true)
	return nil
}

type borrowingDialer struct{ parent net.Conn }

func (d borrowingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return netx.WrapConn(c, d.parent), nil
}

// A CONNECT that times out closes its connection, never the connection that
// a netx.WrapConn borrows for addresses and deadlines.
func TestHTTPConnectTimeoutKeepsBorrowedParent(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	parent := &borrowedParentConn{noDeadlineConn: noDeadlineConn{a}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := (&HTTPDialer{ProxyAddr: addr, Forward: borrowingDialer{parent}}).DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("DialContext() succeeded without a reply")
	}
	if parent.closed.Load() {
		t.Fatal("the CONNECT timeout closed the borrowed parent")
	}
}

// Handshake runs CONNECT on a connection the caller made, returns that
// connection when the proxy sent nothing after its reply and a PrefixConn
// replaying those bytes otherwise, and leaves the connection open on failure.
func TestHTTPDialerHandshake(t *testing.T) {
	for _, tt := range []struct {
		name, reply string
		wantPrefix  bool
		wantErr     bool
	}{
		{"plain", "HTTP/1.1 200 OK\r\n\r\n", false, false},
		{"early bytes", "HTTP/1.1 200 OK\r\n\r\nhello", true, false},
		{"refused", "HTTP/1.1 403 Forbidden\r\n\r\n", false, true},
	} {
		addr := serveOnce(t, func(c net.Conn) {
			req, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil || req.Method != http.MethodConnect || req.RequestURI != "example.com:443" {
				return
			}
			echoAfter(c, tt.reply)
		})
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := (&HTTPDialer{}).Handshake(context.Background(), c, "example.com:443")
		if tt.wantErr {
			if err == nil {
				t.Fatalf("%s: Handshake() succeeded", tt.name)
			}
			if err := c.Close(); err != nil {
				t.Fatalf("%s: Handshake() closed the connection: %v", tt.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: Handshake() error = %v", tt.name, err)
		}
		if _, ok := conn.(*netx.PrefixConn); ok != tt.wantPrefix {
			t.Fatalf("%s: Handshake() = %T, want PrefixConn %v", tt.name, conn, tt.wantPrefix)
		}
		if !tt.wantPrefix && conn != c {
			t.Fatalf("%s: Handshake() = %v, want the given connection", tt.name, conn)
		}
		want := "ping"
		if tt.wantPrefix {
			want = "hello" + want
		}
		if _, err := io.WriteString(conn, "ping"); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != want {
			t.Fatalf("%s: tunnel read = %q, %v; want %q", tt.name, buf, err, want)
		}
		_ = conn.Close()
	}
}

// A canceled context ends Handshake with its error and leaves the connection
// open, with the deadline it poisoned.
func TestHTTPDialerHandshakeCanceled(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := (&HTTPDialer{}).Handshake(ctx, c, "example.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Handshake() error = %v, want context.Canceled", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Handshake() closed the connection: %v", err)
	}
}

// Replies other than 2xx are *ConnectErrors carrying the status and header,
// so that callers can answer a 407 challenge or tell 403 from 502.
func TestHTTPConnectError(t *testing.T) {
	for _, tt := range []struct {
		reply  string
		code   int
		status string
		header string
	}{
		{"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\n\r\n", 407, "407 Proxy Authentication Required", `Basic realm="p"`},
		{"HTTP/1.1 403 Forbidden\r\n\r\n", 403, "403 Forbidden", ""},
		{"HTTP/1.0 502 Bad Gateway\r\n\r\n", 502, "502 Bad Gateway", ""},
		{"HTTP/1.1 101 Switching Protocols\r\n\r\n", 101, "101 Switching Protocols", ""},
	} {
		addr := serveOnce(t, func(c net.Conn) {
			if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
				return
			}
			_, _ = io.WriteString(c, tt.reply)
		})
		_, err := (&HTTPDialer{ProxyAddr: addr}).DialContext(context.Background(), "tcp", "example.com:443")
		ce, ok := errors.AsType[*ConnectError](err)
		if !ok {
			t.Fatalf("DialContext() error = %v, want a *ConnectError", err)
		}
		if ce.StatusCode != tt.code || ce.Status != tt.status || ce.Header.Get("Proxy-Authenticate") != tt.header {
			t.Errorf("ConnectError = %+v, want %d %q with Proxy-Authenticate %q", ce, tt.code, tt.status, tt.header)
		}
	}
}

// FromURL applies the caller's TLS config to https and +tls proxies, filling
// in a missing ServerName on a clone and leaving the caller's config alone.
//
//goland:noinspection HttpUrlsUsage
func TestFromURLTLSConfig(t *testing.T) {
	roots := x509.NewCertPool()
	named := &tls.Config{ServerName: "front.example"}
	unnamed := &tls.Config{RootCAs: roots}
	configOf := func(raw string, cfg *tls.Config) *tls.Config {
		u, _ := url.Parse(raw)
		d, err := FromURL(u, nil, cfg)
		if err != nil {
			t.Fatal(err)
		}
		switch d := d.(type) {
		case *HTTPDialer:
			return d.TLSConfig
		case *socks5.Dialer:
			if td, ok := d.Forward.(*tlsDialer); ok {
				return td.config
			}
		}
		return nil
	}
	for _, raw := range []string{"https://proxy:8443", "socks5+tls://proxy", "socks4a+tls://proxy"} {
		if got := configOf(raw, nil); got == nil || got.ServerName != "proxy" {
			t.Errorf("%s with nil config = %#v", raw, got)
		}
		if got := configOf(raw, named); got != named {
			t.Errorf("%s did not use the named config as is", raw)
		}
		if got := configOf(raw, unnamed); got == unnamed || got.ServerName != "proxy" || got.RootCAs != roots {
			t.Errorf("%s with unnamed config = %#v", raw, got)
		}
	}
	if unnamed.ServerName != "" {
		t.Fatal("FromURL modified the caller's config")
	}
	for _, raw := range []string{"http://proxy", "socks5://proxy"} {
		if got := configOf(raw, named); got != nil {
			t.Errorf("%s uses TLS", raw)
		}
	}
}

func TestParseURL(t *testing.T) {
	for raw, want := range map[string]string{
		"127.0.0.1:1080":            "http://127.0.0.1:1080",
		"proxy.local:3128":          "http://proxy.local:3128",
		"proxy.local":               "http://proxy.local",
		"u:p@proxy.local:3128":      "http://u:p@proxy.local:3128",
		"[::1]:8080":                "http://[::1]:8080",
		"socks5h://u:p@proxy:1080":  "socks5h://u:p@proxy:1080",
		"HTTPS://proxy.example:443": "https://proxy.example:443",
	} {
		u, err := ParseURL(raw)
		if err != nil || u.String() != want {
			t.Errorf("ParseURL(%q) = %v, %v; want %s", raw, u, err, want)
		}
	}
	for raw, secret := range map[string]string{
		"socks5://alice:topsecret@proxy:bad": "topsecret",
		"socks5://u:pa/ss@h:1":               "pa",
		"socks5://u:p%zzw@h:1":               "%zz",
		"u:p%zzw@h:1":                        "%zz",
		"http://[::1":                        "",
	} {
		_, err := ParseURL(raw)
		if err == nil {
			t.Fatalf("ParseURL(%q) succeeded", raw)
		}
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q contains part of the password", err)
		}
	}
}

// Proxy URLs whose user information did not parse as such are rejected
// without the password in the error, whether they come from FromURL,
// ParseURL or ALL_PROXY.
//
//goland:noinspection HttpUrlsUsage
func TestProxyURLErrorsHidePassword(t *testing.T) {
	for _, raw := range []string{
		"http:///user:s3cret@host:1080",
		"socks5:///user:s3cret@host",
		"//user:s3cret@host:1080/x",
		"http://user:12#s3cret@host",
		"http://host/user:s3cret@x",
		"http://host?user:s3cret@x",
		"https://host:1/?s3cret",
	} {
		var errs []error
		if u, err := url.Parse(raw); err == nil {
			_, err := FromURL(u, nil, nil)
			errs = append(errs, err)
		}
		_, err := ParseURL(raw)
		errs = append(errs, err)
		t.Setenv("ALL_PROXY", raw)
		_, err = FromEnvironment(nil, nil)
		errs = append(errs, err)
		for _, err := range errs {
			if err == nil {
				t.Fatalf("%q accepted", raw)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("%q: error %q holds the password", raw, err)
			}
		}
	}
	for _, raw := range []string{"http://u:p@host/", "//u:p@host:1080"} {
		if u, err := ParseURL(raw); err != nil || u.Scheme != "http" || u.Host == "" {
			t.Errorf("ParseURL(%q) = %v, %v", raw, u, err)
		}
	}
}

// After a timeout Handshake closes the connection beneath a *tls.Conn, so
// that the caller's Close sends no close_notify.
func TestHTTPDialerHandshakeTimeoutClosesBeneathTLS(t *testing.T) {
	cert := httptest.NewUnstartedServer(nil)
	cert.StartTLS()
	serverCfg := &tls.Config{Certificates: cert.TLS.Certificates}
	cert.Close()
	addr := serveOnce(t, func(c net.Conn) {
		tc := tls.Server(c, serverCfg)
		_, _ = io.Copy(io.Discard, tc) // completes the handshake, never replies
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := (&HTTPDialer{}).Handshake(ctx, tc, "example.com:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Handshake() error = %v, want context.DeadlineExceeded", err)
	}
	// The expired deadline that ended the handshake may be reported before
	// the close, as on the simulated network of js/wasm.
	_ = raw.SetDeadline(time.Time{})
	if _, err := raw.Write([]byte{0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write beneath TLS error = %v, want net.ErrClosed", err)
	}
}

// Username and Password become Basic Proxy-Authorization unless Header holds
// that field already, and errors never name the password.
func TestHTTPDialerCredentials(t *testing.T) {
	basic := func(user, password string) string {
		return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)) + "\r\n"
	}
	for _, tt := range []struct {
		name string
		d    HTTPDialer
		want string // the only Proxy-Authorization line, or "" for none
	}{
		{"none", HTTPDialer{}, ""},
		{"basic", HTTPDialer{Username: "alice", Password: "s3cret"}, basic("alice", "s3cret")},
		{"password only", HTTPDialer{Password: "s3cret"}, basic("", "s3cret")},
		{"header wins", HTTPDialer{Username: "alice", Password: "s3cret", Header: textproto.MIMEHeader{"proxy-authorization": {"Bearer t"}}}, "proxy-authorization: Bearer t\r\n"},
		{"empty header field", HTTPDialer{Username: "alice", Password: "s3cret", Header: textproto.MIMEHeader{"Proxy-Authorization": {}}}, basic("alice", "s3cret")},
	} {
		req, err := tt.d.request("example.com:443")
		if err != nil {
			t.Fatalf("%s: request() error = %v", tt.name, err)
		}
		n := strings.Count(strings.ToLower(string(req)), "\r\nproxy-authorization:")
		if tt.want == "" && n != 0 || tt.want != "" && (n != 1 || !strings.Contains(string(req), "\r\n"+tt.want)) {
			t.Errorf("%s: request %q, want Proxy-Authorization %q", tt.name, req, tt.want)
		}
	}
	_, err := (&HTTPDialer{Username: "a:b", Password: "s3cret"}).request("example.com:443")
	if err == nil || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "a:b") {
		t.Fatalf("request() with a colon in Username error = %v", err)
	}
	//goland:noinspection HttpUrlsUsage
	if d := mustDialer(t, "http://alice:s3cret@proxy").(*HTTPDialer); d.Username != "alice" || d.Password != "s3cret" || d.Header != nil {
		t.Fatalf("FromURL() = %#v, want the user information as Username and Password", d)
	}
}

// FromEnvironment with NO_PROXY returns a *Bypass whose Proxy is FromURL's
// dialer, which callers can adjust.
func TestFromEnvironmentBypass(t *testing.T) {
	t.Setenv("all_proxy", "")
	t.Setenv("ALL_PROXY", "http://proxy.internal:3128")
	t.Setenv("no_proxy", "")
	t.Setenv("NO_PROXY", "localhost")
	forward := &recordingDialer{}
	d, err := FromEnvironment(forward, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := d.(*Bypass)
	if !ok || b.Direct != forward || !b.NoProxy.Match("localhost:80") {
		t.Fatalf("FromEnvironment() = %#v, want a *Bypass", d)
	}
	if hd, ok := b.Proxy.(*HTTPDialer); !ok || hd.ProxyAddr != "proxy.internal:3128" || hd.Forward != forward {
		t.Fatalf("Bypass.Proxy = %#v, want an *HTTPDialer", b.Proxy)
	}
}

func TestBypassDial(t *testing.T) {
	target := serveEcho(t)
	proxied := &recordingDialer{}
	// Direct defaults to a zero net.Dialer.
	b := &Bypass{Proxy: proxied, NoProxy: ParseNoProxy("127.0.0.1")}
	conn, err := b.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("direct dial error = %v", err)
	}
	_ = conn.Close()
	if _, err := b.Dial("tcp", "example.com:443"); err == nil || strings.Join(proxied.dialed, " ") != "example.com:443" {
		t.Fatalf("proxied dial = %v, dialed %v", err, proxied.dialed)
	}
	if _, err := (&Bypass{}).DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, errNoProxyDialer) {
		t.Fatalf("dial without Proxy error = %v", err)
	}
}
