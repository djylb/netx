package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/djylb/netx/socks5"
	"github.com/djylb/netx/tlsconn"
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

func mustDialer(t *testing.T, rawURL string) ContextDialer {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	d, err := FromURL(u, nil)
	if err != nil {
		t.Fatalf("FromURL(%s) error = %v", rawURL, err)
	}
	return d
}

func echoAfter(c net.Conn, greeting string) {
	_, _ = io.WriteString(c, greeting)
	_, _ = io.Copy(c, c)
}

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

func TestHTTPConnectRejected(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	})
	_, err := mustDialer(t, "http://"+addr).DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("DialContext() error = %v, want 407", err)
	}
}

func TestHTTPConnectRejectsBadTargets(t *testing.T) {
	d := mustDialer(t, "http://127.0.0.1:1")
	for _, target := range []string{"no-port", "evil\r\nX-Injected: 1:80", "a b:80"} {
		if _, err := d.DialContext(context.Background(), "tcp", target); err == nil {
			t.Errorf("DialContext(%q) succeeded", target)
		}
	}
}

func TestHTTPSProxyUsesTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS()
	defer srv.Close()
	_, err := mustDialer(t, "https://"+srv.Listener.Addr().String()).DialContext(context.Background(), "tcp", "example.com:443")
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
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
	for _, scheme := range []string{"http", "socks5"} {
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

func TestFromURLErrors(t *testing.T) {
	if _, err := FromURL(nil, nil); err == nil {
		t.Error("FromURL(nil) succeeded")
	}
	for _, raw := range []string{"ftp://proxy:21", "http://", "socks5://:1080", "socks6://proxy", "https+tls://proxy", "ftp+tls://proxy"} {
		u, _ := url.Parse(raw)
		if _, err := FromURL(u, nil); err == nil {
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

func TestFromEnvironment(t *testing.T) {
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	forward := &recordingDialer{}
	d, err := FromEnvironment(forward)
	if err != nil || d != forward {
		t.Fatalf("FromEnvironment(unset) = %v, %v; want forward", d, err)
	}

	t.Setenv("all_proxy", "socks5://proxy.internal:1081")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "localhost, .corp.example, 10.0.0.0/8")
	d, err = FromEnvironment(forward)
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
	if d, err := FromEnvironment(nil); err != nil {
		t.Fatal(err)
	} else if _, ok := d.(*socks5.Dialer); !ok {
		t.Fatalf("FromEnvironment without NO_PROXY = %T, want *socks5.Dialer", d)
	}

	t.Setenv("ALL_PROXY", "gopher://proxy")
	if _, err := FromEnvironment(nil); err == nil {
		t.Fatal("FromEnvironment(bad scheme) succeeded")
	}
	t.Setenv("ALL_PROXY", "http://[::1")
	if _, err := FromEnvironment(nil); err == nil {
		t.Fatal("FromEnvironment(bad URL) succeeded")
	}
}

func TestNoProxy(t *testing.T) {
	np := ParseNoProxy(" Example.COM ,.sub.test,*.wild.test, 192.0.2.1, 198.51.100.0/24, [2001:db8::1]:8443, internal:8080, 2001:db8:1::/48 ,,")
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
	dialer, err := FromURL(u, forward)
	if err != nil {
		t.Fatal(err)
	}
	d = dialer.(*socks5.Dialer)
	td, ok := d.Forward.(*tlsconn.Dialer)
	if !ok || d.SOCKS4 || d.ProxyAddr != "proxy:1080" || td.Config.ServerName != "proxy" || td.Forward != forward {
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
		var certErr *tls.CertificateVerificationError
		if !errors.As(err, &certErr) {
			t.Fatalf("%s with system roots error = %v, want a certificate error", scheme, err)
		}

		d.(*socks5.Dialer).Forward.(*tlsconn.Dialer).Config.RootCAs = roots
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
