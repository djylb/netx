package httpproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/httpproxy"
	"github.com/djylb/netx/internal/nettest"
	"github.com/djylb/netx/proxydial"
)

// serve runs s on a loopback listener until the test ends and returns its
// address.
func serve(t testing.TB, s *httpproxy.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		_ = s.Close()
		if err := <-done; !errors.Is(err, httpproxy.ErrServerClosed) {
			t.Errorf("Serve() = %v, want ErrServerClosed", err)
		}
	})
	return ln.Addr().String()
}

func echoTCP(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return nettest.ServeEcho(t, ln)
}

// origin is an HTTP server that reports what it receives.
func origin(t testing.TB, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func proxyClient(t testing.TB, proxyAddr string, user *url.Userinfo) *http.Client {
	t.Helper()
	u := &url.URL{Scheme: "http", Host: proxyAddr, User: user}
	tr := &http.Transport{Proxy: http.ProxyURL(u), ExpectContinueTimeout: 5 * time.Second}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func TestConnectWithDialer(t *testing.T) {
	addr := serve(t, &httpproxy.Server{})
	echo := echoTCP(t)
	d := &proxydial.HTTPDialer{ProxyAddr: addr}
	c, err := d.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	assertEcho(t, c, "hello through the tunnel")
}

func assertEcho(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
		t.Fatalf("echo = %q, %v; want %q", got, err, msg)
	}
}

// The bytes a client sends right after CONNECT, before the reply, go
// through the tunnel.
func TestConnectEarlyData(t *testing.T) {
	addr := serve(t, &httpproxy.Server{})
	echo := echoTCP(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\n\r\nearly", echo)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT = %v, %v", resp, err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "early" {
		t.Fatalf("tunnel = %q, %v", got, err)
	}
}

func TestConnectReplies(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	s := &httpproxy.Server{
		Allow: func(_ context.Context, req *httpproxy.Request) error {
			if req.Dst.Port == 25 {
				return errors.New("no mail")
			}
			return nil
		},
		Dial: func(ctx context.Context, req *httpproxy.Request) (net.Conn, error) {
			if req.Dst.Name == "slow.example" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", req.Dst.String())
		},
		DialTimeout: 100 * time.Millisecond,
	}
	addr := serve(t, s)
	for _, tt := range []struct {
		target string
		code   int
	}{
		{"127.0.0.1:25", 403},
		{closed, 502},
		{"slow.example:443", 504},
		{"bad host:1", 400},
		{"[::1:443", 400},
		{"example.com:0", 400},
	} {
		code, _ := rawStatus(t, addr, "CONNECT "+tt.target+" HTTP/1.1\r\n\r\n")
		if code != tt.code {
			t.Errorf("CONNECT %s = %d, want %d", tt.target, code, tt.code)
		}
	}
}

// rawStatus sends raw and returns the status code of the first response
// and the response, its header lines as "Name: value" and then the body,
// with "Connection: close" when the server ends the connection after it.
func rawStatus(t *testing.T, addr, raw string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: strings.Fields(raw)[0]})
	if err != nil {
		return 0, ""
	}
	var sb strings.Builder
	_, _ = fmt.Fprintf(&sb, "%s\r\n", resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			_, _ = fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	if resp.Close {
		sb.WriteString("Connection: close\r\n")
	}
	sb.WriteString("\r\n")
	b, _ := io.ReadAll(resp.Body)
	sb.Write(b)
	return resp.StatusCode, sb.String()
}

func basic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func TestAuth(t *testing.T) {
	var dialedBy atomic.Value
	s := &httpproxy.Server{
		Auth: []httpproxy.Authenticator{httpproxy.Credentials(map[string]string{"alice": "secret"})},
		Dial: func(ctx context.Context, req *httpproxy.Request) (net.Conn, error) {
			dialedBy.Store(req.User)
			var d net.Dialer
			return d.DialContext(ctx, "tcp", req.Dst.String())
		},
	}
	addr := serve(t, s)
	echo := echoTCP(t)

	code, reply := rawStatus(t, addr, "CONNECT "+echo+" HTTP/1.1\r\nConnection: close\r\n\r\n")
	if code != 407 || !strings.Contains(reply, `Proxy-Authenticate: Basic realm="proxy"`) {
		t.Fatalf("CONNECT without credentials = %q", reply)
	}
	for _, auth := range []string{basic("alice", "wrong"), basic("bob", "secret"), "Basic !!!", "Bearer x", basic("alice", "secret") + "x"} {
		if code, _ := rawStatus(t, addr, "CONNECT "+echo+" HTTP/1.1\r\nProxy-Authorization: "+auth+"\r\n\r\n"); code != 407 {
			t.Errorf("CONNECT with %q = %d, want 407", auth, code)
		}
	}
	// Two fields, even one valid, are refused.
	if code, _ := rawStatus(t, addr, "CONNECT "+echo+" HTTP/1.1\r\nProxy-Authorization: "+basic("alice", "secret")+"\r\nProxy-Authorization: x\r\n\r\n"); code != 400 {
		t.Errorf("CONNECT with two credentials = %d, want 400", code)
	}
	d := &proxydial.HTTPDialer{ProxyAddr: addr, Username: "alice", Password: "secret"}
	c, err := d.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	assertEcho(t, c, "authorized")
	_ = c.Close()
	if got := dialedBy.Load(); got != "alice" {
		t.Fatalf("Dial saw user %v, want alice", got)
	}
	// The wrong password through the dialer gives a ConnectError.
	d.Password = "nope"
	_, err = d.DialContext(context.Background(), "tcp", echo)
	var ce *proxydial.ConnectError
	if !errors.As(err, &ce) || ce.StatusCode != 407 || ce.Header.Get("Proxy-Authenticate") == "" {
		t.Fatalf("wrong password = %v", err)
	}
}

// Each request of a kept-alive connection is authenticated: credentials
// that passed for one request do not cover a later one without them, or
// with others.
func TestAuthPerRequest(t *testing.T) {
	o := origin(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	addr := serve(t, &httpproxy.Server{Auth: []httpproxy.Authenticator{httpproxy.Credentials(map[string]string{"alice": "secret"})}})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	get := func(auth string) int {
		t.Helper()
		req := "GET " + o.URL + "/ HTTP/1.1\r\nHost: x\r\n"
		if auth != "" {
			req += "Proxy-Authorization: " + auth + "\r\n"
		}
		if _, err := io.WriteString(c, req+"\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for i, tt := range []struct {
		auth string
		want int
	}{
		{"", 407},
		{basic("alice", "secret"), 200},
		{"", 407},
		{basic("alice", "wrong"), 407},
		{basic("alice", "secret"), 200},
	} {
		if got := get(tt.auth); got != tt.want {
			t.Fatalf("request %d with %q = %d, want %d", i, tt.auth, got, tt.want)
		}
	}
}

// A request that is not a proxy request is not authenticated, and is
// refused unless Handle serves it, so it cannot reach a target.
func TestOriginRequestsNeedHandle(t *testing.T) {
	var dials atomic.Int32
	s := &httpproxy.Server{
		Auth: []httpproxy.Authenticator{httpproxy.Credentials(map[string]string{"alice": "secret"})},
		Dial: func(context.Context, *httpproxy.Request) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("no")
		},
	}
	addr := serve(t, s)
	for _, raw := range []string{
		"GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
		"GET ftp://example.com/ HTTP/1.1\r\n\r\n",
	} {
		code, _ := rawStatus(t, addr, raw)
		if code != 400 && code != 407 && !(code == 200 && strings.HasPrefix(raw, "OPTIONS * ")) {
			t.Errorf("%q = %d, want 400 or 407, or 200 for OPTIONS *", raw, code)
		}
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("dialed %d times", n)
	}
}

func TestHandleServesOriginRequests(t *testing.T) {
	s := &httpproxy.Server{
		Handle: func(_ context.Context, req *httpproxy.Request) (bool, error) {
			if !req.Dst.IP.IsValid() && req.Dst.Name == "" {
				_, err := io.WriteString(req.Conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhome")
				return true, err
			}
			return false, nil
		},
	}
	addr := serve(t, s)
	code, reply := rawStatus(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if code != 200 || !strings.HasSuffix(reply, "home") {
		t.Fatalf("origin request = %q", reply)
	}
}

func TestForwardWithTransport(t *testing.T) {
	type seen struct {
		header http.Header
		body   string
		host   string
		uri    string
	}
	got := make(chan seen, 1)
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.Header.Clone(), string(b), r.Host, r.RequestURI}
		w.Header().Set("X-Origin", "yes")
		if r.URL.Query().Get("chunked") != "" {
			w.(http.Flusher).Flush() // no Content-Length
		}
		_, _ = io.WriteString(w, "response to "+r.Method)
	})
	var users []string
	var mu sync.Mutex
	s := &httpproxy.Server{
		Auth: []httpproxy.Authenticator{httpproxy.Credentials(map[string]string{"alice": "secret"})},
		Allow: func(_ context.Context, req *httpproxy.Request) error {
			mu.Lock()
			users = append(users, req.User)
			mu.Unlock()
			return nil
		},
		ForwardHeader: func(req *httpproxy.Request, h *httphead.Header) {
			h.Add("Via", "1.1 test")
		},
	}
	addr := serve(t, s)
	client := proxyClient(t, addr, url.UserPassword("alice", "secret"))
	for _, tt := range []struct {
		method, query, body string
		chunkedReq          bool
	}{
		{"GET", "", "", false},
		{"GET", "?chunked=1", "", false},
		{"POST", "", "a body of known length", false},
		{"POST", "?chunked=1", "a body sent chunked", true},
		{"HEAD", "", "", false},
	} {
		var body io.Reader
		if tt.body != "" {
			body = strings.NewReader(tt.body)
			if tt.chunkedReq {
				body = io.MultiReader(body) // unknown length: chunked
			}
		}
		req, _ := http.NewRequest(tt.method, o.URL+"/p"+tt.query, body)
		req.Header.Set("Connection", "X-Hop")
		req.Header.Set("X-Hop", "dropped")
		req.Header.Set("Keep-Alive", "timeout=5")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tt.method, tt.query, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		want := "response to " + tt.method
		if tt.method == "HEAD" {
			want = ""
		}
		if resp.StatusCode != 200 || string(b) != want || resp.Header.Get("X-Origin") != "yes" {
			t.Fatalf("%s %s = %d %q %v", tt.method, tt.query, resp.StatusCode, b, resp.Header)
		}
		s := <-got
		if s.body != tt.body {
			t.Errorf("%s: origin got body %q, want %q", tt.method, s.body, tt.body)
		}
		for _, h := range []string{"Proxy-Authorization", "X-Hop", "Keep-Alive", "Proxy-Connection"} {
			if s.header.Get(h) != "" {
				t.Errorf("%s: origin got %s: %q", tt.method, h, s.header.Get(h))
			}
		}
		if s.header.Get("Via") != "1.1 test" || s.host != strings.TrimPrefix(o.URL, "http://") || s.uri != "/p"+tt.query {
			t.Errorf("%s: origin got Via %q, Host %q, URI %q", tt.method, s.header.Get("Via"), s.host, s.uri)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, u := range users {
		if u != "alice" {
			t.Fatalf("Allow saw users %q", users)
		}
	}
}

// CONNECT from net/http's Transport to a TLS origin.
func TestConnectWithTransport(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secure")
	}))
	defer ts.Close()
	addr := serve(t, &httpproxy.Server{})
	tr := &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		TLSClientConfig: &tls.Config{RootCAs: ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs},
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "secure" {
		t.Fatalf("body = %q", b)
	}
}

// One client connection carries requests to different hosts.
func TestKeepAliveAcrossHosts(t *testing.T) {
	o1 := origin(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "one") })
	o2 := origin(t, func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush() // chunked
		_, _ = io.WriteString(w, "two")
	})
	s := &httpproxy.Server{}
	addr := serve(t, s)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	// Pipelined: both requests are sent before either response.
	_, _ = fmt.Fprintf(c, "GET %s/a HTTP/1.1\r\nHost: x\r\n\r\nPOST %s/b HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc", o1.URL, o2.URL)
	for i, want := range []string{"one", "two", "one"} {
		if i == 2 {
			_, _ = fmt.Fprintf(c, "GET %s/c HTTP/1.1\r\n\r\n", o1.URL)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(b) != want || resp.Close {
			t.Fatalf("response %d = %q (close %v), want %q", i, b, resp.Close, want)
		}
	}
	if n := s.ActiveConns(); n != 1 {
		t.Fatalf("ActiveConns() = %d, want 1", n)
	}
}

// An HTTP/1.0 client gets a chunked response without chunking, and the
// connection ends with it.
func TestHTTP10Client(t *testing.T) {
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "body for 1.0")
	})
	addr := serve(t, &httpproxy.Server{})
	_, reply := rawStatus(t, addr, "GET "+o.URL+"/ HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
	if !strings.HasSuffix(reply, "\r\n\r\nbody for 1.0") || strings.Contains(strings.ToLower(reply), "chunked") {
		t.Fatalf("reply = %q", reply)
	}
}

func TestExpectContinue(t *testing.T) {
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "got "+string(b))
	})
	addr := serve(t, &httpproxy.Server{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	_, _ = fmt.Fprintf(c, "PUT %s/ HTTP/1.1\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n", o.URL)
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil || line != "HTTP/1.1 100 Continue" {
		t.Fatalf("interim = %q, %v", line, err)
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "data")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "got data" {
		t.Fatalf("body = %q", b)
	}
}

// A target that answers before the request body ends gets the rest cut
// off, and the client the response and the end of the connection.
func TestEarlyResponse(t *testing.T) {
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(413)
	})
	addr := serve(t, &httpproxy.Server{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "POST %s/ HTTP/1.1\r\nContent-Length: 1000000\r\n\r\nsome", o.URL)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 413 {
		t.Fatalf("response = %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("connection still open")
	}
}

func TestUpgradePassthrough(t *testing.T) {
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" || !strings.EqualFold(r.Header.Get("Connection"), "upgrade") {
			w.WriteHeader(400)
			return
		}
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		_, _ = io.Copy(c, brw) // echo the new protocol
	})
	addr := serve(t, &httpproxy.Server{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "GET %s/ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", o.URL)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 || resp.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("upgrade = %v, %v", resp, err)
	}
	_, _ = io.WriteString(c, "frames")
	got := make([]byte, 6)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "frames" {
		t.Fatalf("upgraded echo = %q, %v", got, err)
	}
}

// Requests that could be read in two ways, or carry bytes a field cannot
// hold, are refused and end the connection, before anything is sent on.
func TestSmugglingRejected(t *testing.T) {
	// Counted are the requests that reach the origin whole; the head of a
	// request whose chunked body turns out malformed is sent on before the
	// body, which then ends short, on a connection of its own.
	var forwarded atomic.Int32
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err == nil {
			forwarded.Add(1)
		}
	})
	addr := serve(t, &httpproxy.Server{MaxHeaderBytes: 4 << 10})
	u := o.URL + "/"
	for _, tt := range []struct {
		name, raw string
		code      int
	}{
		{"CL and TE", "POST " + u + " HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400},
		{"two CL", "POST " + u + " HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", 400},
		{"CL list", "POST " + u + " HTTP/1.1\r\nContent-Length: 3, 4\r\n\r\nabcd", 400},
		{"signed CL", "POST " + u + " HTTP/1.1\r\nContent-Length: +3\r\n\r\nabc", 400},
		{"TE gzip", "POST " + u + " HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", 501},
		{"TE twice", "POST " + u + " HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501},
		{"TE in 1.0", "POST " + u + " HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400},
		{"obs-fold", "GET " + u + " HTTP/1.1\r\nX: a\r\n b\r\n\r\n", 400},
		{"space before colon", "GET " + u + " HTTP/1.1\r\nHost : x\r\n\r\n", 400},
		{"bare CR", "GET " + u + " HTTP/1.1\r\nX: a\rb\r\n\r\n", 400},
		{"NUL", "GET " + u + " HTTP/1.1\r\nX: a\x00b\r\n\r\n", 400},
		{"two Host", "GET " + u + " HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400},
		{"userinfo", "GET http://user@127.0.0.1/ HTTP/1.1\r\n\r\n", 400},
		{"HTTP/2", "GET " + u + " HTTP/2.0\r\n\r\n", 505},
		{"big head", "GET " + u + " HTTP/1.1\r\nX: " + strings.Repeat("a", 5<<10) + "\r\n\r\n", 431},
		{"space in target", "GET " + u + "a b HTTP/1.1\r\n\r\n", 400},
	} {
		code, reply := rawStatus(t, addr, tt.raw)
		if code != tt.code || !strings.Contains(reply, "Connection: close") {
			t.Errorf("%s: reply %q, want %d and close", tt.name, reply, tt.code)
		}
	}
	// Malformed chunked bodies end the exchange without a complete request
	// reaching the target.
	for _, body := range []string{"x\r\n", "5\r\nabc\r\n0\r\n\r\n", "fffffffffffffffff\r\n", "3;\x01\r\nabc\r\n0\r\n\r\n", "3\r\nabcXY0\r\n\r\n"} {
		_, reply := rawStatus(t, addr, "POST "+u+" HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"+body)
		if strings.Contains(reply, " 200 ") {
			t.Errorf("chunked body %q was forwarded: %q", body, reply)
		}
	}
	if n := forwarded.Load(); n != 0 {
		t.Fatalf("%d smuggled requests reached the origin", n)
	}
}

// A hook cannot inject header lines.
func TestForwardHeaderInjection(t *testing.T) {
	var forwarded atomic.Int32
	o := origin(t, func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) })
	s := &httpproxy.Server{ForwardHeader: func(req *httpproxy.Request, h *httphead.Header) {
		h.Add("X-Client", req.Header.Get("X-Name")+"\r\nEvil: yes")
	}}
	addr := serve(t, s)
	if code, _ := rawStatus(t, addr, "GET "+o.URL+"/ HTTP/1.1\r\nX-Name: a\r\n\r\n"); code != 500 {
		t.Fatalf("injected header = %d, want 500", code)
	}
	if forwarded.Load() != 0 {
		t.Fatal("request with an injected header was forwarded")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	errs := make(chan error, 1)
	s := &httpproxy.Server{HandshakeTimeout: 100 * time.Millisecond, OnError: func(_ net.Conn, err error) {
		select {
		case errs <- err:
		default:
		}
	}}
	addr := serve(t, s)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "GET http://example.com/ HTTP/1.1\r\n") // never ends
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after the timeout = %v, want EOF", err)
	}
	if err := <-errs; !errors.Is(err, errDeadline) {
		t.Fatalf("OnError = %v, want a deadline error", err)
	}
}

func TestIdleTimeout(t *testing.T) {
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {})
	s := &httpproxy.Server{IdleTimeout: 100 * time.Millisecond, OnError: func(_ net.Conn, err error) {
		t.Errorf("OnError(%v) for an idle connection", err)
	}}
	addr := serve(t, s)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "GET %s/ HTTP/1.1\r\n\r\n", o.URL)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("read on the idle connection = %v, want EOF", err)
	}
}

func TestCloseEndsTunnelsAndShutdownWaits(t *testing.T) {
	s := &httpproxy.Server{}
	addr := serve(t, s)
	echo := echoTCP(t)
	c, err := (&proxydial.HTTPDialer{ProxyAddr: addr}).DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	assertEcho(t, c, "x")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() with a live tunnel = %v, want DeadlineExceeded", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("tunnel read after Close = %v, want EOF", err)
	}
	waitFor(t, "the connections to end", func() bool { return s.ActiveConns() == 0 })
	if err := s.ServeConn(context.Background(), c); !errors.Is(err, httpproxy.ErrServerClosed) {
		t.Fatalf("ServeConn after Close = %v", err)
	}
}

func TestShutdownDrains(t *testing.T) {
	s := &httpproxy.Server{}
	addr := serve(t, s)
	echo := echoTCP(t)
	c, err := (&proxydial.HTTPDialer{ProxyAddr: addr}).DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	_ = c.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown() = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the tunnel ended")
	}
}

var errDeadline = os.ErrDeadlineExceeded
