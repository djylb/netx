package httpproxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/httpproxy"
)

// scriptedOrigin serves each connection with handle, counting connections.
func scriptedOrigin(t *testing.T, handle func(c net.Conn, br *bufio.Reader)) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns atomic.Int32
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				handle(c, bufio.NewReader(c))
			})
		}
	})
	return ln.Addr().String(), &conns
}

// readReq reads a request head from br and returns it.
func readReq(br *bufio.Reader) (httphead.Request, error) {
	b, err := httphead.Read(br, nil, 64<<10)
	if err != nil {
		return httphead.Request{}, err
	}
	return httphead.ParseRequest(string(b), nil)
}

func doGet(t *testing.T, c net.Conn, br *bufio.Reader, url, method string) *http.Response {
	t.Helper()
	_, _ = fmt.Fprintf(c, "%s %s HTTP/1.1\r\n\r\n", method, url)
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

// A kept connection that the target closed while idle is detected, and an
// idempotent request that finds it dead before any response is sent again
// on a new one; a POST is never sent twice.
func TestKeptConnRetry(t *testing.T) {
	var requests atomic.Int32
	origin, conns := scriptedOrigin(t, func(c net.Conn, br *bufio.Reader) {
		for i := 0; ; i++ {
			req, err := readReq(br)
			if err != nil {
				return
			}
			requests.Add(1)
			if i == 1 {
				return // closes without answering its second request
			}
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			_ = req
		}
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
	if resp := doGet(t, c, br, "http://"+origin+"/1", "GET"); resp.StatusCode != 200 {
		t.Fatalf("first GET = %d", resp.StatusCode)
	}
	// The second GET goes over the kept connection, which closes: it is
	// sent again on a new one.
	if resp := doGet(t, c, br, "http://"+origin+"/2", "GET"); resp.StatusCode != 200 {
		t.Fatalf("retried GET = %d", resp.StatusCode)
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("connections = %d, want 2", n)
	}
	// The same for a POST gets 502, not a second copy.
	_, _ = fmt.Fprintf(c, "POST http://%s/3 HTTP/1.1\r\nContent-Length: 1\r\n\r\nx", origin)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 502 {
		t.Fatalf("POST on a dying kept connection = %d, want 502", resp.StatusCode)
	}
	if n := requests.Load(); n != 4 {
		t.Fatalf("the origin read %d requests, want 4", n)
	}
}

// A kept connection that the target closes while idle leaves the pool.
func TestKeptConnClosedByTarget(t *testing.T) {
	origin, _ := scriptedOrigin(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readReq(br); err == nil {
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}
		time.Sleep(50 * time.Millisecond)
	})
	s := &httpproxy.Server{}
	addr := serve(t, s)
	rawStatus(t, addr, "GET http://"+origin+"/ HTTP/1.1\r\n\r\n")
	waitFor(t, "the closed kept connection to leave the pool", func() bool { return s.IdleConns() == 0 })
}

// ReuseKey and MaxIdleConnsPerKey choose what is kept.
func TestReuseKey(t *testing.T) {
	origin, conns := scriptedOrigin(t, func(c net.Conn, br *bufio.Reader) {
		for {
			if _, err := readReq(br); err != nil {
				return
			}
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}
	})
	for _, tt := range []struct {
		name  string
		s     *httpproxy.Server
		conns int32
	}{
		{"default", &httpproxy.Server{}, 1},
		{"no reuse", &httpproxy.Server{MaxIdleConnsPerKey: -1}, 3},
		{"own key", &httpproxy.Server{ReuseKey: func(req *httpproxy.Request) (string, bool) {
			return req.Header.Get("X-Route"), req.Header.Get("X-Route") != ""
		}}, 3},
	} {
		conns.Store(0)
		addr := serve(t, tt.s)
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		for _, route := range []string{"a", "b", ""} {
			_, _ = fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nX-Route: %s\r\n\r\n", origin, route)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		}
		_ = c.Close()
		if n := conns.Load(); n != tt.conns {
			t.Errorf("%s: %d target connections, want %d", tt.name, n, tt.conns)
		}
	}
}

// Large bodies of a known length go through exactly, in both directions,
// counted exactly by the relay's flows, and the connections stay usable.
func TestLargeBodiesSplicedExactly(t *testing.T) {
	const size = 4<<20 + 7
	body := bytes.Repeat([]byte("0123456789abcdef"), size/16+1)[:size]
	sum := sha256.Sum256(body)
	origin, _ := scriptedOrigin(t, func(c net.Conn, br *bufio.Reader) {
		for {
			req, err := readReq(br)
			if err != nil {
				return
			}
			_, n, _ := httphead.RequestBody(req.Header, req.Minor)
			h := sha256.New()
			if _, err := io.CopyN(h, br, n); err != nil {
				return
			}
			if !bytes.Equal(h.Sum(nil), sum[:]) {
				_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
				continue
			}
			_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
			_, _ = c.Write(body)
		}
	})
	var up, down atomic.Int64
	s := &httpproxy.Server{RelayOptions: func(*httpproxy.Request) []netx.RelayOption {
		return []netx.RelayOption{netx.WithRelayFlows(
			&netx.RelayFlow{Done: func(n int64) error { up.Add(n); return nil }},
			&netx.RelayFlow{Done: func(n int64) error { down.Add(n); return nil }},
		)}
	}}
	var results []httpproxy.Result
	var mu sync.Mutex
	s.OnDone = func(_ *httpproxy.Request, r httpproxy.Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}
	addr := serve(t, s)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(c)
	for i := range 2 {
		go func() {
			_, _ = fmt.Fprintf(c, "PUT http://%s/ HTTP/1.1\r\nContent-Length: %d\r\n\r\n", origin, size)
			_, _ = c.Write(body)
		}()
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		n, err := io.Copy(h, resp.Body)
		if resp.StatusCode != 200 || err != nil || n != size || !bytes.Equal(h.Sum(nil), sum[:]) {
			t.Fatalf("exchange %d: %d, %d bytes, %v", i, resp.StatusCode, n, err)
		}
	}
	waitFor(t, "OnDone", func() bool { mu.Lock(); defer mu.Unlock(); return len(results) == 2 })
	mu.Lock()
	defer mu.Unlock()
	var toTarget, toClient int64
	for _, r := range results {
		if r.Status != 200 || r.Err != nil {
			t.Fatalf("result %+v", r)
		}
		toTarget += r.ToTarget
		toClient += r.ToClient
	}
	if toTarget != up.Load() || toClient != down.Load() || toTarget < 2*size || toClient < 2*size {
		t.Fatalf("results counted %d/%d, flows %d/%d", toTarget, toClient, up.Load(), down.Load())
	}
	if !results[1].Reused {
		t.Fatal("the second exchange did not reuse the connection")
	}
}

func TestMaxForwards(t *testing.T) {
	var forwarded atomic.Value
	origin, _ := scriptedOrigin(t, func(c net.Conn, br *bufio.Reader) {
		req, err := readReq(br)
		if err != nil {
			return
		}
		forwarded.Store(req.Header.Get("Max-Forwards"))
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	addr := serve(t, &httpproxy.Server{})
	_, reply := rawStatus(t, addr, "TRACE http://"+origin+"/ HTTP/1.1\r\nMax-Forwards: 0\r\nProxy-Authorization: secret\r\nX-A: 1\r\n\r\n")
	if !strings.Contains(reply, "TRACE http://"+origin+"/ HTTP/1.1\r\n") || !strings.Contains(reply, "X-A: 1") || strings.Contains(reply, "secret") {
		t.Fatalf("TRACE reply %q", reply)
	}
	if code, _ := rawStatus(t, addr, "OPTIONS http://"+origin+"/ HTTP/1.1\r\nMax-Forwards: 0\r\n\r\n"); code != 200 || forwarded.Load() != nil {
		t.Fatalf("OPTIONS Max-Forwards: 0 = %d, forwarded %v", code, forwarded.Load())
	}
	if code, _ := rawStatus(t, addr, "OPTIONS http://"+origin+"/ HTTP/1.1\r\nMax-Forwards: 5\r\n\r\n"); code != 200 || forwarded.Load() != "4" {
		t.Fatalf("OPTIONS Max-Forwards: 5 = %d, forwarded %v", code, forwarded.Load())
	}
}

// Via, Intercept with HostDst, and a response with a transfer coding
// before chunked, which is passed on.
func TestViaInterceptAndCodings(t *testing.T) {
	type seen struct{ via, host, target string }
	got := make(chan seen, 1)
	origin, _ := scriptedOrigin(t, func(c net.Conn, br *bufio.Reader) {
		req, err := readReq(br)
		if err != nil {
			return
		}
		got <- seen{req.Header.Get("Via"), req.Header.Get("Host"), req.Target}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	})
	addr := serve(t, &httpproxy.Server{Via: "proxy", Intercept: httpproxy.HostDst})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "GET /path HTTP/1.1\r\nHost: %s\r\nVia: 1.0 first\r\n\r\n", origin)
	tp := bufio.NewReader(c)
	head, err := httphead.Read(tp, nil, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := httphead.ParseResponse(string(head), nil)
	if err != nil {
		t.Fatal(err)
	}
	if te := resp.Header.Get("Transfer-Encoding"); te != "gzip, chunked" || resp.Header.Get("Via") != "1.1 proxy" {
		t.Fatalf("response head %q", head)
	}
	s := <-got
	if s.via != "1.0 first, 1.1 proxy" || s.host != origin || s.target != "/path" {
		t.Fatalf("origin saw %+v", s)
	}
}

// A refusal that ends the connection while the client still sends its body
// reaches the client: the server reads on for a while before closing, so
// that the unread body does not reset the connection.
func TestLingeringClose(t *testing.T) {
	s := &httpproxy.Server{Auth: []httpproxy.Authenticator{httpproxy.Credentials(nil)}}
	addr := serve(t, s)
	for range 5 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		go func() {
			_, _ = io.WriteString(c, "POST http://127.0.0.1:1/ HTTP/1.1\r\nContent-Length: 4000000\r\n\r\n")
			buf := make([]byte, 64<<10)
			for range 3 {
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}()
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != 407 {
			t.Fatalf("refusal = %v, %v", resp, err)
		}
		_ = c.Close()
	}
}

func TestResponseHeaderTimeout(t *testing.T) {
	origin, _ := scriptedOrigin(t, func(c net.Conn, br *bufio.Reader) {
		_, _ = readReq(br)
		time.Sleep(time.Second) // never answers in time
	})
	addr := serve(t, &httpproxy.Server{ResponseHeaderTimeout: 100 * time.Millisecond})
	start := time.Now()
	if code, _ := rawStatus(t, addr, "GET http://"+origin+"/ HTTP/1.1\r\n\r\n"); code != 504 {
		t.Fatalf("slow target = %d, want 504", code)
	}
	if d := time.Since(start); d > 800*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

// OnDone reports refusals too, with their status.
func TestOnDoneRefusal(t *testing.T) {
	done := make(chan httpproxy.Result, 1)
	s := &httpproxy.Server{
		Allow:  func(context.Context, *httpproxy.Request) error { return errors.New("no") },
		OnDone: func(_ *httpproxy.Request, r httpproxy.Result) { done <- r },
	}
	addr := serve(t, s)
	rawStatus(t, addr, "GET http://example.com/ HTTP/1.1\r\n\r\n")
	if r := <-done; r.Status != 403 || r.Err == nil || r.ToClient == 0 {
		t.Fatalf("result %+v", r)
	}
}
