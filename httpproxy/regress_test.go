package httpproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/httpproxy"
)

// A target that answers early and stops reading the request body does not
// hold the exchange: the rest of the body is cut off.
func TestEarlyResponseFromTargetThatStopsReading(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	hold := make(chan struct{})
	defer close(hold)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadSlice('\n')
			if err != nil || len(line) <= 2 {
				break
			}
		}
		time.Sleep(200 * time.Millisecond) // the proxy's writes fill the buffers
		_, _ = io.WriteString(c, "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
		<-hold // open, never reading
	}()
	s := &httpproxy.Server{}
	addr := serve(t, s)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nContent-Length: %d\r\n\r\n", ln.Addr(), 64<<20)
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 413 {
		t.Fatalf("response = %v, %v", resp, err)
	}
	waitFor(t, "the exchange to end", func() bool { return s.ActiveConns() == 0 })
}

// CONNECT in another case reaches the hooks as "CONNECT", so that a policy
// on the method holds.
func TestLowercaseConnectIsCanonical(t *testing.T) {
	methods := make(chan string, 1)
	s := &httpproxy.Server{Allow: func(_ context.Context, req *httpproxy.Request) error {
		methods <- req.Method
		return &httpproxy.StatusError{Code: 403}
	}}
	addr := serve(t, s)
	if code, _ := rawStatus(t, addr, "connect 127.0.0.1:22 HTTP/1.1\r\n\r\n"); code != 403 {
		t.Fatalf("lowercase connect = %d", code)
	}
	if m := <-methods; m != "CONNECT" {
		t.Fatalf("Allow saw method %q", m)
	}
}

// Check sees the connection being served, as socks5's does, so that one
// check can look at its type.
func TestCheckSeesServedConn(t *testing.T) {
	conns := make(chan net.Conn, 1)
	s := &httpproxy.Server{Auth: []httpproxy.Authenticator{httpproxy.BasicAuth{
		Check: func(_ context.Context, c net.Conn, _, _ string) (bool, error) {
			conns <- c
			return false, nil
		},
	}}}
	addr := serve(t, s)
	rawStatus(t, addr, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nProxy-Authorization: "+basic("a", "b")+"\r\n\r\n")
	if c := <-conns; func() bool { _, ok := c.(*net.TCPConn); return !ok }() {
		t.Fatalf("Check got a %T, want the *net.TCPConn being served", c)
	}
}

// Shutdown ends a kept-alive connection after the request in progress.
func TestShutdownEndsKeptAliveConns(t *testing.T) {
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {})
	s := &httpproxy.Server{}
	addr := serve(t, s)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	_, _ = fmt.Fprintf(c, "GET %s/ HTTP/1.1\r\n\r\n", o.URL)
	if _, err := http.ReadResponse(br, nil); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()
	waitFor(t, "Shutdown to start", func() bool {
		select {
		case err := <-done:
			done <- err
			return true
		default:
		}
		return false
	})
}

// A request whose last body bytes the target answers at once, before the
// request's direction has seen its end, is not taken for one cut off: both
// connections are kept.
func TestFastAnswerToCompleteRequestKeepsConns(t *testing.T) {
	origin, conns := scriptedOrigin(t, func(c net.Conn, br *bufio.Reader) {
		for {
			req, err := readReq(br)
			if err != nil {
				return
			}
			_, n, _ := httphead.RequestBody(req.Header, req.Minor)
			if _, err := io.CopyN(io.Discard, br, n); err != nil {
				return
			}
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	})
	s := &httpproxy.Server{RelayOptions: func(*httpproxy.Request) []netx.RelayOption {
		// Slow after each write, standing in for a delay in scheduling.
		slow := &netx.RelayFlow{Done: func(int64) error { time.Sleep(50 * time.Millisecond); return nil }}
		return []netx.RelayOption{netx.WithRelayFlows(slow, nil)}
	}}
	addr := serve(t, s)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	for i := range 3 {
		_, _ = fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", origin)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d target connections, want 1", n)
	}
}
