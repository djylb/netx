package httpproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/httpproxy"
	"github.com/djylb/netx/proxydial"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Every goroutine the server starts, for tunnels, forwarded requests,
// upgrades, refusals and aborted exchanges, ends with Close.
func TestNoGoroutineLeak(t *testing.T) {
	o := origin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stall" {
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	})
	echo := echoTCP(t)
	before := runtime.NumGoroutine()

	s := &httpproxy.Server{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = s.Serve(ln); close(done) }()
	addr := ln.Addr().String()

	tunnel, err := (&proxydial.HTTPDialer{ProxyAddr: addr}).DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	assertEcho(t, tunnel, "live")
	client := proxyClient(t, addr, nil)
	for range 5 {
		resp, err := client.Post(o.URL+"/", "text/plain", io.MultiReader(stringsReader("chunked body")))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	rawStatus(t, addr, "GET / HTTP/1.1\r\n\r\n")
	// An exchange in progress, waiting on the origin, and an idle kept-alive
	// connection.
	stalled, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(stalled, "GET %s/stall HTTP/1.1\r\n\r\n", o.URL)
	if _, err := bufio.NewReader(stalled).ReadByte(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "connections", func() bool { return s.ActiveConns() >= 3 })

	_ = s.Close()
	<-done
	_ = tunnel.Close()
	_ = stalled.Close()
	client.Transport.(*http.Transport).CloseIdleConnections()
	waitFor(t, "the server's goroutines to end", func() bool { return runtime.NumGoroutine() <= before })
}

func stringsReader(s string) io.Reader { return &onceReader{s: s} }

type onceReader struct{ s string }

func (r *onceReader) Read(p []byte) (int, error) {
	if r.s == "" {
		return 0, io.EOF
	}
	n := copy(p, r.s)
	r.s = r.s[n:]
	return n, nil
}

// Connections to targets are kept for later requests, one serving them
// all here, and closed: when the client goes away in the middle of a
// response, and by Close for those kept.
func TestTargetConnsClosed(t *testing.T) {
	var opened, closed atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/endless" {
			for {
				if _, err := w.Write(make([]byte, 32<<10)); err != nil {
					return
				}
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	ts.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		switch st {
		case http.StateNew:
			opened.Add(1)
		case http.StateClosed, http.StateHijacked:
			closed.Add(1)
		case http.StateActive, http.StateIdle:
			// In use or kept: neither opened nor closed.
		}
	}
	ts.Start()
	defer ts.Close()
	s := &httpproxy.Server{}
	addr := serve(t, s)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	for range 10 {
		_, _ = fmt.Fprintf(c, "GET %s/ HTTP/1.1\r\n\r\n", ts.URL)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if n := opened.Load(); n != 1 {
		t.Fatalf("10 requests opened %d target connections, want 1", n)
	}
	_, _ = fmt.Fprintf(c, "GET %s/endless HTTP/1.1\r\n\r\n", ts.URL)
	if _, err := io.ReadFull(br, make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	waitFor(t, "the target connection of the aborted response to close", func() bool {
		return opened.Load() == 1 && closed.Load() == 1
	})
	// One kept connection, then Close.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c2, "GET %s/ HTTP/1.1\r\nConnection: close\r\n\r\n", ts.URL)
	if _, err := io.ReadAll(c2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a kept connection", func() bool { return s.IdleConns() == 1 })
	_ = s.Close()
	waitFor(t, "Close to close the kept connection", func() bool {
		return opened.Load() == 2 && closed.Load() == 2 && s.IdleConns() == 0
	})
}
