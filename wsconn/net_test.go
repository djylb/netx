package wsconn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/httphead"
)

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// pair returns a server and a client connection over TCP.
func pair(t *testing.T, so *ServerOptions, co *ClientOptions) (srv, cli *Conn) {
	t.Helper()
	ctx := testContext(t)
	ln := listen(t)
	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- result{nil, err}
			return
		}
		c, err := Accept(ctx, raw, so)
		ch <- result{c, err}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli, _, err = Client(ctx, raw, "ws://"+ln.Addr().String()+"/path?q=1", co)
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() {
		_ = cli.NetConn().Close()
		_ = r.c.NetConn().Close()
	})
	return r.c, cli
}

func TestHandshake(t *testing.T) {
	so := &ServerOptions{
		Subprotocols: []string{"v2", "v1"},
		Header:       httphead.Header{{Name: "X-Server", Value: "yes"}},
	}
	co := &ClientOptions{
		Subprotocols: []string{"v1", "v2"},
		Header:       httphead.Header{{Name: "X-Token", Value: "t"}},
		Host:         "front.example",
	}
	srv, cli := pair(t, so, co)
	if srv.Subprotocol() != "v2" || cli.Subprotocol() != "v2" {
		t.Fatalf("subprotocols %q %q", srv.Subprotocol(), cli.Subprotocol())
	}
	req := srv.Request()
	if req.Target != "/path?q=1" || req.Header.Get("X-Token") != "t" || req.Header.Get("Host") != "front.example" {
		t.Fatalf("request %+v", req)
	}
	if cli.Response().Header.Get("X-Server") != "yes" {
		t.Fatalf("response %+v", cli.Response())
	}
	if srv.Compressed() || cli.Compressed() {
		t.Fatal("compression without options")
	}
	if srv.RemoteAddr().String() != cli.LocalAddr().String() {
		t.Fatalf("addresses %v %v", srv.RemoteAddr(), cli.LocalAddr())
	}
}

func TestHandshakeRefusals(t *testing.T) {
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	base := "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\n"
	tests := []struct {
		name, req string
		status    int
		opts      *ServerOptions
	}{
		{"ok", base + "Sec-WebSocket-Version: 13\r\n\r\n", 101, nil},
		{"lower case tokens", strings.ReplaceAll(base, "Upgrade\r\n", "keep-alive, upgrade\r\n") + "sec-websocket-version: 13\r\n\r\n", 101, nil},
		{"no host", strings.Replace(base, "Host: h\r\n", "", 1) + "Sec-WebSocket-Version: 13\r\n\r\n", 101, nil},
		{"version 8", base + "Sec-WebSocket-Version: 8\r\n\r\n", 426, nil},
		{"post", strings.Replace(base, "GET", "POST", 1) + "Sec-WebSocket-Version: 13\r\n\r\n", 405, nil},
		{"http 1.0", strings.Replace(base, "1.1", "1.0", 1) + "Sec-WebSocket-Version: 13\r\n\r\n", 505, nil},
		{"no upgrade", strings.Replace(base, "Upgrade: websocket\r\n", "", 1) + "Sec-WebSocket-Version: 13\r\n\r\n", 426, nil},
		{"short key", strings.Replace(base, key, "AAAA", 1) + "Sec-WebSocket-Version: 13\r\n\r\n", 400, nil},
		{"cross origin", base + "Sec-WebSocket-Version: 13\r\nOrigin: https://evil.example\r\n\r\n", 403, nil},
		{"same origin", base + "Sec-WebSocket-Version: 13\r\nOrigin: https://H\r\n\r\n", 101, nil},
		{"any origin", base + "Sec-WebSocket-Version: 13\r\nOrigin: https://evil.example\r\n\r\n", 101, &ServerOptions{CheckOrigin: AnyOrigin}},
		{"origin hook", base + "Sec-WebSocket-Version: 13\r\n\r\n", 401, &ServerOptions{CheckOrigin: func(*httphead.Request) error {
			return &HandshakeError{Status: 401, Msg: "no"}
		}}},
		{"head too large", base + "X: " + strings.Repeat("a", 200) + "\r\n\r\n", 431, &ServerOptions{MaxHeaderBytes: 100}},
		{"malformed", "GET / HTTP/1.1\r\nBad Field: x\r\n\r\n", 400, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer func() { _ = a.Close() }()
			done := make(chan error, 1)
			go func() {
				c, err := Accept(context.Background(), b, tt.opts)
				if c != nil {
					_ = c.NetConn().Close()
				}
				done <- err
			}()
			go func() { _, _ = io.WriteString(a, tt.req) }()
			head, err := httphead.Read(bufio.NewReader(a), nil, 4096)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := httphead.ParseResponse(string(head), nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Code != tt.status {
				t.Fatalf("status %d, want %d", resp.Code, tt.status)
			}
			if tt.status == 426 && resp.Header.Get("Sec-WebSocket-Version") != "13" {
				t.Fatal("426 without Sec-WebSocket-Version")
			}
			if tt.status == 101 && resp.Header.Get("Sec-WebSocket-Accept") != AcceptKey(key) {
				t.Fatal("wrong accept key")
			}
			_ = a.Close()
			err = <-done
			if (err == nil) != (tt.status == 101) {
				t.Fatalf("Accept error %v", err)
			}
			var he *HandshakeError
			if err != nil && tt.status != 431 && tt.status != 400 && (!errors.As(err, &he) || he.Status != tt.status) {
				t.Fatalf("error %v", err)
			}
		})
	}
}

func TestClientRefusals(t *testing.T) {
	tests := []struct {
		name string
		resp func(key string) string
	}{
		{"status 200", func(string) string { return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" }},
		{"wrong accept", func(string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n"
		}},
		{"unrequested protocol", func(key string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + AcceptKey(key) + "\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
		}},
		{"unrequested extension", func(key string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + AcceptKey(key) + "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer func() { _ = a.Close() }()
			go func() {
				head, err := httphead.Read(bufio.NewReader(a), nil, 4096)
				if err != nil {
					return
				}
				req, _ := httphead.ParseRequest(string(head), nil)
				_, _ = io.WriteString(a, tt.resp(req.Header.Get("Sec-WebSocket-Key")))
			}()
			_, resp, err := Client(context.Background(), b, "ws://h/", nil)
			var he *HandshakeError
			if !errors.As(err, &he) || resp == nil || he.Response != resp {
				t.Fatalf("err %v resp %v", err, resp)
			}
		})
	}
	if _, _, err := Client(context.Background(), &memConn{r: strings.NewReader("")}, "ftp://h/", nil); err == nil {
		t.Fatal("ftp URL accepted")
	}
	if _, _, err := Client(context.Background(), &memConn{r: strings.NewReader("")}, "ws://h/", &ClientOptions{
		Header: httphead.Header{{Name: "Sec-WebSocket-Key", Value: "x"}},
	}); err == nil {
		t.Fatal("reserved field accepted")
	}
}

// The frames a client sends with its request stay readable.
func TestAcceptKeepsBufferedFrames(t *testing.T) {
	ln := listen(t)
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		req := "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
		_, _ = c.Write(append([]byte(req), frame(finBit|opText, true, []byte("early"))...))
		_, _ = io.Copy(io.Discard, c)
	}()
	raw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(raw)
	head, err := httphead.Read(br, nil, 4096)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := httphead.ParseRequest(string(head), nil)
	c, err := AcceptRequest(testContext(t), raw, br, &req, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.NetConn().Close() }()
	if _, p, err := c.ReadMessage(); err != nil || string(p) != "early" {
		t.Fatalf("%q %v", p, err)
	}
}

func TestMessagesBothWays(t *testing.T) {
	for _, comp := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "deflate"}[comp], func(t *testing.T) {
			var so ServerOptions
			var co ClientOptions
			if comp {
				so.Compression = &Compression{Threshold: -1}
				co.Compression = &Compression{Level: 6}
			}
			srv, cli := pair(t, &so, &co)
			if srv.Compressed() != comp || cli.Compressed() != comp {
				t.Fatalf("compressed %v %v", srv.Compressed(), cli.Compressed())
			}
			r := rand.New(rand.NewPCG(3, 4))
			msgs := [][]byte{nil, []byte("x"), bytes.Repeat([]byte("abc"), 50000), make([]byte, 200000)}
			for i := range msgs[3] {
				msgs[3][i] = byte(r.Uint32())
			}
			for _, pair := range [][2]*Conn{{srv, cli}, {cli, srv}} {
				w, rd := pair[0], pair[1]
				errc := make(chan error, 1)
				go func() {
					for _, m := range msgs {
						if err := w.WriteMessage(Binary, m); err != nil {
							errc <- err
							return
						}
					}
					nw, _ := w.NextWriter(Text)
					for range 3000 {
						_, _ = io.WriteString(nw, "héllo wörld ")
					}
					errc <- nw.Close()
				}()
				for i, m := range msgs {
					typ, p, err := rd.ReadMessage()
					if err != nil || typ != Binary || !bytes.Equal(p, m) {
						t.Fatalf("message %d: %v %d bytes %v", i, typ, len(p), err)
					}
				}
				typ, p, err := rd.ReadMessage()
				if err != nil || typ != Text || string(p) != strings.Repeat("héllo wörld ", 3000) {
					t.Fatalf("text: %v %d %v", typ, len(p), err)
				}
				if err := <-errc; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCloseHandshake(t *testing.T) {
	for _, initiator := range []string{"server", "client"} {
		t.Run(initiator, func(t *testing.T) {
			srv, cli := pair(t, nil, nil)
			a, b := srv, cli
			if initiator == "client" {
				a, b = cli, srv
			}
			got := make(chan error, 1)
			go func() {
				_, _, err := b.ReadMessage()
				got <- err
			}()
			start := time.Now()
			if err := a.CloseWithStatus(StatusGoingAway, "bye"); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("Close took %v", d)
			}
			var ce *CloseError
			if err := <-got; !errors.As(err, &ce) || ce.Code != StatusGoingAway || ce.Reason != "bye" {
				t.Fatalf("peer read %v", err)
			}
			select {
			case <-b.done:
			case <-time.After(5 * time.Second):
				t.Fatal("peer did not close")
			}
			if _, _, err := a.ReadMessage(); err == nil {
				t.Fatal("read after Close")
			}
		})
	}
}

// Close returns within the close timeout when a write is blocked because
// the peer does not read, and the write fails.
func TestCloseWithBlockedWriter(t *testing.T) {
	srv, _ := pair(t, &ServerOptions{Options: Options{CloseTimeout: 300 * time.Millisecond}}, nil)
	werr := make(chan error, 1)
	go func() {
		big := make([]byte, 1<<20)
		for {
			if err := srv.WriteMessage(Binary, big); err != nil {
				werr <- err
				return
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	_ = srv.Close()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close took %v", d)
	}
	select {
	case err := <-werr:
		if err == nil {
			t.Fatal("write succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer still blocked")
	}
}

func TestStreamConnCopy(t *testing.T) {
	for _, comp := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "deflate"}[comp], func(t *testing.T) {
			var so ServerOptions
			var co ClientOptions
			if comp {
				so.Compression = &Compression{}
				co.Compression = &Compression{}
			}
			srv, cli := pair(t, &so, &co)
			s, c := NewStreamConn(srv), NewStreamConn(cli)
			data := make([]byte, 3<<20+17)
			r := rand.New(rand.NewPCG(5, 6))
			for i := range data {
				data[i] = byte(r.IntN(16))
			}
			// Both ways at once. A close frame ends both directions, as
			// WebSocket has no half-close, so the sides close once both
			// streams arrived.
			var wg sync.WaitGroup
			var copied sync.WaitGroup
			copied.Add(2)
			check := func(dst, src net.Conn) {
				defer wg.Done()
				go func() {
					if _, err := io.Copy(dst, bytes.NewReader(data)); err != nil {
						t.Error(err)
					}
				}()
				got := make([]byte, len(data))
				n, err := io.ReadFull(src, got)
				if err != nil || !bytes.Equal(got, data) {
					t.Errorf("copied %d of %d bytes: %v", n, len(data), err)
				}
				copied.Done()
				copied.Wait()
				_ = dst.Close()
			}
			wg.Add(2)
			go check(s, c)
			go check(c, s)
			wg.Wait()
		})
	}
}

func TestConcurrentWritersAndPings(t *testing.T) {
	var pongs atomic.Int32
	srv, cli := pair(t, nil, &ClientOptions{Options: Options{OnPong: func(*Conn, []byte) { pongs.Add(1) }}})
	const writers, each = 8, 200
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := bytes.Repeat([]byte{byte(i)}, 1000+i)
			for range each {
				if i%2 == 0 {
					if err := cli.WriteMessage(Binary, msg); err != nil {
						t.Error(err)
						return
					}
					continue
				}
				w, _ := cli.NextWriter(Binary)
				_, _ = w.Write(msg[:500])
				_, _ = w.Write(msg[500:])
				if err := w.Close(); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		for range 50 {
			_ = cli.Ping([]byte("hb"))
		}
	}()
	// The client reads too, for the pongs and the server's pings.
	go func() {
		for {
			if _, _, err := cli.ReadMessage(); err != nil {
				return
			}
		}
	}()
	go func() {
		for range 50 {
			_ = srv.Ping(nil)
		}
	}()
	for n := range writers * each {
		_, p, err := srv.ReadMessage()
		if err != nil {
			t.Fatalf("message %d: %v", n, err)
		}
		for _, b := range p {
			if b != p[0] || len(p) != 1000+int(p[0]) {
				t.Fatalf("interleaved message of %d bytes", len(p))
			}
		}
	}
	wg.Wait()
	<-pingDone
	// Pings sent after the last message are answered only while the
	// server reads.
	go func() {
		for {
			if _, _, err := srv.ReadMessage(); err != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for pongs.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if pongs.Load() == 0 {
		t.Fatal("no pongs")
	}
}

// A read interrupted by a deadline leaves the connection usable.
func TestReadDeadlineResumes(t *testing.T) {
	srv, cli := pair(t, nil, nil)
	_ = srv.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := srv.ReadMessage(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	_ = srv.SetReadDeadline(time.Time{})
	go func() { _ = cli.WriteMessage(Text, []byte("after")) }()
	if _, p, err := srv.ReadMessage(); err != nil || string(p) != "after" {
		t.Fatalf("%q %v", p, err)
	}
}

func TestDialer(t *testing.T) {
	ln := listen(t)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		c, err := Accept(context.Background(), raw, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.NetConn().Close() }()
		typ, p, err := c.ReadMessage()
		if err == nil {
			_ = c.WriteMessage(typ, p)
		}
		_, _, _ = c.ReadMessage()
	}()
	d := &Dialer{}
	c, resp, err := d.Dial(testContext(t), "ws://"+ln.Addr().String()+"/echo")
	if err != nil || resp.Code != 101 {
		t.Fatal(err)
	}
	if err := c.WriteMessage(Text, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, p, err := c.ReadMessage(); err != nil || string(p) != "ping" {
		t.Fatalf("%q %v", p, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Dial(context.Background(), "wss://127.0.0.1:1/"); !errors.Is(err, ErrNoTLSDialer) {
		t.Fatalf("wss without TLS: %v", err)
	}
}
