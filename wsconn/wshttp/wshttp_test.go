package wshttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/wsconn"
	"github.com/djylb/netx/wsconn/wshttp"
)

// wrapped hides the http.Hijacker of the ResponseWriter, as middleware
// does, behind an Unwrap method.
type wrapped struct{ http.ResponseWriter }

func (w wrapped) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestUpgrade(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "s=1")
		c, err := wshttp.Upgrade(wrapped{w}, r, &wsconn.ServerOptions{Subprotocols: []string{"echo"}})
		if err != nil {
			return
		}
		// The handler returns; the connection lives on.
		go func() {
			defer func() { _ = c.Close() }()
			for {
				typ, p, err := c.ReadMessage()
				if err != nil {
					return
				}
				if err := c.WriteMessage(typ, p); err != nil {
					return
				}
			}
		}()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	d := &wsconn.Dialer{ClientOptions: wsconn.ClientOptions{
		Subprotocols: []string{"echo"},
		Header:       httphead.Header{{Name: "Origin", Value: srv.URL}},
	}}
	c, resp, err := d.Dial(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subprotocol() != "echo" || resp.Header.Get("Set-Cookie") != "s=1" {
		t.Fatalf("subprotocol %q, response %+v", c.Subprotocol(), resp)
	}
	for _, m := range []string{"one", strings.Repeat("two", 20000)} {
		if err := c.WriteMessage(wsconn.Text, []byte(m)); err != nil {
			t.Fatal(err)
		}
		if _, p, err := c.ReadMessage(); err != nil || string(p) != m {
			t.Fatalf("echo %d bytes: %v", len(p), err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// A cross-origin request is refused through the ResponseWriter.
	d.Header = httphead.Header{{Name: "Origin", Value: "https://evil.example"}}
	_, resp, err = d.Dial(ctx, url)
	var he *wsconn.HandshakeError
	if !errors.As(err, &he) || resp == nil || resp.Code != http.StatusForbidden {
		t.Fatalf("cross origin: %v", err)
	}
}

func TestUpgradeRefusesPlainRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = wshttp.Upgrade(w, r, nil)
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired || resp.Header.Get("Sec-WebSocket-Version") != "13" {
		t.Fatalf("status %d %v", resp.StatusCode, resp.Header)
	}
}

// Check writes nothing: a handler decides on a valid handshake and either
// answers it with Accept or serves the request otherwise.
func TestCheckThenAccept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hs, err := wshttp.Check(w, r, &wsconn.ServerOptions{Subprotocols: []string{"echo"}})
		if err != nil || hs.Subprotocol == "" || r.Header.Get("X-Pass") == "" {
			http.Error(w, "elsewhere", http.StatusTeapot)
			return
		}
		c, err := wshttp.Accept(w, r, hs)
		if err != nil {
			return
		}
		typ, p, err := c.ReadMessage()
		if err == nil {
			_ = c.WriteMessage(typ, p)
		}
		_ = c.Close()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	for _, tc := range []struct {
		name   string
		header httphead.Header
		protos []string
		ok     bool
	}{
		{"accepted", httphead.Header{{Name: "X-Pass", Value: "1"}}, []string{"echo"}, true},
		{"undecided", nil, []string{"echo"}, false},
		{"no subprotocol", httphead.Header{{Name: "X-Pass", Value: "1"}}, []string{"other"}, false},
	} {
		d := &wsconn.Dialer{ClientOptions: wsconn.ClientOptions{Subprotocols: tc.protos, Header: tc.header}}
		c, resp, err := d.Dial(ctx, url)
		if !tc.ok {
			if err == nil || resp == nil || resp.Code != http.StatusTeapot {
				t.Fatalf("%s: %v %+v", tc.name, err, resp)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_ = c.WriteMessage(wsconn.Binary, []byte("x"))
		if _, p, err := c.ReadMessage(); err != nil || string(p) != "x" {
			t.Fatalf("%s: %q %v", tc.name, p, err)
		}
		_ = c.Close()
	}
	// A plain request is refused by Check with the status to answer with.
	rec := httptest.NewRecorder()
	if _, err := wshttp.Check(rec, httptest.NewRequest("GET", "/", nil), nil); err == nil || rec.Body.Len() != 0 {
		t.Fatalf("plain request: %v, wrote %q", err, rec.Body.String())
	}
}

// Accept on a ResponseWriter that cannot be hijacked writes nothing and
// returns a 500 handshake error.
func TestAcceptWithoutHijacker(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rec := httptest.NewRecorder()
	hs, err := wshttp.Check(rec, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = wshttp.Accept(rec, r, hs)
	var he *wsconn.HandshakeError
	if !errors.As(err, &he) || he.Status != http.StatusInternalServerError || rec.Body.Len() != 0 || rec.Flushed {
		t.Fatalf("%v, wrote %q", err, rec.Body.String())
	}
}

func TestRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/a?b=c", nil)
	r.Header.Set("X-A", "1")
	req := wshttp.Request(r)
	if req.Method != "GET" || req.Target != "/a?b=c" || req.Minor != 1 || req.Header[0] != (httphead.Field{Name: "Host", Value: "example.com"}) || req.Header.Get("x-a") != "1" {
		t.Fatalf("%+v", req)
	}
}

func TestDialerNeedsTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = wshttp.Serve(w, r, nil, func(c *wsconn.Conn) {
			typ, p, err := c.ReadMessage()
			if err == nil {
				_ = c.WriteMessage(typ, p)
			}
		})
	}))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	d := &wshttp.Dialer{}
	if _, _, err := d.Dial(ctx, url); !errors.Is(err, wshttp.ErrNoTransport) {
		t.Fatalf("err %v", err)
	}
	d.HTTP1 = &wsconn.Dialer{}
	c, resp, err := d.Dial(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Code != 101 {
		t.Fatalf("response %+v", resp)
	}
	_ = c.WriteMessage(wsconn.Text, []byte("h1"))
	if _, p, err := c.ReadMessage(); err != nil || string(p) != "h1" {
		t.Fatalf("%q %v", p, err)
	}
	_ = c.Close()
}

// Without GODEBUG=http2xconnect=1, an HTTP/2 request is refused as before.
func TestUpgradeOverHTTP2WithoutExtendedConnect(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = wshttp.Upgrade(w, r, nil)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusHTTPVersionNotSupported {
		t.Fatalf("%s %d", resp.Proto, resp.StatusCode)
	}
}
