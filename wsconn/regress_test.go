package wsconn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/httphead"
)

// timeoutConn fails writes with a timeout, writing nothing, while fail is
// set.
type timeoutConn struct {
	memConn
	fail atomic.Bool
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	if c.fail.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	return c.memConn.Write(p)
}

// A write that fails after the first frame of a message went out fails the
// connection's writes: another message's frame would break the fragments.
func TestFailedFragmentFailsWrites(t *testing.T) {
	tc := &timeoutConn{memConn: memConn{r: bytes.NewReader(nil)}}
	c := NewConn(tc, nil, false, nil)
	w, _ := c.NextWriter(Binary)
	if _, err := w.Write(make([]byte, 40000)); err != nil {
		t.Fatal(err)
	}
	tc.fail.Store(true)
	if _, err := w.Write(make([]byte, 40000)); err == nil {
		t.Fatal("write succeeded")
	}
	_ = w.Close()
	tc.fail.Store(false)
	if err := c.WriteMessage(Binary, []byte("x")); err == nil {
		t.Fatal("a message went out after a broken one")
	}
	// A timeout before any frame of a message leaves the connection usable.
	tc2 := &timeoutConn{memConn: memConn{r: bytes.NewReader(nil)}}
	c = NewConn(tc2, nil, false, nil)
	tc2.fail.Store(true)
	if err := c.WriteMessage(Binary, []byte("x")); err == nil {
		t.Fatal("write succeeded")
	}
	tc2.fail.Store(false)
	if err := c.WriteMessage(Binary, []byte("y")); err != nil {
		t.Fatal(err)
	}
}

// With a negative close timeout, Close does not block on a peer that does
// not read.
func TestCloseNegativeTimeoutBounded(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := NewConn(a, nil, false, &Options{CloseTimeout: -50 * time.Millisecond})
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked")
	}
}

// Close bounds the whole closing handshake by one close timeout, also on a
// client whose server answers slowly.
func TestCloseWithinOneTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	const timeout = 300 * time.Millisecond
	c := NewConn(a, nil, true, &Options{CloseTimeout: timeout})
	go func() {
		// Read the close frame slowly, answer late, never close.
		time.Sleep(timeout / 2)
		buf := make([]byte, 64)
		_, _ = b.Read(buf)
		time.Sleep(timeout / 3)
		_, _ = b.Write(frame(finBit|opClose, false, []byte{0x03, 0xe8}))
	}()
	start := time.Now()
	_ = c.Close()
	if d := time.Since(start); d > timeout+200*time.Millisecond {
		t.Fatalf("Close took %v with a timeout of %v", d, timeout)
	}
}

func TestCheckOriginStatus(t *testing.T) {
	req := &httphead.Request{Method: "GET", Minor: 1, Header: httphead.Header{
		{Name: "Upgrade", Value: "websocket"}, {Name: "Connection", Value: "Upgrade"},
		{Name: "Sec-WebSocket-Version", Value: "13"}, {Name: "Sec-WebSocket-Key", Value: "dGhlIHNhbXBsZSBub25jZQ=="},
		{Name: "Sec-WebSocket-Extensions", Value: "permessage-deflate; server_max_window_bits=10, permessage-deflate; server_max_window_bits=15"},
	}}
	for _, status := range []int{0, 101, 302, 600} {
		_, err := CheckRequest(req, &ServerOptions{CheckOrigin: func(*httphead.Request) error {
			return &HandshakeError{Status: status, Msg: "no"}
		}})
		var he *HandshakeError
		if !errors.As(err, &he) || he.Status != 403 {
			t.Fatalf("status %d: %v", status, err)
		}
	}
	hs, err := CheckRequest(req, &ServerOptions{Options: Options{Compression: &Compression{}}})
	if err != nil || !hs.Compressed {
		t.Fatal(err)
	}
	resp, _ := hs.AppendResponse(nil)
	if !strings.Contains(string(resp), "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=15\r\n") {
		t.Fatalf("response %q", resp)
	}
}

func TestDeflateParams(t *testing.T) {
	for _, bad := range [][]string{
		{"server_max_window_bits=010"}, {`server_max_window_bits="10`}, {"server_max_window_bits=16"},
		{"server_max_window_bits"}, {"client_no_context_takeover=1"}, {"x=1"},
		{"server_no_context_takeover", "server_no_context_takeover"},
	} {
		if _, err := parseDeflateParams(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	p, err := parseDeflateParams([]string{` server_max_window_bits="12" `, "client_max_window_bits"})
	if err != nil || p.serverMaxBits != 12 || p.clientMaxBits != -1 {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestClientRefusesSpaceInURL(t *testing.T) {
	_, _, err := Client(context.Background(), &memConn{r: strings.NewReader("")}, "ws://h/p?a b", nil)
	if err == nil || !strings.Contains(err.Error(), "space") {
		t.Fatalf("err %v", err)
	}
}

func TestExtendedConnectHandshake(t *testing.T) {
	req := &httphead.Request{Method: "CONNECT", Target: "/chat", Proto: "HTTP/2.0", Header: httphead.Header{
		{Name: "Host", Value: "h"}, {Name: ":protocol", Value: "websocket"},
		{Name: "Sec-WebSocket-Version", Value: "13"}, {Name: "Sec-WebSocket-Protocol", Value: "a, b"},
		{Name: "Sec-WebSocket-Extensions", Value: "permessage-deflate"},
	}}
	so := &ServerOptions{Subprotocols: []string{"b"}, Options: Options{Compression: &Compression{Threshold: -1}}}
	hs, err := CheckRequest(req, so)
	if err != nil || !hs.ExtendedConnect || hs.Subprotocol != "b" || !hs.Compressed {
		t.Fatalf("%+v %v", hs, err)
	}
	if _, err := hs.AppendResponse(nil); err == nil {
		t.Fatal("101 response for HTTP/2")
	}
	co := &ClientOptions{Subprotocols: []string{"a", "b"}, Options: Options{Compression: &Compression{}}}
	fields, err := co.ExtendedConnectHeader()
	if err != nil || fields.Get("Sec-WebSocket-Version") != "13" || fields.Get("Sec-WebSocket-Protocol") != "a, b" || fields.Has("Sec-WebSocket-Key") {
		t.Fatalf("%v %v", fields, err)
	}
	a, b := net.Pipe()
	srv := hs.NewConn(a, nil)
	cli, err := ExtendedConnectClient(b, &httphead.Response{Code: 200, Header: hs.ResponseHeader()}, co)
	if err != nil || cli.Subprotocol() != "b" || !cli.Compressed() {
		t.Fatalf("client %v", err)
	}
	go func() {
		_, p, err := srv.ReadMessage()
		if err == nil {
			_ = srv.WriteMessage(Text, p)
		}
	}()
	_ = cli.WriteMessage(Text, []byte("over a stream"))
	if _, p, err := cli.ReadMessage(); err != nil || string(p) != "over a stream" {
		t.Fatalf("%q %v", p, err)
	}
	_ = a.Close()
	_ = b.Close()

	// Refusals.
	for _, tt := range []struct {
		field, value string
		status       int
	}{{":protocol", "chat", 400}, {"Sec-WebSocket-Version", "12", 426}} {
		bad := *req
		bad.Header = slices.Clone(req.Header)
		bad.Header.Set(tt.field, tt.value)
		var he *HandshakeError
		if _, err := CheckRequest(&bad, nil); !errors.As(err, &he) || he.Status != tt.status {
			t.Fatalf("%s: %v", tt.field, err)
		}
	}
	if _, err := ExtendedConnectClient(&memConn{r: strings.NewReader("")}, &httphead.Response{Code: 403}, nil); err == nil {
		t.Fatal("403 accepted")
	}
}
