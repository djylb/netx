package wshttp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/wsconn"
)

type fakeRW struct{ h http.Header }

func (f *fakeRW) Header() http.Header         { return f.h }
func (f *fakeRW) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeRW) WriteHeader(int)             {}
func (f *fakeRW) Flush()                      {}

// A stream whose context is already done when acceptStream registers its
// AfterFunc: the callback runs at once, on its own goroutine, and must
// find sc.stop set; the connection is closed.
func TestAcceptStreamCanceledContext(t *testing.T) {
	hreq := &httphead.Request{Method: "CONNECT", Target: "/", Proto: "HTTP/2.0", Header: httphead.Header{
		{Name: ":protocol", Value: "websocket"},
		{Name: "Sec-WebSocket-Version", Value: "13"},
	}}
	hs, err := wsconn.CheckRequest(hreq, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 20000 {
		r, _ := http.NewRequestWithContext(ctx, "CONNECT", "http://x/", io.NopCloser(strings.NewReader("")))
		r.ProtoMajor = 2
		c, err := acceptStream(&fakeRW{h: http.Header{}}, r, hs)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-Done(c):
		case <-time.After(5 * time.Second):
			t.Fatal("connection of a done context not closed")
		}
	}
}

// Replacing a deadline before it expires keeps the stream.
func TestClientDeadlineReplaced(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	var resets int
	var mu sync.Mutex
	c := &clientConn{pw: pw, body: io.NopCloser(strings.NewReader("")), cancel: func() {
		mu.Lock()
		resets++
		mu.Unlock()
	}}
	for range 100 {
		_ = c.SetDeadline(time.Now().Add(5 * time.Millisecond))
		_ = c.SetDeadline(time.Now().Add(time.Hour))
	}
	_ = c.SetDeadline(time.Time{})
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if resets != 0 || c.isExpired() {
		t.Fatalf("%d resets", resets)
	}
}
