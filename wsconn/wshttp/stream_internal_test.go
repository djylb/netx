package wshttp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
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
		r, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "http://x/", io.NopCloser(strings.NewReader("")))
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
	synctest.Test(t, func(t *testing.T) {
		pr, pw := io.Pipe()
		defer func() { _ = pr.Close() }()
		resets := 0
		c := &clientConn{pw: pw, body: io.NopCloser(strings.NewReader("")), cancel: func() { resets++ }}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		old := c.rd
		_ = c.SetReadDeadline(time.Now().Add(time.Hour))
		time.Sleep(2 * time.Second)
		c.expire(&c.rd, old)
		if resets != 0 || c.isExpired() {
			t.Fatal("superseded read deadline expired")
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if resets != 1 || !c.isExpired() {
			t.Fatal("replacement deadline did not expire")
		}
	})
}
