package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestChanListenerDeliverAndAccept(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	l := NewChanListener(addr, 2)
	defer func() { _ = l.Close() }()
	if l.Addr() != addr {
		t.Fatalf("Addr() = %v, want %v", l.Addr(), addr)
	}

	first, second := &countedCloseConn{}, &countedCloseConn{}
	for _, c := range []net.Conn{first, second} {
		if err := l.Deliver(context.Background(), c); err != nil {
			t.Fatalf("Deliver() error = %v", err)
		}
	}
	for i, want := range []net.Conn{first, second} {
		got, err := l.Accept()
		if err != nil || got != want {
			t.Fatalf("Accept() #%d = %v, %v; want %v", i, got, err, want)
		}
	}
	if err := l.Deliver(context.Background(), nil); err == nil {
		t.Fatal("Deliver(nil) error = nil")
	}
}

func TestChanListenerDefaultAddr(t *testing.T) {
	l := NewChanListener(nil, 0)
	defer func() { _ = l.Close() }()
	if got := l.Addr(); got == nil || got.Network() != "pipe" || got.String() != "pipe" {
		t.Fatalf("Addr() = %v, want pipe", got)
	}
}

func TestChanListenerDeliverWaitsForContext(t *testing.T) {
	l := NewChanListener(nil, 0)
	defer func() { _ = l.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	c := &countedCloseConn{}
	if err := l.Deliver(ctx, c); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Deliver() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if c.Calls() != 1 {
		t.Fatalf("Close calls = %d, want 1", c.Calls())
	}
}

func TestChanListenerUnbufferedHandoff(t *testing.T) {
	l := NewChanListener(nil, 0)
	defer func() { _ = l.Close() }()
	c := &countedCloseConn{}
	errc := make(chan error, 1)
	go func() { errc <- l.Deliver(context.Background(), c) }()
	got, err := l.Accept()
	if err != nil || got != c {
		t.Fatalf("Accept() = %v, %v", got, err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
}

func TestChanListenerCloseClosesQueuedAndUnblocks(t *testing.T) {
	l := NewChanListener(nil, 4)
	queued := &countedCloseConn{}
	if err := l.Deliver(context.Background(), queued); err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if queued.Calls() != 1 {
		t.Fatalf("queued conn Close calls = %d, want 1", queued.Calls())
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() after Close error = %v", err)
	}
	late := &countedCloseConn{}
	if err := l.Deliver(context.Background(), late); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Deliver() after Close error = %v", err)
	}
	if late.Calls() != 1 {
		t.Fatalf("late conn Close calls = %d, want 1", late.Calls())
	}
	if _, err := l.Dial(context.Background(), nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Dial() after Close error = %v", err)
	}

	blocked := NewChanListener(nil, 0)
	acceptErr := make(chan error, 1)
	go func() {
		_, err := blocked.Accept()
		acceptErr <- err
	}()
	deliverErr := make(chan error, 1)
	waiting := &countedCloseConn{}
	unbuffered := NewChanListener(nil, 0)
	go func() { deliverErr <- unbuffered.Deliver(context.Background(), waiting) }()
	time.Sleep(10 * time.Millisecond)
	_ = blocked.Close()
	_ = unbuffered.Close()
	if err := <-acceptErr; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("blocked Accept() error = %v", err)
	}
	if err := <-deliverErr; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("blocked Deliver() error = %v", err)
	}
	if waiting.Calls() != 1 {
		t.Fatalf("blocked conn Close calls = %d, want 1", waiting.Calls())
	}
}

// Every delivered connection must end up accepted or closed, even when Close
// races with Deliver.
func TestChanListenerCloseRaceLeaksNothing(t *testing.T) {
	for range 200 {
		l := NewChanListener(nil, 8)
		var wg sync.WaitGroup
		conns := make([]*countedCloseConn, 16)
		var accepted atomic.Int32
		for i := range conns {
			conns[i] = &countedCloseConn{}
			wg.Go(func() { _ = l.Deliver(context.Background(), conns[i]) })
		}
		wg.Go(func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				_ = c.Close()
			}
		})
		_ = l.Close()
		wg.Wait()
		for i, c := range conns {
			if c.Calls() != 1 {
				t.Fatalf("conn %d Close calls = %d, want 1", i, c.Calls())
			}
		}
	}
}

func TestChanListenerDial(t *testing.T) {
	lAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 80}
	rAddr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 5555}
	l := NewChanListener(lAddr, 1)
	defer func() { _ = l.Close() }()

	client, err := l.Dial(context.Background(), rAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = client.Close() }()
	server, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer func() { _ = server.Close() }()

	if server.LocalAddr() != lAddr || server.RemoteAddr() != rAddr {
		t.Fatalf("server addrs = %v -> %v", server.LocalAddr(), server.RemoteAddr())
	}
	if client.LocalAddr() != rAddr || client.RemoteAddr() != lAddr {
		t.Fatalf("client addrs = %v -> %v", client.LocalAddr(), client.RemoteAddr())
	}
	go func() { _, _ = client.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("server read = %q, %v", buf, err)
	}

	anonymous, err := l.Dial(context.Background(), nil)
	if err != nil {
		t.Fatalf("Dial(nil) error = %v", err)
	}
	defer func() { _ = anonymous.Close() }()
	if got := anonymous.LocalAddr(); got == nil || got.String() != "pipe" {
		t.Fatalf("Dial(nil) LocalAddr() = %v, want pipe", got)
	}
}

func TestChanListenerDialTimeoutClosesClient(t *testing.T) {
	l := NewChanListener(nil, 0)
	defer func() { _ = l.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if c, err := l.Dial(ctx, nil); !errors.Is(err, context.DeadlineExceeded) || c != nil {
		t.Fatalf("Dial() = %v, %v; want nil, %v", c, err, context.DeadlineExceeded)
	}
}

func TestSingleConnListenerEndsWhenConnCloses(t *testing.T) {
	base := &countedCloseConn{}
	l := NewSingleConnListener(base)
	if l.Addr() != base.LocalAddr() {
		t.Fatalf("Addr() = %v, want %v", l.Addr(), base.LocalAddr())
	}
	c, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if RawConnOf(c) != base {
		t.Fatalf("RawConnOf(accepted) = %v, want base", RawConnOf(c))
	}

	next := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		next <- err
	}()
	select {
	case err := <-next:
		t.Fatalf("second Accept() returned early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-next; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Accept() error = %v, want %v", err, net.ErrClosed)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("listener Close() error = %v", err)
	}
	if base.Calls() != 1 {
		t.Fatalf("base Close calls = %d, want 1", base.Calls())
	}
}

func TestSingleConnListenerCloseBeforeAccept(t *testing.T) {
	base := &countedCloseConn{}
	l := NewSingleConnListener(base)
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if base.Calls() != 1 {
		t.Fatalf("base Close calls = %d, want 1", base.Calls())
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error = %v, want %v", err, net.ErrClosed)
	}
	if got := NewSingleConnListener(nil).Addr(); got == nil || got.String() != "pipe" {
		t.Fatalf("Addr() of nil conn listener = %v", got)
	}
}

func TestSingleConnListenerServesHTTP(t *testing.T) {
	client, server := net.Pipe()
	l := NewSingleConnListener(server)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()

	tr := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
	resp, err := (&http.Client{Transport: tr}).Get("http://single/")
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	tr.CloseIdleConnections()

	select {
	case err := <-served:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve() error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after the connection closed")
	}
}
