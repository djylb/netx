package socks5_test

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/socks5"
)

// serveRaw accepts connections on a loopback listener and runs handle on each.
func serveRaw(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// recordingDialer dials with a net.Dialer and records the addresses.
type recordingDialer struct {
	mu    sync.Mutex
	addrs []string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestDialerForwardAndHostNames(t *testing.T) {
	requests := make(chan socks5.Addr, 1)
	addr := serveRaw(t, func(c net.Conn) {
		if _, err := socks5.ReadMethods(c); err != nil {
			return
		}
		_ = socks5.WriteMethod(c, socks5.MethodNoAuth)
		_, dst, err := socks5.ReadRequest(c)
		if err != nil {
			return
		}
		requests <- dst
		_ = socks5.WriteReply(c, socks5.ReplySucceeded, socks5.Addr{})
		_, _ = io.Copy(c, c)
	})
	forward := &recordingDialer{}
	c, err := (&socks5.Dialer{ProxyAddr: addr, Forward: forward}).DialContext(context.Background(), "tcp4", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer func() { _ = c.Close() }()
	if got := <-requests; got != (socks5.Addr{Name: "example.com", Port: 443}) {
		t.Fatalf("request = %v, want example.com:443 by name", got)
	}
	if len(forward.addrs) != 1 || forward.addrs[0] != addr {
		t.Fatalf("forward dialed %v, want the proxy %s", forward.addrs, addr)
	}
	assertEcho(t, c, "ping")
}

func TestDialerErrors(t *testing.T) {
	d := &socks5.Dialer{ProxyAddr: "127.0.0.1:1"}
	if _, err := d.Dial("udp", "example.com:53"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("udp error = %v, want %v", err, errors.ErrUnsupported)
	}
	if _, err := d.Dial("tcp", "example.com"); !errors.Is(err, socks5.ErrInvalidAddr) {
		t.Errorf("target without port error = %v, want %v", err, socks5.ErrInvalidAddr)
	}

	// The server selects username/password although the client offered none.
	addr := serveRaw(t, func(c net.Conn) {
		if _, err := socks5.ReadMethods(c); err == nil {
			_ = socks5.WriteMethod(c, socks5.MethodUserPass)
		}
		_, _ = io.Copy(io.Discard, c)
	})
	if _, err := (&socks5.Dialer{ProxyAddr: addr}).Dial("tcp", "example.com:80"); err == nil {
		t.Error("unoffered method accepted")
	}
}

func TestDialerEndsStalledHandshake(t *testing.T) {
	addr := serveRaw(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	d := &socks5.Dialer{ProxyAddr: addr}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err := d.DialContext(ctx, "tcp", "example.com:80")
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v, want %v", err, context.DeadlineExceeded)
	}

	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := d.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v, want %v", err, context.Canceled)
	}
}

func TestServerOnError(t *testing.T) {
	errs := make(chan error, 1)
	addr := serve(t, &socks5.Server{
		OnError: func(c net.Conn, err error) {
			if c == nil {
				err = errors.New("nil connection")
			}
			errs <- err
		},
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte{9, 1, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		if !errors.Is(err, socks5.ErrVersion) {
			t.Fatalf("OnError() error = %v, want %v", err, socks5.ErrVersion)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnError was not called")
	}
}

func TestDialerSOCKS4(t *testing.T) {
	target := echoTCP(t)
	_, port, _ := net.SplitHostPort(target)
	requests := make(chan socks5.Addr, 4)
	addr := serve(t, &socks5.Server{
		SOCKS4: true,
		Dial: func(ctx context.Context, req *socks5.Request) (net.Conn, error) {
			if req.Version != 4 {
				t.Errorf("Request.Version = %d, want 4", req.Version)
			}
			requests <- req.Dst
			return (&net.Dialer{}).DialContext(ctx, "tcp", target)
		},
	})
	d := &socks5.Dialer{ProxyAddr: addr, SOCKS4: true, Username: "alice"}
	for _, dst := range []string{target, "echo.example:" + port} {
		c, err := d.Dial("tcp", dst)
		if err != nil {
			t.Fatalf("Dial(%s) error = %v", dst, err)
		}
		if got := <-requests; got.String() != dst {
			t.Fatalf("server received %v, want %s", got, dst)
		}
		assertEcho(t, c, "v4")
		_ = c.Close()
	}

	if _, err := d.Dial("tcp", "[2001:db8::1]:80"); !errors.Is(err, socks5.ErrAddrType) {
		t.Fatalf("IPv6 target error = %v, want %v", err, socks5.ErrAddrType)
	}

	// A SOCKS4 failure arrives as a *ReplyError with the SOCKS4 code.
	refusing := serve(t, &socks5.Server{
		SOCKS4: true,
		Dial: func(context.Context, *socks5.Request) (net.Conn, error) {
			return nil, errors.New("refused")
		},
	})
	_, err := (&socks5.Dialer{ProxyAddr: refusing, SOCKS4: true}).Dial("tcp", target)
	var replyErr *socks5.ReplyError
	if !errors.As(err, &replyErr) || replyErr.Reply != socks5.Reply4Rejected {
		t.Fatalf("rejected error = %v, want %v", err, socks5.Reply4Rejected)
	}
}

func TestDialerResolver(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("no name resolution on " + runtime.GOOS)
	}
	target := echoTCP(t)
	requests := make(chan socks5.Addr, 2)
	addr := serve(t, &socks5.Server{
		SOCKS4: true,
		Dial: func(ctx context.Context, req *socks5.Request) (net.Conn, error) {
			requests <- req.Dst
			return (&net.Dialer{}).DialContext(ctx, "tcp", target)
		},
	})
	for _, socks4 := range []bool{true, false} {
		d := &socks5.Dialer{ProxyAddr: addr, SOCKS4: socks4, Resolver: net.DefaultResolver}
		c, err := d.Dial("tcp", "localhost:80")
		if err != nil {
			t.Fatalf("SOCKS4 %v: Dial() error = %v", socks4, err)
		}
		_ = c.Close()
		got := <-requests
		if !got.IP.IsLoopback() || got.Name != "" || got.Port != 80 || socks4 && !got.IP.Is4() {
			t.Fatalf("SOCKS4 %v: server received %v, want a resolved loopback address", socks4, got)
		}
	}
}
