package socks5_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/socks5"
)

// A client that announces the control connection's own address and a port
// gets the datagrams of that source alone: another port of the same IP
// address cannot take the association first.
func TestServerUDPExactAnnouncementTakesOnlyItsSource(t *testing.T) {
	echo := udpEcho(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, &socks5.Server{UDPSocket: pc})
	victim, attacker := newUDPClient(t), newUDPClient(t)
	ctl, relay := associate(t, addr, socks5.AddrFromNetAddr(victim.LocalAddr()))
	defer func() { _ = ctl.Close() }()

	if got, _ := exchange(t, attacker, relay, echo, "attacker"); got != "" {
		t.Fatalf("another port of the victim's IP got %q through the victim's association", got)
	}
	if got, _ := exchange(t, victim, relay, echo, "victim"); got != "echo:victim" {
		t.Fatalf("the announced source got %q, want %q", got, "echo:victim")
	}
}

// Once the shared UDP socket is closed by its owner, a UDP ASSOCIATE fails
// rather than being told to send to a dead socket, and associations waiting
// for their first datagram end.
func TestServerUDPStoppedSharedSocket(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, &socks5.Server{UDPSocket: pc})
	waiting, _ := associate(t, addr, socks5.Addr{})
	defer func() { _ = waiting.Close() }()
	_ = pc.Close()

	_ = waiting.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := waiting.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("waiting association's control connection Read() = %v, want it closed", err)
	}
	for deadline := time.Now().Add(2 * time.Second); ; {
		c := handshake(t, addr)
		if err := socks5.WriteRequest(c, socks5.CmdUDPAssociate, socks5.Addr{}); err != nil {
			t.Fatal(err)
		}
		_, err := socks5.ReadReply(c)
		_ = c.Close()
		var replyErr *socks5.ReplyError
		if errors.As(err, &replyErr) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP ASSOCIATE on a closed socket = %v, want a failure reply", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// countingConn counts the reads of a connection until its first write.
type countingConn struct {
	net.Conn
	reads        atomic.Int32
	beforeWrite  atomic.Int32
	wroteAlready atomic.Bool
}

func (c *countingConn) Read(b []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(b)
}

func (c *countingConn) Write(b []byte) (int, error) {
	if !c.wroteAlready.Swap(true) {
		c.beforeWrite.Store(c.reads.Load())
	}
	return c.Conn.Write(b)
}

// A SOCKS4 request is not read one byte per read of the connection, and
// bytes the client sends right after it reach the target.
func TestServerSOCKS4BufferedRequestKeepsEarlyData(t *testing.T) {
	target := echoTCP(t)
	client, server := net.Pipe()
	counted := &countingConn{Conn: server}
	var allowed atomic.Value
	s := &socks5.Server{SOCKS4: true, Allow: func(_ context.Context, req *socks5.Request) error {
		allowed.Store(req.Conn)
		return nil
	}}
	served := make(chan struct{})
	go func() { _ = s.ServeConn(context.Background(), counted); close(served) }()
	defer func() { <-served }()

	var req bytes.Buffer
	ap := netip.MustParseAddrPort(target)
	if err := socks5.WriteRequest4(&req, socks5.CmdConnect, socks5.Addr{IP: ap.Addr(), Port: ap.Port()}, "a-fairly-long-user-id"); err != nil {
		t.Fatal(err)
	}
	req.WriteString("early")
	go func() { _, _ = client.Write(req.Bytes()) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := socks5.ReadReply4(client); err != nil {
		t.Fatalf("SOCKS4 reply error = %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "early" {
		t.Fatalf("echo of the early data = %q, %v", buf, err)
	}
	// req.Conn replays the early bytes over the served connection.
	if got, _ := allowed.Load().(net.Conn); netx.InnermostConn(got) != net.Conn(counted) {
		t.Errorf("Allow saw req.Conn %T, want one wrapping the served connection", got)
	}
	if n := counted.beforeWrite.Load(); n > 3 {
		t.Errorf("the request took %d reads of the connection, want at most 3", n)
	}
	_ = client.Close()
}

// The connections that Close ends are not reported to OnError.
func TestServeDoesNotReportConnectionsEndedByClose(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reported []error
	s := &socks5.Server{UDPSocket: pc, OnError: func(_ net.Conn, err error) {
		mu.Lock()
		reported = append(reported, err)
		mu.Unlock()
	}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = s.Serve(ln); close(done) }()
	ctl, _ := associate(t, ln.Addr().String(), socks5.Addr{})
	defer func() { _ = ctl.Close() }()
	c, err := (&socks5.Dialer{ProxyAddr: ln.Addr().String()}).Dial("tcp", echoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	assertEcho(t, c, "live")
	_ = s.Close()
	<-done
	_ = ctl.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = ctl.Read(make([]byte, 1))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(make([]byte, 1))
	time.Sleep(100 * time.Millisecond) // let the serving goroutines report
	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 0 {
		t.Fatalf("OnError got %v for connections that Close ended", reported)
	}
}

// Connections that Close ends inside a hook or a dial are not reported
// either, whatever error the hook returns for its cancelled context.
func TestServeDoesNotReportHooksEndedByClose(t *testing.T) {
	var mu sync.Mutex
	var reported []error
	entered := make(chan struct{}, 2)
	s := &socks5.Server{
		Allow: func(ctx context.Context, req *socks5.Request) error {
			if req.Dst.Port != 1 {
				return nil
			}
			entered <- struct{}{}
			<-ctx.Done()
			return fmt.Errorf("allow: %v", ctx.Err()) // not wrapped
		},
		Dial: func(ctx context.Context, req *socks5.Request) (net.Conn, error) {
			entered <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		},
		OnError: func(_ net.Conn, err error) {
			mu.Lock()
			reported = append(reported, err)
			mu.Unlock()
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = s.Serve(ln); close(done) }()
	for _, port := range []string{"1", "2"} {
		go func() {
			c, err := (&socks5.Dialer{ProxyAddr: ln.Addr().String()}).Dial("tcp", "192.0.2.1:"+port)
			if err == nil {
				_ = c.Close()
			}
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the hooks were not called")
		}
	}
	_ = s.Close()
	<-done
	time.Sleep(100 * time.Millisecond) // let the serving goroutines report
	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 0 {
		t.Fatalf("OnError got %v for connections that Close ended", reported)
	}
}
