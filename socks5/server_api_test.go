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
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/socks5"
)

// A caller serves BIND after Handshake, replying twice, the listening and
// then the peer's address, in the client's protocol version.
func TestServerHandshakeCustomCommand(t *testing.T) {
	for _, socks4 := range []bool{false, true} {
		name := "SOCKS5"
		if socks4 {
			name = "SOCKS4"
		}
		t.Run(name, func(t *testing.T) {
			s := &socks5.Server{SOCKS4: true}
			defer func() { _ = s.Close() }()
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			type result struct {
				req      *socks5.Request
				early    string
				err      error
				replyErr error
			}
			done := make(chan result, 1)
			go func() {
				defer func() { _ = server.Close() }()
				req, err := s.Handshake(context.Background(), server)
				if err != nil {
					done <- result{err: err}
					return
				}
				bound := netx.Addr{IP: netip.MustParseAddr("192.0.2.7"), Port: 4321}
				if err := req.Reply(socks5.ReplySucceeded, bound); err != nil {
					done <- result{err: err}
					return
				}
				buf := make([]byte, 5)
				if _, err = io.ReadFull(req.Conn, buf); err == nil {
					err = req.Reply(socks5.ReplySucceeded, netx.Addr{IP: netip.MustParseAddr("192.0.2.8"), Port: 8})
				}
				done <- result{req: req, early: string(buf), err: err, replyErr: req.Reply(socks5.ReplySucceeded, netx.Addr{})}
			}()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			dst := netx.Addr{IP: netip.MustParseAddr("198.51.100.1"), Port: 80}
			var bound netx.Addr
			var err error
			if socks4 {
				// The early bytes come in the same write as the request, so
				// the buffered read of the request takes them.
				var msg bytes.Buffer
				_ = socks5.WriteRequest4(&msg, socks5.CmdBind, dst, "ident")
				msg.WriteString("early")
				go func() { _, _ = client.Write(msg.Bytes()) }()
				bound, err = socks5.ReadReply4(client)
			} else {
				d := &socks5.Dialer{}
				if bound, err = d.Handshake(context.Background(), client, socks5.CmdBind, dst); err == nil {
					_, err = io.WriteString(client, "early")
				}
			}
			if err != nil || bound.String() != "192.0.2.7:4321" {
				t.Fatalf("reply = %v, %v; want 192.0.2.7:4321", bound, err)
			}
			read := socks5.ReadReply
			if socks4 {
				read = socks5.ReadReply4
			}
			if peer, err := read(client); err != nil || peer.String() != "192.0.2.8:8" {
				t.Fatalf("second reply = %v, %v; want 192.0.2.8:8", peer, err)
			}
			r := <-done
			if r.err != nil {
				t.Fatalf("server error = %v", r.err)
			}
			if r.req.Command != socks5.CmdBind || r.req.Dst != dst || r.early != "early" {
				t.Fatalf("request = %+v, early %q", r.req, r.early)
			}
			if !errors.Is(r.replyErr, socks5.ErrReplied) {
				t.Fatalf("third Reply() = %v, want ErrReplied", r.replyErr)
			}
			wantVersion, wantID := byte(socks5.Version5), ""
			if socks4 {
				wantVersion, wantID = socks5.Version4, "ident"
			}
			if r.req.Version != wantVersion || r.req.UserID4 != wantID || r.req.User != "" {
				t.Fatalf("Version, UserID4, User = %d, %q, %q; want %d, %q, empty", r.req.Version, r.req.UserID4, r.req.User, wantVersion, wantID)
			}
		})
	}
}

// ServeRequest refuses commands it does not serve, also UDP ASSOCIATE over
// SOCKS4, which has none, and closes the connection.
func TestServerServeRequestRefusesUnservedCommands(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5.Server{SOCKS4: true, UDPSocket: pc}
	defer func() { _ = s.Close() }()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	served := make(chan error, 1)
	go func() {
		req, err := s.Handshake(context.Background(), server)
		if err != nil {
			_ = server.Close()
			served <- err
			return
		}
		served <- s.ServeRequest(context.Background(), req)
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		_ = socks5.WriteRequest4(client, socks5.CmdUDPAssociate, netx.Addr{IP: netip.MustParseAddr("192.0.2.1")}, "")
	}()
	var replyErr *socks5.ReplyError
	if _, err := socks5.ReadReply4(client); !errors.As(err, &replyErr) || replyErr.Reply != socks5.Reply4Rejected {
		t.Fatalf("SOCKS4 UDP ASSOCIATE reply = %v, want rejected", err)
	}
	if err := <-served; !errors.As(err, &replyErr) || replyErr.Reply != socks5.ReplyCommandNotSupported {
		t.Fatalf("ServeRequest() = %v, want ReplyCommandNotSupported", err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("ServeRequest left the connection open")
	}
}

// Close ends a Handshake that the caller runs, and later calls fail at once.
func TestServerCloseEndsHandshakeCall(t *testing.T) {
	s := &socks5.Server{HandshakeTimeout: time.Minute}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	done := make(chan error, 1)
	go func() {
		_, err := s.Handshake(context.Background(), server)
		done <- err
	}()
	if _, err := client.Write([]byte{socks5.Version5}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Handshake() = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end Handshake")
	}
	if _, err := s.Handshake(context.Background(), server); !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("Handshake() after Close = %v, want ErrServerClosed", err)
	}
}

// The relay starts with the bytes that a SOCKS4 client sent along with its
// request.
func TestServerRelaysEarlyData(t *testing.T) {
	got := make(chan string, 1)
	addr := serve(t, &socks5.Server{
		SOCKS4: true,
		Dial: func(context.Context, *socks5.Request) (net.Conn, error) {
			a, b := net.Pipe()
			go func() {
				buf := make([]byte, 5)
				_, _ = io.ReadFull(b, buf)
				got <- string(buf)
				_, _ = io.Copy(io.Discard, b)
			}()
			return a, nil
		},
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var msg bytes.Buffer
	_ = socks5.WriteRequest4(&msg, socks5.CmdConnect, netx.Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 1}, "")
	msg.WriteString("early")
	if _, err := c.Write(msg.Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "early" {
			t.Fatalf("target read %q, want early", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the target got nothing")
	}
}

// Shutdown waits for the connections being served and counts them.
func TestServerShutdown(t *testing.T) {
	s := &socks5.Server{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve(ln) }()
	target := echoTCP(t)
	c, err := (&socks5.Dialer{ProxyAddr: ln.Addr().String()}).Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	assertEcho(t, c, "before")
	if n := s.ActiveConns(); n != 1 {
		t.Fatalf("ActiveConns() = %d, want 1", n)
	}

	shut := make(chan error, 1)
	go func() { shut <- s.Shutdown(context.Background()) }()
	if err := <-served; !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("Serve() = %v, want ErrServerClosed", err)
	}
	// The connection is still served while Shutdown waits.
	assertEcho(t, c, "during")
	select {
	case err := <-shut:
		t.Fatalf("Shutdown() = %v before the connection ended", err)
	default:
	}
	if err := s.ServeConn(context.Background(), nopConn{}); !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("ServeConn() during Shutdown = %v, want ErrServerClosed", err)
	}
	_ = c.Close()
	select {
	case err := <-shut:
		if err != nil {
			t.Fatalf("Shutdown() = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the connection ended")
	}
	if n := s.ActiveConns(); n != 0 {
		t.Fatalf("ActiveConns() after Shutdown = %d", n)
	}
}

// Shutdown whose context ends closes the remaining connections.
func TestServerShutdownContextEnds(t *testing.T) {
	s := &socks5.Server{}
	addr := serve(t, s)
	c, err := (&socks5.Dialer{ProxyAddr: addr}).Dial("tcp", echoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() = %v, want context.DeadlineExceeded", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Read() after Shutdown = %v, want the connection closed", err)
	}
}

// A UDP association opened by Dialer.ListenPacket exchanges datagrams, ends
// with Close, and serves as the outbound side of another server.
func TestDialerListenPacket(t *testing.T) {
	echo := udpEcho(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &socks5.Server{UDPSocket: pc}
	upAddr := serve(t, upstream)
	d := &socks5.Dialer{ProxyAddr: upAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u, err := d.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.RelayAddr(); got != pc.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("RelayAddr() = %v, want %v", got, pc.LocalAddr())
	}
	if got, src := exchangeUDPConn(t, u, netx.AddrFromNetAddr(echo), "direct"); got != "echo:direct" || src != netx.AddrFromNetAddr(echo) {
		t.Fatalf("reply = %q from %v", got, src)
	}
	if n := upstream.ActiveConns(); n != 1 {
		t.Fatalf("ActiveConns() = %d, want the control connection", n)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, _, err := u.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom() after Close = %v, want net.ErrClosed", err)
	}
	waitFor(t, "the association to end upstream", func() bool { return upstream.ActiveConns() == 0 })

	// A chained server relays its clients' datagrams through upstream.
	chained := serve(t, &socks5.Server{
		ListenUDP: socks5.ListenAssociationUDP,
		DialPacket: func(ctx context.Context, _ *socks5.Request) (socks5.PacketConn, error) {
			return d.ListenPacket(ctx)
		},
	})
	ctl, relay := associate(t, chained, netx.Addr{})
	defer func() { _ = ctl.Close() }()
	client := newUDPClient(t)
	var got string
	for range 10 {
		if got, _ = exchange(t, client, relay, echo, "chained"); got != "" {
			break
		}
	}
	if got != "echo:chained" {
		t.Fatalf("chained reply = %q", got)
	}
	_ = ctl.Close()
	waitFor(t, "the chained association to end upstream", func() bool { return upstream.ActiveConns() == 0 })
}

// The proxy ending the control connection closes the UDPConn, and replies
// from other senders than the relay are dropped.
func TestDialerListenPacketEndsWithControl(t *testing.T) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()
	end := make(chan struct{})
	addr := serveRaw(t, func(c net.Conn) {
		if _, err := socks5.ReadMethods(c); err != nil {
			return
		}
		_ = socks5.WriteMethod(c, socks5.MethodNoAuth)
		if cmd, _, err := socks5.ReadRequest(c); err != nil || cmd != socks5.CmdUDPAssociate {
			return
		}
		// An unspecified bound address stands for the proxy's.
		_ = socks5.WriteReply(c, socks5.ReplySucceeded, netx.Addr{Port: uint16(relay.LocalAddr().(*net.UDPAddr).Port)})
		<-end
	})
	u, err := (&socks5.Dialer{ProxyAddr: addr}).ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Close() }()
	if got, want := u.RelayAddr(), relay.LocalAddr().(*net.UDPAddr).AddrPort(); got != want {
		t.Fatalf("RelayAddr() = %v, want %v", got, want)
	}
	local := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(u.LocalAddr().(*net.UDPAddr).Port))
	foreign := newUDPClient(t)
	packet, _ := socks5.AppendDatagram(nil, netx.Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 1}, []byte("forged"))
	if _, err := foreign.WriteToUDPAddrPort(packet, local); err != nil {
		t.Fatal(err)
	}
	packet, _ = socks5.AppendDatagram(nil, netx.Addr{IP: netip.MustParseAddr("192.0.2.2"), Port: 2}, []byte("genuine"))
	if _, err := relay.WriteToUDPAddrPort(packet, local); err != nil {
		t.Fatal(err)
	}
	_ = u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, src, err := u.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "genuine" || src.Port != 2 {
		t.Fatalf("ReadFrom() = %q from %v, %v; want only the relay's datagram", buf[:n], src, err)
	}
	_ = u.SetReadDeadline(time.Time{})
	close(end)
	if _, _, err := u.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom() after the control connection ended = %v, want net.ErrClosed", err)
	}
}

func TestDialerListenPacketSOCKS4(t *testing.T) {
	if _, err := (&socks5.Dialer{ProxyAddr: "127.0.0.1:1", SOCKS4: true}).ListenPacket(context.Background()); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("SOCKS4 ListenPacket() = %v, want errors.ErrUnsupported", err)
	}
}

// exchangeUDPConn sends payload to dst through u until a reply comes, as a
// loopback datagram can be lost on a busy host.
func exchangeUDPConn(t *testing.T, u *socks5.UDPConn, dst netx.Addr, payload string) (string, netx.Addr) {
	t.Helper()
	buf := make([]byte, 2048)
	for range 10 {
		if _, err := u.WriteTo([]byte(payload), dst); err != nil {
			t.Fatal(err)
		}
		_ = u.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, src, err := u.ReadFrom(buf)
		if err == nil {
			_ = u.SetReadDeadline(time.Time{})
			return string(buf[:n]), src
		}
	}
	return "", netx.Addr{}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Dialer.Handshake returns the bound address of the reply, in either
// version, and leaves the connection open on a refusal.
func TestDialerHandshakeBoundAddr(t *testing.T) {
	bound := netx.Addr{IP: netip.MustParseAddr("192.0.2.9"), Port: 5000}
	for _, tt := range []struct {
		name  string
		d     *socks5.Dialer
		serve func(c net.Conn, rep socks5.Reply)
	}{
		{"SOCKS5", &socks5.Dialer{}, func(c net.Conn, rep socks5.Reply) {
			if _, err := socks5.ReadMethods(c); err != nil {
				return
			}
			_ = socks5.WriteMethod(c, socks5.MethodNoAuth)
			if _, _, err := socks5.ReadRequest(c); err == nil {
				_ = socks5.WriteReply(c, rep, bound)
			}
		}},
		{"SOCKS4", &socks5.Dialer{SOCKS4: true}, func(c net.Conn, rep socks5.Reply) {
			if _, _, _, err := socks5.ReadRequest4(c); err == nil {
				_ = socks5.WriteReply4(c, rep, bound)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, rep := range []socks5.Reply{socks5.ReplySucceeded, socks5.ReplyNotAllowed} {
				client, server := net.Pipe()
				go func() {
					defer func() { _ = server.Close() }()
					tt.serve(server, rep)
				}()
				got, err := tt.d.Handshake(context.Background(), client, socks5.CmdConnect, netx.Addr{Name: "example.com", Port: 80})
				var replyErr *socks5.ReplyError
				switch {
				case rep == socks5.ReplySucceeded && (err != nil || got != bound):
					t.Fatalf("Handshake() = %v, %v; want %v", got, err, bound)
				case rep != socks5.ReplySucceeded && !errors.As(err, &replyErr):
					t.Fatalf("Handshake() of a refusal = %v, %v; want a *ReplyError", got, err)
				}
				// The caller's on success, closed on failure.
				_, err = client.Read(make([]byte, 1))
				if closed := errors.Is(err, io.ErrClosedPipe); closed != (rep != socks5.ReplySucceeded) {
					t.Fatalf("after a reply %v the connection is closed: %v, want %v", rep, closed, rep != socks5.ReplySucceeded)
				}
				_ = client.Close()
			}
		})
	}
}

// backendAuth fails as an authenticator does whose own backend timed out.
type backendAuth struct{}

func (backendAuth) Method() socks5.Method { return socks5.MethodUserPass }

func (backendAuth) Authenticate(ctx context.Context, c net.Conn) (string, error) {
	if _, _, err := socks5.ReadUserPass(c); err != nil {
		return "", err
	}
	_ = socks5.WriteUserPassStatus(c, false)
	backend, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()
	<-backend.Done()
	return "", fmt.Errorf("backend: %w", backend.Err())
}

// A timeout of an authenticator's own backend is its error, not the
// handshake timeout.
func TestServerHandshakeKeepsAuthenticatorTimeout(t *testing.T) {
	s := &socks5.Server{Auth: []socks5.Authenticator{backendAuth{}}, HandshakeTimeout: time.Minute}
	defer func() { _ = s.Close() }()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	done := make(chan error, 1)
	go func() {
		_, err := s.Handshake(context.Background(), server)
		done <- err
	}()
	d := &socks5.Dialer{Username: "alice", Password: "secret"}
	if _, err := d.Handshake(context.Background(), client, socks5.CmdConnect, netx.Addr{Name: "example.com", Port: 80}); !errors.Is(err, socks5.ErrAuthFailed) {
		t.Fatalf("client Handshake() = %v, want ErrAuthFailed", err)
	}
	err := <-done
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || err.Error() != "backend: context deadline exceeded" {
		t.Fatalf("Handshake() = %v, want the backend's error", err)
	}
}

// gateListener hands out the connections sent on conn, also after Close,
// which it signals on closed, as an Accept racing with Close does, and
// reports itself closed once conn is closed.
type gateListener struct {
	conn      chan net.Conn
	accepting chan struct{} // closed by the first Accept
	closed    chan struct{}
	started   sync.Once
	closing   sync.Once
}

func (l *gateListener) Accept() (net.Conn, error) {
	l.started.Do(func() { close(l.accepting) })
	if c, ok := <-l.conn; ok {
		return c, nil
	}
	return nil, net.ErrClosed
}

func (l *gateListener) Close() error {
	l.closing.Do(func() { close(l.closed) })
	return nil
}

func (l *gateListener) Addr() net.Addr { return &net.TCPAddr{} }

// A connection accepted just before Shutdown closed the listener is refused
// without an OnError report.
func TestServerShutdownDoesNotReportRefusedConn(t *testing.T) {
	reported := make(chan error, 1)
	s := &socks5.Server{OnError: func(_ net.Conn, err error) { reported <- err }}
	// A connection being served keeps Shutdown draining.
	active, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	go func() { _ = s.ServeConn(context.Background(), active) }()
	waitFor(t, "the connection to be served", func() bool { return s.ActiveConns() == 1 })

	l := &gateListener{conn: make(chan net.Conn), accepting: make(chan struct{}), closed: make(chan struct{})}
	served := make(chan error, 1)
	go func() { served <- s.Serve(l) }()
	<-l.accepting
	shut := make(chan error, 1)
	go func() { shut <- s.Shutdown(context.Background()) }()
	<-l.closed

	late, latePeer := net.Pipe()
	defer func() { _ = latePeer.Close() }()
	l.conn <- late // the Accept that raced with Shutdown
	close(l.conn)
	if _, err := latePeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("the late connection was served")
	}
	select {
	case err := <-reported:
		t.Fatalf("OnError(%v) for a connection refused by Shutdown", err)
	case <-time.After(50 * time.Millisecond):
	}
	_ = peer.Close()
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	if err := <-served; !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("Serve() = %v", err)
	}
}

// Shutdown during a Close returns once that Close has finished.
func TestServerShutdownWaitsForClose(t *testing.T) {
	s := &socks5.Server{}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	slow := &slowCloseConn{Conn: server, closing: make(chan struct{}), release: make(chan struct{})}
	go func() { _ = s.ServeConn(context.Background(), slow) }()
	if _, err := client.Write([]byte{socks5.Version5}); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	<-slow.closing
	shut := make(chan error, 1)
	go func() { shut <- s.Shutdown(context.Background()) }()
	select {
	case err := <-shut:
		t.Fatalf("Shutdown() = %v while Close was still closing", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(slow.release)
	if err := <-closed; err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
}

// ServeConn's context ending ends the connection, also once it is relaying.
func TestServerServeConnContext(t *testing.T) {
	s := &socks5.Server{}
	defer func() { _ = s.Close() }()
	target := echoTCP(t)
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- s.ServeConn(ctx, server) }()
	dst, _ := netx.ParseAddr(target)
	if _, err := (&socks5.Dialer{}).Handshake(context.Background(), client, socks5.CmdConnect, dst); err != nil {
		t.Fatal(err)
	}
	assertEcho(t, client, "relayed")
	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn outlived its context")
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil || netx.IsTimeout(err) {
		t.Fatalf("Read() after the context ended = %v, want the connection closed", err)
	}
	if n := s.ActiveConns(); n != 0 {
		t.Fatalf("ActiveConns() = %d after ServeConn returned", n)
	}
}

// Handle serves a command of its own through Serve, and Shutdown waits for
// it.
func TestServerHandleCustomCommand(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	s := &socks5.Server{Handle: func(_ context.Context, req *socks5.Request) (bool, error) {
		if req.Command != socks5.CmdBind {
			return false, nil
		}
		if err := req.Reply(socks5.ReplySucceeded, netx.Addr{IP: netip.MustParseAddr("192.0.2.3"), Port: 3}); err != nil {
			return true, err
		}
		close(entered)
		<-release
		_, err := io.WriteString(req.Conn, "bound")
		return true, err
	}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve(ln) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	bound, err := (&socks5.Dialer{}).Handshake(context.Background(), c, socks5.CmdBind, netx.Addr{IP: netip.MustParseAddr("198.51.100.1"), Port: 1})
	if err != nil || bound.Port != 3 {
		t.Fatalf("BIND reply = %v, %v", bound, err)
	}
	<-entered
	if n := s.ActiveConns(); n != 1 {
		t.Fatalf("ActiveConns() = %d, want the handled connection", n)
	}
	shut := make(chan error, 1)
	go func() { shut <- s.Shutdown(context.Background()) }()
	<-served
	select {
	case err := <-shut:
		t.Fatalf("Shutdown() = %v while Handle was serving", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "bound" {
		t.Fatalf("read = %q, %v", buf, err)
	}
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the connection outlived Handle")
	}
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
}

// A Handle error that does not serve the request refuses it with the cause.
func TestServerHandleRefuses(t *testing.T) {
	reported := make(chan error, 1)
	addr := serve(t, &socks5.Server{
		Handle: func(context.Context, *socks5.Request) (bool, error) {
			return false, &socks5.ReplyError{Reply: socks5.ReplyHostUnreachable, Err: errors.New("no route")}
		},
		OnError: func(_ net.Conn, err error) { reported <- err },
	})
	c := handshake(t, addr)
	if err := socks5.WriteRequest(c, socks5.CmdConnect, netx.Addr{Name: "example.com", Port: 80}); err != nil {
		t.Fatal(err)
	}
	var replyErr *socks5.ReplyError
	if _, err := socks5.ReadReply(c); !errors.As(err, &replyErr) || replyErr.Reply != socks5.ReplyHostUnreachable {
		t.Fatalf("reply = %v, want host unreachable", err)
	}
	if err := <-reported; err.Error() != "socks5: host unreachable: no route" {
		t.Fatalf("OnError(%v), want the reply with its cause", err)
	}
}

// The refusals that the server returns carry the reply and its cause.
func TestServerRefusalKeepsCause(t *testing.T) {
	cause := errors.New("blocked by policy")
	reported := make(chan error, 2)
	addr := serve(t, &socks5.Server{
		Allow: func(_ context.Context, req *socks5.Request) error {
			if req.Dst.Port == 25 {
				return cause
			}
			return nil
		},
		OnError: func(_ net.Conn, err error) { reported <- err },
	})
	for _, tt := range []struct {
		cmd  socks5.Command
		code socks5.Reply
		port uint16
		want string
	}{
		{socks5.CmdConnect, socks5.ReplyNotAllowed, 25, "socks5: connection not allowed by ruleset: blocked by policy"},
		{socks5.CmdBind, socks5.ReplyCommandNotSupported, 80, "socks5: command not supported: bind"},
	} {
		c := handshake(t, addr)
		if err := socks5.WriteRequest(c, tt.cmd, netx.Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: tt.port}); err != nil {
			t.Fatal(err)
		}
		var replyErr *socks5.ReplyError
		if _, err := socks5.ReadReply(c); !errors.As(err, &replyErr) || replyErr.Reply != tt.code {
			t.Fatalf("reply = %v, want %v", err, tt.code)
		}
		err := <-reported
		if err.Error() != tt.want || !errors.As(err, &replyErr) || replyErr.Reply != tt.code {
			t.Fatalf("OnError(%v), want %q", err, tt.want)
		}
		if tt.port == 25 && !errors.Is(err, cause) {
			t.Fatalf("OnError(%v) lost the cause", err)
		}
	}
}

// RelayOptions adds options, such as flows per user, to the default relay.
func TestServerRelayOptions(t *testing.T) {
	var mu sync.Mutex
	sent := map[string]int64{}
	addr := serve(t, &socks5.Server{
		Auth: []socks5.Authenticator{socks5.Credentials(map[string]string{"alice": "a", "bob": "b"})},
		RelayOptions: func(req *socks5.Request) []netx.RelayOption {
			count := netx.RelayFlow{Done: func(n int64) error {
				mu.Lock()
				sent[req.User] += n
				mu.Unlock()
				return nil
			}}
			return []netx.RelayOption{netx.WithRelayFlows(&count, nil)}
		},
	})
	target := echoTCP(t)
	for _, user := range []string{"alice", "bob"} {
		d := &socks5.Dialer{ProxyAddr: addr, Username: user, Password: user[:1]}
		c, err := d.Dial("tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		assertEcho(t, c, "hello "+user)
		_ = c.Close()
	}
	waitFor(t, "the counts", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return sent["alice"] == int64(len("hello alice")) && sent["bob"] == int64(len("hello bob"))
	})
}

// Check gets the context and connection, and its error is told apart from
// rejected credentials.
func TestUserPassAuthCheck(t *testing.T) {
	backendDown := errors.New("account backend unreachable")
	for _, tt := range []struct {
		name    string
		ok      bool
		err     error
		wantErr error
	}{
		{"accepted", true, nil, nil},
		{"rejected", false, nil, socks5.ErrAuthFailed},
		{"backend failure", true, backendDown, backendDown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			type key struct{}
			ctx := context.WithValue(context.Background(), key{}, "v")
			auth := socks5.UserPassAuth{Check: func(ctx context.Context, c net.Conn, user, password string) (bool, error) {
				if ctx.Value(key{}) != "v" || c != server || user != "alice" || password != "secret" {
					return false, fmt.Errorf("unexpected Check arguments %v, %v, %q, %q", ctx, c, user, password)
				}
				return tt.ok, tt.err
			}}
			done := make(chan error, 1)
			go func() {
				_, err := auth.Authenticate(ctx, server)
				done <- err
			}()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			if err := socks5.WriteUserPass(client, "alice", "secret"); err != nil {
				t.Fatal(err)
			}
			statusErr := socks5.ReadUserPassStatus(client)
			if err := <-done; !errors.Is(err, tt.wantErr) || (tt.wantErr == nil) != (err == nil) {
				t.Fatalf("Authenticate() = %v, want %v", err, tt.wantErr)
			}
			if (statusErr == nil) != (tt.wantErr == nil) {
				t.Fatalf("status error = %v, want success %v", statusErr, tt.wantErr == nil)
			}
		})
	}
}

// AsNetPacketConn serves code that expects a net.PacketConn.
func TestUDPConnAsNetPacketConn(t *testing.T) {
	echo := udpEcho(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u, err := (&socks5.Dialer{ProxyAddr: serve(t, &socks5.Server{UDPSocket: pc})}).ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	npc := u.AsNetPacketConn()
	defer func() { _ = npc.Close() }()
	if _, err := npc.WriteTo([]byte("x"), &net.UnixAddr{Name: "/sock", Net: "unix"}); !errors.Is(err, socks5.ErrInvalidAddr) {
		t.Fatalf("WriteTo(unix address) = %v, want ErrInvalidAddr", err)
	}
	buf := make([]byte, 64)
	for _, dst := range []net.Addr{echo, netx.AddrFromNetAddr(echo)} {
		var n int
		var src net.Addr
		for range 10 {
			if _, err := npc.WriteTo([]byte("net"), dst); err != nil {
				t.Fatal(err)
			}
			_ = npc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n, src, err = npc.ReadFrom(buf); err == nil {
				break
			}
		}
		if err != nil || string(buf[:n]) != "echo:net" {
			t.Fatalf("ReadFrom() = %q, %v", buf[:n], err)
		}
		if ua, ok := src.(*net.UDPAddr); !ok || ua.AddrPort() != echo.AddrPort() {
			t.Fatalf("source = %#v, want the *net.UDPAddr %v", src, echo)
		}
	}
	if got := netx.AddrFromNetAddr(netx.Addr{Name: "example.com", Port: 53}); got.Name != "example.com" || got.Port != 53 {
		t.Fatalf("AddrFromNetAddr(Addr) = %v", got)
	}
}

// A request gets one reply, BIND two, and a failure reply is the last.
func TestRequestReplyLimit(t *testing.T) {
	for _, tt := range []struct {
		cmd   socks5.Command
		codes []socks5.Reply
		want  int // replies written
	}{
		{socks5.CmdConnect, []socks5.Reply{socks5.ReplySucceeded, socks5.ReplySucceeded}, 1},
		{socks5.CmdBind, []socks5.Reply{socks5.ReplySucceeded, socks5.ReplySucceeded, socks5.ReplySucceeded}, 2},
		{socks5.CmdBind, []socks5.Reply{socks5.ReplyGeneralFailure, socks5.ReplySucceeded}, 1},
	} {
		var wire bytes.Buffer
		req := &socks5.Request{Version: socks5.Version5, Command: tt.cmd, Conn: bufConn{&wire}}
		n := 0
		for i, code := range tt.codes {
			err := req.Reply(code, netx.Addr{})
			if (i < tt.want) != (err == nil) || err != nil && !errors.Is(err, socks5.ErrReplied) {
				t.Fatalf("%v reply %d = %v", tt.cmd, i, err)
			}
			if err == nil {
				n++
			}
		}
		if wire.Len() != n*10 {
			t.Fatalf("%v wrote %d bytes for %d replies", tt.cmd, wire.Len(), n)
		}
	}
}

// bufConn is a net.Conn that writes to a buffer.
type bufConn struct{ w io.Writer }

func (c bufConn) Read([]byte) (int, error)       { return 0, io.EOF }
func (c bufConn) Write(b []byte) (int, error)    { return c.w.Write(b) }
func (bufConn) Close() error                     { return nil }
func (bufConn) LocalAddr() net.Addr              { return nil }
func (bufConn) RemoteAddr() net.Addr             { return nil }
func (bufConn) SetDeadline(time.Time) error      { return nil }
func (bufConn) SetReadDeadline(time.Time) error  { return nil }
func (bufConn) SetWriteDeadline(time.Time) error { return nil }

// A Handle that replies but reports the request unhandled has still served
// it: the built-in CONNECT does not dial.
func TestServerHandleRepliedIsHandled(t *testing.T) {
	dialed := make(chan struct{}, 1)
	reported := make(chan error, 1)
	addr := serve(t, &socks5.Server{
		Handle: func(_ context.Context, req *socks5.Request) (bool, error) {
			return false, req.Reply(socks5.ReplyNotAllowed, netx.Addr{})
		},
		Dial: func(context.Context, *socks5.Request) (net.Conn, error) {
			dialed <- struct{}{}
			return nil, errors.New("dialed")
		},
		OnError: func(_ net.Conn, err error) { reported <- err },
	})
	c := handshake(t, addr)
	if err := socks5.WriteRequest(c, socks5.CmdConnect, netx.Addr{Name: "example.com", Port: 80}); err != nil {
		t.Fatal(err)
	}
	var replyErr *socks5.ReplyError
	if _, err := socks5.ReadReply(c); !errors.As(err, &replyErr) || replyErr.Reply != socks5.ReplyNotAllowed {
		t.Fatalf("reply = %v, want Handle's", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection outlived Handle")
	}
	select {
	case <-dialed:
		t.Fatal("CONNECT ran after Handle replied")
	case err := <-reported:
		t.Fatalf("OnError(%v), want nothing", err)
	case <-time.After(50 * time.Millisecond):
	}
}

// stepListener reports each call of Accept on entered and hands out the
// connections sent on conn until it is closed.
type stepListener struct {
	conn    chan net.Conn
	entered chan struct{}
	closed  chan struct{}
	closing sync.Once
}

func (l *stepListener) Accept() (net.Conn, error) {
	l.entered <- struct{}{}
	select {
	case c := <-l.conn:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *stepListener) Close() error {
	l.closing.Do(func() { close(l.closed) })
	return nil
}

func (l *stepListener) Addr() net.Addr { return &net.TCPAddr{} }

// Serve tracks a connection before serving it, so that Shutdown cannot miss
// one that has just been accepted.
func TestServeTracksAcceptedBeforeServing(t *testing.T) {
	s := &socks5.Server{}
	l := &stepListener{conn: make(chan net.Conn), entered: make(chan struct{}, 2), closed: make(chan struct{})}
	served := make(chan error, 1)
	go func() { served <- s.Serve(l) }()
	<-l.entered
	c, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	l.conn <- c
	<-l.entered // the next Accept: the connection has been handed on
	if n := s.ActiveConns(); n != 1 {
		t.Fatalf("ActiveConns() = %d right after Accept, want 1", n)
	}
	shut := make(chan error, 1)
	go func() { shut <- s.Shutdown(context.Background()) }()
	<-served
	select {
	case err := <-shut:
		t.Fatalf("Shutdown() = %v with a connection being served", err)
	case <-time.After(50 * time.Millisecond):
	}
	_ = peer.Close()
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
}

// Credentials accepts exactly the accounts it was given.
func TestCredentials(t *testing.T) {
	check := socks5.Credentials(map[string]string{"alice": "secret", "empty": ""}).Check
	for _, tt := range []struct {
		user, password string
		want           bool
	}{
		{"alice", "secret", true},
		{"alice", "secre", false},
		{"alice", "secret!", false},
		{"alice", "", false},
		{"empty", "", true},
		{"empty", "x", false},
		{"bob", "", false},
		{"bob", "secret", false},
	} {
		if ok, err := check(context.Background(), nil, tt.user, tt.password); ok != tt.want || err != nil {
			t.Errorf("Check(%q, %q) = %v, %v; want %v", tt.user, tt.password, ok, err, tt.want)
		}
	}
}

// AddrFromNetAddr returns the zero Addr for nil pointers of any type.
func TestAddrFromNilPointers(t *testing.T) {
	for _, a := range []net.Addr{(*netx.Addr)(nil), (*net.IPAddr)(nil), (*net.UnixAddr)(nil), (*net.TCPAddr)(nil)} {
		if got := netx.AddrFromNetAddr(a); got != (netx.Addr{}) {
			t.Errorf("AddrFromNetAddr(%T nil) = %v", a, got)
		}
	}
	u := &socks5.UDPConn{}
	if _, err := u.AsNetPacketConn().WriteTo(nil, (*netx.Addr)(nil)); !errors.Is(err, socks5.ErrInvalidAddr) {
		t.Fatalf("WriteTo(nil *Addr) = %v, want ErrInvalidAddr", err)
	}
}
