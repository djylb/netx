package socks5_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/djylb/netx/socks5"
)

// checkNoAuth is a NoAuth authenticator that decides by the connection
// itself, as an IP allowlist or a TLS client certificate check does.
type checkNoAuth struct {
	user string
	err  error
}

func (checkNoAuth) Method() socks5.Method { return socks5.MethodNoAuth }

func (a checkNoAuth) Authenticate(context.Context, net.Conn) (string, error) {
	return a.user, a.err
}

func TestServerNoAuthAuthenticatorDecides(t *testing.T) {
	target := echoTCP(t)
	deny := serve(t, &socks5.Server{SOCKS4: true, Auth: []socks5.Authenticator{checkNoAuth{err: errors.New("not allowed")}}})
	dst, _ := socks5.ParseAddr(target)

	// A NoAuth method, an empty list and an unknown method all reach it.
	for _, methods := range [][]byte{{byte(socks5.MethodNoAuth)}, {}, {byte(socks5.MethodGSSAPI)}} {
		c, err := net.Dial("tcp", deny)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(append([]byte{socks5.Version, byte(len(methods))}, methods...))
		if m, err := socks5.ReadMethod(c); err != nil || m != socks5.MethodNoAuth {
			t.Fatalf("methods %v: selected %v, %v", methods, m, err)
		}
		_ = socks5.WriteRequest(c, socks5.CmdConnect, dst)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := socks5.ReadReply(c); err == nil {
			t.Fatalf("methods %v: CONNECT succeeded past the authenticator", methods)
		}
		_ = c.Close()
	}

	// Username/password alone: any credentials, then the authenticator.
	c, err := net.Dial("tcp", deny)
	if err != nil {
		t.Fatal(err)
	}
	_ = socks5.WriteMethods(c, socks5.MethodUserPass)
	if m, err := socks5.ReadMethod(c); err != nil || m != socks5.MethodUserPass {
		t.Fatalf("user/pass: selected %v, %v", m, err)
	}
	_ = socks5.WriteUserPass(c, "any", "thing")
	if err := socks5.ReadUserPassStatus(c); !errors.Is(err, socks5.ErrAuthFailed) {
		t.Fatalf("user/pass status = %v, want %v", err, socks5.ErrAuthFailed)
	}
	_ = c.Close()

	// SOCKS4 has no authentication of its own.
	_, err = (&socks5.Dialer{ProxyAddr: deny, SOCKS4: true}).Dial("tcp", target)
	var replyErr *socks5.ReplyError
	if !errors.As(err, &replyErr) || replyErr.Reply != socks5.Reply4Rejected {
		t.Fatalf("SOCKS4 error = %v, want %v", err, socks5.Reply4Rejected)
	}

	// An accepting authenticator names SOCKS4 clients.
	users := make(chan string, 1)
	allow := serve(t, &socks5.Server{
		SOCKS4: true,
		Auth:   []socks5.Authenticator{checkNoAuth{user: "trusted-net"}},
		Allow: func(_ context.Context, req *socks5.Request) error {
			users <- req.User
			return nil
		},
	})
	c, err = (&socks5.Dialer{ProxyAddr: allow, SOCKS4: true}).Dial("tcp", target)
	if err != nil {
		t.Fatalf("SOCKS4 Dial() error = %v", err)
	}
	_ = c.Close()
	if user := <-users; user != "trusted-net" {
		t.Fatalf("Request.User = %q, want the authenticator's identity", user)
	}
}

// TestServerUDPIgnoresForeignAnnouncement checks that a client cannot claim
// the datagrams of another IP address by announcing it.
func TestServerUDPIgnoresForeignAnnouncement(t *testing.T) {
	victimUDP, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer func() { _ = victimUDP.Close() }()
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	handlers := make(chan string, 1)
	s := &socks5.Server{
		PacketConn: pc,
		AllowPacket: func(req *socks5.Request, _ socks5.Addr) bool {
			handlers <- req.Conn.RemoteAddr().String()
			return false
		},
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	probe, err := net.Dial("tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Skip("listener is not dual-stack:", err)
	}
	_ = probe.Close()

	victim, _ := associate(t, net.JoinHostPort("::1", strconv.Itoa(port)), socks5.Addr{})
	attacker, _ := associate(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), socks5.AddrFromNetAddr(victimUDP.LocalAddr()))
	defer func() { _ = attacker.Close() }()

	packet, _ := socks5.AppendDatagram(nil, socks5.Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 9}, []byte("victim"))
	relay := &net.UDPAddr{IP: net.IPv6loopback, Port: pc.LocalAddr().(*net.UDPAddr).Port}
	if _, err := victimUDP.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-handlers:
		if got != victim.LocalAddr().String() {
			t.Fatalf("datagram handled by the association of %s, want the victim's %s", got, victim.LocalAddr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the victim's datagram was not routed")
	}
}

// TestServerCloseEndsOutlivingAssociation checks that Close ends an
// association kept by UDPOutlivesControl and its own socket.
func TestServerCloseEndsOutlivingAssociation(t *testing.T) {
	echo := udpEcho(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5.Server{
		UDPOutlivesControl: true,
		ListenUDP: func(context.Context, *socks5.Request) (net.PacketConn, error) {
			return net.ListenPacket("udp", "127.0.0.1:0")
		},
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	ctl, relay := associate(t, ln.Addr().String(), socks5.Addr{})
	client := newUDPClient(t)
	if got, _ := exchange(t, client, relay, echo, "before"); got != "echo:before" {
		t.Fatalf("reply = %q", got)
	}
	_ = ctl.Close()
	_ = s.Close()
	<-done
	time.Sleep(50 * time.Millisecond)
	if got, _ := exchange(t, client, relay, echo, "after"); got != "" {
		t.Fatalf("reply %q after Close", got)
	}
}

// noAddrConn has no remote address, like some multiplexed streams.
type noAddrConn struct{ net.Conn }

func (noAddrConn) RemoteAddr() net.Addr { return nil }

func TestServerUDPWithoutRemoteAddr(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5.Server{PacketConn: pc}
	defer func() { _ = s.Close() }()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() { _ = s.ServeConn(noAddrConn{server}) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = socks5.WriteMethods(client, socks5.MethodNoAuth)
	if _, err := socks5.ReadMethod(client); err != nil {
		t.Fatal(err)
	}
	_ = socks5.WriteRequest(client, socks5.CmdUDPAssociate, socks5.Addr{})
	if _, err := socks5.ReadReply(client); err != nil {
		t.Fatalf("UDP ASSOCIATE reply error = %v", err)
	}
}

func TestReplyForTranslatesSOCKS4(t *testing.T) {
	for in, want := range map[socks5.Reply]socks5.Reply{
		socks5.ReplyConnectionRefused: socks5.ReplyConnectionRefused,
		socks5.Reply4Rejected:         socks5.ReplyGeneralFailure,
		socks5.Reply4IdentdMismatch:   socks5.ReplyNotAllowed,
		socks5.Reply(200):             socks5.ReplyGeneralFailure,
	} {
		if got := socks5.ReplyFor(&socks5.ReplyError{Reply: in}); got != want {
			t.Errorf("ReplyFor(%v) = %v, want %v", in, got, want)
		}
	}
	if got := socks5.ReplyFor(io.EOF); got != socks5.ReplyGeneralFailure {
		t.Errorf("ReplyFor(EOF) = %v", got)
	}
}
