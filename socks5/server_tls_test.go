package socks5_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/netx/socks5"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestServerOverTLS serves SOCKS5, SOCKS4a and UDP ASSOCIATE behind TLS: the
// server takes a TLS listener and the Dialer a TLS Forward dialer.
func TestServerOverTLS(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	s := &socks5.Server{SOCKS4: true, PacketConn: udp}
	done := make(chan error, 1)
	go func() { done <- s.Serve(tlsLn) }()
	t.Cleanup(func() {
		_ = s.Close()
		<-done
	})
	addr := ln.Addr().String()
	tlsDialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
	target := echoTCP(t)

	for _, socks4 := range []bool{false, true} {
		c, err := (&socks5.Dialer{ProxyAddr: addr, SOCKS4: socks4, Forward: tlsDialer}).Dial("tcp", target)
		if err != nil {
			t.Fatalf("SOCKS4 %v over TLS: Dial() error = %v", socks4, err)
		}
		if _, ok := c.(*tls.Conn); !ok {
			t.Fatalf("connection = %T, want *tls.Conn", c)
		}
		assertEcho(t, c, "tls")
		_ = c.Close()
	}

	// UDP ASSOCIATE: the control connection is TLS, the datagrams plain UDP.
	ctrl, err := tlsDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ctrl.Close() }()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := socks5.WriteMethods(ctrl, socks5.MethodNoAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := socks5.ReadMethod(ctrl); err != nil {
		t.Fatal(err)
	}
	if err := socks5.WriteRequest(ctrl, socks5.CmdUDPAssociate, socks5.AddrFromNetAddr(client.LocalAddr())); err != nil {
		t.Fatal(err)
	}
	bound, err := socks5.ReadReply(ctrl)
	if err != nil {
		t.Fatal(err)
	}
	peer := echoUDPOnce(t)
	packet, _ := socks5.AppendDatagram(nil, socks5.AddrFromNetAddr(peer.LocalAddr()), []byte("dgram"))
	if _, err := client.WriteToUDPAddrPort(packet, netip.AddrPortFrom(bound.IP, bound.Port)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, payload, err := socks5.ParseDatagram(buf[:n]); err != nil || string(payload) != "dgram" {
		t.Fatalf("UDP reply = %q, %v", payload, err)
	}
}

// echoUDPOnce answers the first datagram it receives.
func echoUDPOnce(t *testing.T) *net.UDPConn {
	t.Helper()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	go func() {
		buf := make([]byte, 512)
		n, from, err := peer.ReadFromUDPAddrPort(buf)
		if err == nil {
			_, _ = peer.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return peer
}
