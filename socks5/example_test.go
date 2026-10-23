package socks5_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/socks5"
)

// A CONNECT handshake without authentication, client and server side.
func Example() {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		methods, err := socks5.ReadMethods(server)
		if err != nil || !slices.Contains(methods, socks5.MethodNoAuth) {
			_ = socks5.WriteMethod(server, socks5.MethodNoAcceptable)
			return
		}
		_ = socks5.WriteMethod(server, socks5.MethodNoAuth)
		cmd, dst, err := socks5.ReadRequest(server)
		if err != nil {
			return
		}
		fmt.Println("server:", cmd, dst)
		_ = socks5.WriteReply(server, socks5.ReplySucceeded, socks5.Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 40000})
	}()

	if err := socks5.WriteMethods(client, socks5.MethodNoAuth); err != nil {
		log.Fatal(err)
	}
	if _, err := socks5.ReadMethod(client); err != nil {
		log.Fatal(err)
	}
	dst, _ := socks5.ParseAddr("example.com:443")
	if err := socks5.WriteRequest(client, socks5.CmdConnect, dst); err != nil {
		log.Fatal(err)
	}
	bound, err := socks5.ReadReply(client)
	fmt.Println("client: bound", bound, err)
	// Output:
	// server: connect example.com:443
	// client: bound 192.0.2.1:40000 <nil>
}

func ExampleDecodeDatagram() {
	packet, _ := socks5.AppendDatagram(nil, socks5.Addr{IP: netip.MustParseAddr("198.51.100.7"), Port: 53}, []byte("query"))
	dst, n, err := socks5.DecodeDatagram(packet)
	fmt.Println(dst, string(packet[n:]), err)
	// Output: 198.51.100.7:53 query <nil>
}

// Decode an address embedded in a larger message.
func ExampleDecodeAddr() {
	msg := []byte{3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g', 0x01, 0xbb, 'm', 'o', 'r', 'e'}
	addr, n, err := socks5.DecodeAddr(msg)
	fmt.Println(addr, string(msg[n:]), err)
	// Output: example.org:443 more <nil>
}

// A SOCKS5 server with accounts, a destination policy and UDP on a fixed
// port.
func ExampleServer() {
	udp, err := net.ListenPacket("udp", ":1080")
	if err != nil {
		log.Fatal(err)
	}
	s := &socks5.Server{
		Auth: []socks5.Authenticator{
			socks5.Credentials(map[string]string{"alice": "secret"}),
		},
		Allow: func(_ context.Context, req *socks5.Request) error {
			if req.Dst.Port == 25 {
				return errors.New("no mail") // answered with ReplyNotAllowed
			}
			return nil
		},
		UDPSocket: udp, // every association uses this port
	}
	ln, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

// Count the bytes each user sends, end idle connections, and report a
// bound address of our choosing in CONNECT replies.
func ExampleServer_hooks() {
	var mu sync.Mutex
	sent := map[string]int64{}
	s := &socks5.Server{
		Auth: []socks5.Authenticator{
			socks5.Credentials(map[string]string{"alice": "secret", "bob": "hunter2"}),
		},
		Dial: func(ctx context.Context, req *socks5.Request) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", req.Dst.String())
			if err != nil {
				return nil, err
			}
			public := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1080}
			return netx.NewAddrOverrideConn(c, public, nil), nil
		},
		RelayOptions: func(req *socks5.Request) []netx.RelayOption {
			count := netx.RelayFlow{Done: func(n int64) error {
				mu.Lock()
				sent[req.User] += n
				mu.Unlock()
				return nil
			}}
			return []netx.RelayOption{
				netx.WithRelayFlows(&count, nil),
				netx.WithRelayIdleTimeout(5 * time.Minute),
			}
		},
	}
	ln, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

// Dial through a SOCKS5 proxy that resolves the host name.
func ExampleDialer() {
	d := &socks5.Dialer{
		ProxyAddr: "127.0.0.1:1080",
		Username:  "alice",
		Password:  "secret",
		Forward:   &net.Dialer{Timeout: 10 * time.Second},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
}

// Serve SOCKS5, SOCKS4 and SOCKS4a over TLS. Clients reach it with a TLS
// dialer as the Dialer's Forward, or the socks5+tls and socks4a+tls schemes
// of the proxydial package.
func ExampleServer_tls() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":1443")
	if err != nil {
		log.Fatal(err)
	}
	s := &socks5.Server{SOCKS4: true}
	log.Fatal(s.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})))
}

// Dial through a SOCKS4 proxy, resolving the host name locally for servers
// without the SOCKS4a extension.
func ExampleDialer_socks4() {
	d := &socks5.Dialer{
		ProxyAddr: "127.0.0.1:1080",
		SOCKS4:    true,
		Username:  "alice", // the SOCKS4 user ID
		Resolver:  net.DefaultResolver,
	}
	conn, err := d.Dial("tcp", "example.com:80")
	if err != nil {
		log.Println(err)
		return
	}
	defer func() { _ = conn.Close() }()
}
