package socks5_test

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"

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

func ExampleParseDatagram() {
	packet, _ := socks5.AppendDatagram(nil, socks5.Addr{IP: netip.MustParseAddr("198.51.100.7"), Port: 53}, []byte("query"))
	dst, payload, err := socks5.ParseDatagram(packet)
	fmt.Println(dst, string(payload), err)
	// Output: 198.51.100.7:53 query <nil>
}

// Decode an address embedded in a larger message.
func ExampleDecodeAddr() {
	msg := []byte{3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g', 0x01, 0xbb, 'm', 'o', 'r', 'e'}
	addr, n, err := socks5.DecodeAddr(msg)
	fmt.Println(addr, string(msg[n:]), err)
	// Output: example.org:443 more <nil>
}
