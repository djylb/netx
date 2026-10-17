package proxyproto_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"

	"github.com/djylb/netx"
	"github.com/djylb/netx/proxyproto"
)

func ExampleNewHeader() {
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51234}
	target := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443}
	for _, v := range []proxyproto.Version{proxyproto.V1, proxyproto.V2} {
		h, err := proxyproto.NewHeader(v, client, target)
		if err != nil {
			fmt.Println(err)
			return
		}
		var b bytes.Buffer
		if _, err := h.WriteTo(&b); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%d %q\n", b.Len(), b.Bytes()[:12])
	}
	// Output:
	// 47 "PROXY TCP4 1"
	// 28 "\r\n\r\n\x00\r\nQUIT\n"
}

func ExampleDecode() {
	data := []byte("PROXY TCP4 203.0.113.7 198.51.100.1 40000 443\r\nGET / HTTP/1.1\r\n")
	h, n, err := proxyproto.Decode(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(h.Source, h.Destination)
	fmt.Printf("%q\n", data[n:n+5])
	// Output:
	// 203.0.113.7:40000 198.51.100.1:443
	// "GET /"
}

// Serve HTTP behind load balancers in 10.0.0.0/8 that send PROXY protocol
// headers, and to other peers directly.
func ExampleListener() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	pl := &proxyproto.Listener{
		Listener:  ln,
		PolicyFor: proxyproto.TrustPrefixes(netip.MustParsePrefix("10.0.0.0/8")),
	}
	_ = http.Serve(pl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "client:", r.RemoteAddr) // from the header
	}))
}

// Serve UDP behind a proxy that sends a PROXY protocol header in the first
// datagram of each flow, as some UDP proxies do with version 1 TCP4 and TCP6
// tokens.
func ExampleListener_datagram() {
	pc, err := net.ListenPacket("udp", ":19132")
	if err != nil {
		fmt.Println(err)
		return
	}
	pl := &proxyproto.Listener{Listener: netx.NewPacketListener(pc), Config: proxyproto.Config{Datagram: true}}
	defer func() { _ = pl.Close() }()
	for {
		c, err := pl.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			buf := make([]byte, 1500)
			for {
				n, err := c.Read(buf) // one datagram, header removed
				if err != nil {
					return
				}
				// c.RemoteAddr() is the client's *net.UDPAddr from the header.
				_, _ = c.Write(buf[:n])
			}
		}()
	}
}

// Forward clients to a backend that expects a PROXY protocol header telling
// it who each client is.
func ExampleHeader_WriteTo() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = client.Close() }()
			backend, err := net.Dial("tcp", "backend.example:8080")
			if err != nil {
				return
			}
			defer func() { _ = backend.Close() }()
			h, err := proxyproto.HeaderFromConn(proxyproto.V2, client)
			if err != nil {
				return
			}
			if _, err := h.WriteTo(backend); err != nil {
				return
			}
			_, _, _ = netx.Relay(context.Background(), client, backend)
		}()
	}
}

// Read the header of a connection accepted elsewhere.
func ExampleNewConn() {
	server, client := net.Pipe()
	go func() {
		h, _ := proxyproto.NewHeader(proxyproto.V1,
			&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40000},
			&net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443})
		_, _ = h.WriteTo(client)
		_, _ = client.Write([]byte("hello"))
		_ = client.Close()
	}()
	c := proxyproto.NewConn(server, proxyproto.Config{})
	defer func() { _ = c.Close() }()
	buf := make([]byte, 5)
	n, err := c.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(c.RemoteAddr(), string(buf[:n]))
	// Output:
	// 203.0.113.7:40000 hello
}

// Serve HTTPS behind TLS-passthrough load balancers that send PROXY protocol
// headers with the host name the client asked for, and reach the header from
// the *tls.Conn of each request.
func ExampleHeaderOf() {
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		fmt.Println(err)
		return
	}
	config := &tls.Config{} // with the server's certificates
	srv := &http.Server{
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if h, err := proxyproto.HeaderOf(c); err == nil && h != nil {
				if v, ok := h.TLV(proxyproto.TLVAuthority); ok {
					fmt.Printf("%s asked the load balancer for %s\n", h.Source, v)
				}
			}
			return ctx
		},
	}
	_ = srv.Serve(tls.NewListener(&proxyproto.Listener{Listener: ln}, config))
}
