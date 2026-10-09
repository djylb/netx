package proxyproto_test

import (
	"fmt"
	"net"
	"net/http"

	"github.com/djylb/netx/proxyproto"
)

func ExampleHeaderFromAddrs() {
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51234}
	target := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443}
	fmt.Printf("%q\n", proxyproto.HeaderFromAddrs(client, target, proxyproto.V1))
	fmt.Println(len(proxyproto.HeaderFromAddrs(client, target, proxyproto.V2)))
	// Output:
	// "PROXY TCP4 192.0.2.10 198.51.100.20 51234 443\r\n"
	// 28
}

func ExampleParse() {
	data := []byte("PROXY TCP4 203.0.113.7 198.51.100.1 40000 443\r\nGET / HTTP/1.1\r\n")
	h, n, err := proxyproto.Parse(data)
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

// Serve HTTP behind a load balancer that sends PROXY protocol headers.
func ExampleListener() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	pl := &proxyproto.Listener{Listener: ln}
	_ = http.Serve(pl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "client:", r.RemoteAddr) // from the header
	}))
}
