package netx_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/djylb/netx"
)

// Serve HTTP on connections that never touch a socket.
func ExampleChanListener() {
	l := netx.NewChanListener(nil, 16)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "hello from ", r.RemoteAddr)
	})}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return l.Dial(ctx, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4000})
		},
	}}
	resp, err := client.Get("http://in-memory/")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	// Output: hello from 192.0.2.1:4000
}

// Run an http.Server on one connection; Serve returns once it is closed.
func ExampleNewSingleConnListener() {
	client, server := net.Pipe()
	served := make(chan error, 1)
	go func() {
		served <- http.Serve(netx.NewSingleConnListener(server), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, "ok")
		}))
	}()

	req, _ := http.NewRequest(http.MethodGet, "http://single/", nil)
	req.Close = true // the server closes the connection after the response
	go func() { _ = req.Write(client) }()
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	fmt.Println(errors.Is(<-served, net.ErrClosed))
	// Output:
	// ok
	// true
}

// Forward a client to an echo backend.
func ExampleRelay() {
	client, front := net.Pipe()
	back, backend := net.Pipe()
	go func() { _, _ = io.Copy(backend, backend) }()

	done := make(chan struct{})
	go func() {
		up, down, err := netx.Relay(front, back)
		fmt.Println(up, down, err)
		close(done)
	}()

	_, _ = client.Write([]byte("ping"))
	buf := make([]byte, 4)
	_, _ = io.ReadFull(client, buf)
	fmt.Println(string(buf))
	_ = client.Close()
	<-done
	// Output:
	// ping
	// 4 4 <nil>
}

// Hand a connection on after sniffing its first bytes.
func ExampleNewPrefixConn() {
	client, server := net.Pipe()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\n"))
		_ = client.Close()
	}()

	head := make([]byte, 4)
	_, _ = io.ReadFull(server, head)
	c := netx.NewPrefixConn(server, head) // the next reader sees the whole request
	all, _ := io.ReadAll(c)
	fmt.Printf("%q\n", all)
	// Output: "GET / HTTP/1.1\r\n"
}
