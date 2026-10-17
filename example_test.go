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
	"time"

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

// Serve one connection with an http.Server and stop it from outside:
// closing the listener would leave the connection being served alone, so
// Shutdown, which closes the server's connections once idle, or Close ends
// it.
func ExampleNewSingleConnListener_shutdown() {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(netx.NewSingleConnListener(server)) }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	fmt.Println(errors.Is(<-served, http.ErrServerClosed))
	// Output: true
}

// Forward a client to an echo backend.
func ExampleRelay() {
	client, front := net.Pipe()
	back, backend := net.Pipe()
	go func() { _, _ = io.Copy(backend, backend) }()

	done := make(chan struct{})
	go func() {
		up, down, err := netx.Relay(context.Background(), front, back)
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

// Count what a relay passes and end it from outside, as when an allowance
// runs out.
func ExampleWithRelayFlows() {
	client, front := net.Pipe()
	back, backend := net.Pipe()
	go func() { _, _ = io.Copy(backend, backend) }()

	var counted int64
	count := netx.RelayFlow{Done: func(n int64) error {
		counted += n
		return nil
	}}
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error)
	go func() {
		_, _, err := netx.Relay(ctx, front, back, netx.WithRelayFlows(count, netx.RelayFlow{}))
		done <- err
	}()

	_, _ = client.Write([]byte("ping"))
	_, _ = io.ReadFull(client, make([]byte, 4))
	cancel(errors.New("allowance used up"))
	err := <-done
	fmt.Println(err, counted)
	// Output:
	// allowance used up 4
}

// Close every connection of a group at once.
func ExampleConnGroup() {
	var user netx.ConnGroup
	a, b := net.Pipe()
	remove, _ := user.Add(a)
	defer remove()
	fmt.Println(user.Len())
	_ = user.CloseMembers(nil)
	_, err := b.Read(make([]byte, 1))
	fmt.Println(user.Len(), err)
	// Output:
	// 1
	// 0 EOF
}

// Hand a connection on after sniffing its first bytes.
func ExamplePeek() {
	client, server := net.Pipe()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\n"))
		_ = client.Close()
	}()

	c, head, _ := netx.PeekFull(context.Background(), server, 4)
	fmt.Printf("%q\n", head)
	all, _ := io.ReadAll(c) // the next reader sees the whole request
	fmt.Printf("%q\n", all)
	// Output:
	// "GET "
	// "GET / HTTP/1.1\r\n"
}

// Serve one goroutine per UDP peer, like a TCP server.
func ExamplePacketListener() {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	l := netx.NewPacketListener(pc, netx.WithPacketIdleTimeout(time.Minute))
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			buf := make([]byte, 1500)
			for {
				n, err := c.Read(buf) // one datagram from this peer
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n]) // echo it back
			}
		}()
	}
}
