package httpproxy_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/djylb/netx/httpproxy"
	"github.com/djylb/netx/internal/nettest"
)

// rawOrigin answers every request on a connection with a fixed response of
// size bytes, ending the connection after it when the request asks to,
// without the cost of an HTTP server, so that the benchmarks measure the
// proxy.
func rawOrigin(b *testing.B, size int) string {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(size) + "\r\n\r\n" + strings.Repeat("x", size))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				for {
					closing := false
					for {
						line, err := br.ReadSlice('\n')
						if err != nil {
							return
						}
						if len(line) <= 2 {
							break
						}
						closing = closing || strings.HasPrefix(strings.ToLower(string(line)), "connection: close")
					}
					if _, err := c.Write(resp); err != nil || closing {
						return
					}
				}
			}()
		}
	}()
	b.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// BenchmarkConnectSetup measures a CONNECT tunnel from dialing the proxy to
// the first echoed byte.
func BenchmarkConnectSetup(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	echo := nettest.ServeEcho(b, ln)
	addr := serve(b, &httpproxy.Server{})
	benchConnect(b, addr, echo)
}

func benchConnect(b *testing.B, proxy, target string) {
	req := []byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
	buf := make([]byte, 64)
	b.ReportAllocs()
	for b.Loop() {
		c, err := net.Dial("tcp", proxy)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.Write(req); err != nil {
			b.Fatal(err)
		}
		// "HTTP/1.1 200 Connection established\r\n\r\n", or a shorter reason.
		n, err := io.ReadAtLeast(c, buf, 16)
		if err != nil || !strings.Contains(string(buf[:n]), " 200 ") {
			b.Fatalf("reply %q, %v", buf[:n], err)
		}
		for !strings.HasSuffix(string(buf[:n]), "\r\n\r\n") {
			m, err := c.Read(buf[n:])
			if err != nil {
				b.Fatal(err)
			}
			n += m
		}
		if _, err := c.Write([]byte{1}); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			b.Fatal(err)
		}
		_ = c.Close()
	}
}

// BenchmarkForwardKeepAlive measures forwarded GET requests on one
// kept-alive client connection, over a kept target connection.
func BenchmarkForwardKeepAlive(b *testing.B) {
	o := rawOrigin(b, 2)
	addr := serve(b, &httpproxy.Server{})
	benchForward(b, addr, o, 2)
}

// BenchmarkForwardNoReuse is BenchmarkForwardKeepAlive with a new target
// connection for each request.
func BenchmarkForwardNoReuse(b *testing.B) {
	o := rawOrigin(b, 2)
	addr := serve(b, &httpproxy.Server{MaxIdleConnsPerKey: -1})
	benchForward(b, addr, o, 2)
}

// BenchmarkForwardBody measures the throughput of a forwarded 1 MiB
// response.
func BenchmarkForwardBody(b *testing.B) {
	const size = 1 << 20
	o := rawOrigin(b, size)
	addr := serve(b, &httpproxy.Server{})
	b.SetBytes(size)
	benchForward(b, addr, o, size)
}

func benchForward(b *testing.B, proxy, origin string, size int) {
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	br := bufio.NewReaderSize(c, 64<<10)
	req := []byte(fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n", origin, origin))
	body := make([]byte, size)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Write(req); err != nil {
			b.Fatal(err)
		}
		length := -1
		for {
			line, err := br.ReadSlice('\n')
			if err != nil {
				b.Fatal(err)
			}
			if len(line) <= 2 {
				break
			}
			if v, ok := strings.CutPrefix(string(line), "Content-Length: "); ok {
				length, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		if length != size {
			b.Fatalf("Content-Length %d", length)
		}
		if _, err := io.ReadFull(br, body); err != nil {
			b.Fatal(err)
		}
	}
}
