package netx

import (
	"io"
	"net"
	"testing"
	"time"
)

// benchTCPPair returns a connected loopback TCP pair for benchmarks.
func benchTCPPair(b *testing.B) (net.Conn, net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	server := <-accepted
	b.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func BenchmarkTimeoutConnWriteTCP(b *testing.B) {
	client, server := benchTCPPair(b)
	go func() { _, _ = io.Copy(io.Discard, server) }()
	conn := NewTimeoutConn(client, 30*time.Second)
	msg := make([]byte, 512)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := conn.Write(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkFramedReadTCP(b *testing.B, opts ...FramedOption) {
	client, server := benchTCPPair(b)
	payload := make([]byte, 64)
	frame := append([]byte{0, byte(len(payload))}, payload...)
	burst := make([]byte, 0, len(frame)*256)
	for range 256 {
		burst = append(burst, frame...)
	}
	go func() {
		for {
			if _, err := server.Write(burst); err != nil {
				return
			}
		}
	}()
	fc := NewFramedConn(client, append(opts, WithDatagramReads())...)
	buf := make([]byte, 2048)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fc.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFramedConnReadTCP(b *testing.B) { benchmarkFramedReadTCP(b) }

func BenchmarkFramedConnReadTCPBuffered(b *testing.B) {
	benchmarkFramedReadTCP(b, WithReadBuffer(64<<10))
}

func BenchmarkFramedConnWriteTCP(b *testing.B) {
	client, server := benchTCPPair(b)
	go func() { _, _ = io.Copy(io.Discard, server) }()
	fc := NewFramedConn(client)
	msg := make([]byte, 1024)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		if err := fc.WriteFrame(msg); err != nil {
			b.Fatal(err)
		}
	}
}
