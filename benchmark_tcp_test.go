package netx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
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
	fc := NewFramedConn(client, append(opts, WithFramedDatagrams())...)
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
	benchmarkFramedReadTCP(b, WithFramedReadBuffer(64<<10))
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

// BenchmarkRelayTCP moves data between two TCP connections, which splice
// copies on Linux, without and with a counting flow, against io.Copy.
func BenchmarkRelayTCP(b *testing.B) {
	const chunk = 64 << 10
	for _, mode := range []string{"io.Copy", "Relay", "RelayFlow"} {
		b.Run(mode, func(b *testing.B) {
			src, srcPeer := benchTCPPair(b)
			dstPeer, dst := benchTCPPair(b)
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch mode {
				case "io.Copy":
					_, _ = io.Copy(dst, srcPeer)
				case "Relay":
					_, _, _ = Relay(context.Background(), srcPeer, dst)
				default:
					var counted int64
					_, _, _ = Relay(context.Background(), srcPeer, dst, WithRelayFlows(&RelayFlow{Done: func(n int64) error {
						counted += n
						return nil
					}}, nil))
				}
			}()
			go func() { _, _ = io.Copy(io.Discard, dstPeer) }()
			buf := make([]byte, chunk)
			b.SetBytes(chunk)
			b.ResetTimer()
			for b.Loop() {
				if _, err := src.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			_ = src.Close()
			_ = dst.Close()
			<-done
		})
	}
}

// BenchmarkCopySetup measures what Copy costs before data moves: it copies
// a TCP connection whose peer has finished, so each Copy finds the end at
// once, beneath a TimeoutConn and a PrefixConn, with a counting flow.
func BenchmarkCopySetup(b *testing.B) {
	client, server := benchTCPPair(b)
	_ = server.(*net.TCPConn).CloseWrite()
	src := NewTimeoutConn(NewPrefixConn(client, nil), time.Minute)
	f := RelayFlow{Done: func(int64) error { return nil }}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Copy(context.Background(), io.Discard, src, &f); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCopyStream copies a stream without WriterTo through Copy's
// buffer, with a counting flow.
func BenchmarkCopyStream(b *testing.B) {
	const chunk = 32 << 10
	data := make([]byte, chunk)
	f := RelayFlow{Done: func(int64) error { return nil }}
	b.SetBytes(chunk * 64)
	b.ReportAllocs()
	for b.Loop() {
		r := &repeatReader{data: data, left: 64}
		if _, err := Copy(context.Background(), io.Discard, r, &f); err != nil {
			b.Fatal(err)
		}
	}
}

// repeatReader returns data left times, then EOF.
type repeatReader struct {
	data []byte
	left int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	r.left--
	return copy(p, r.data), nil
}

// BenchmarkCopyFramedDatagrams copies the frames of a FramedConn with
// WithFramedDatagrams, each handed over in a pooled buffer, with a counting
// flow.
func BenchmarkCopyFramedDatagrams(b *testing.B) {
	for _, size := range []int{512, 8 << 10} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			wire := make([]byte, 2+size)
			binary.BigEndian.PutUint16(wire, uint16(size))
			const frames = 64
			raw := &loopReadConn{data: bytes.Repeat(wire, frames)}
			fc := NewFramedConn(raw, WithFramedDatagrams())
			var left int
			f := RelayFlow{
				// Ends the copy after frames datagrams.
				Wait: func(_ context.Context, n int64) (int64, error) {
					if left == 0 {
						return 0, errBenchDone
					}
					left--
					return n, nil
				},
				Done: func(int64) error { return nil },
			}
			b.SetBytes(int64(size) * frames)
			b.ReportAllocs()
			for b.Loop() {
				left = frames
				if _, err := Copy(context.Background(), io.Discard, fc, &f); !errors.Is(err, errBenchDone) {
					b.Fatal(err)
				}
			}
		})
	}
}

var errBenchDone = errors.New("bench done")

// BenchmarkPacketListener sends datagrams from a UDP client to a
// PacketListener connection that Reads them: the read loop's dispatch and
// queue, and the connection's Read.
func BenchmarkPacketListener(b *testing.B) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	l := NewPacketListener(pc)
	b.Cleanup(func() { _ = l.Close() })
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = client.Close() })
	msg := make([]byte, 1200)
	if _, err := client.Write(msg); err != nil {
		b.Fatal(err)
	}
	c, err := l.Accept()
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 2048)
	if _, err := c.Read(buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		// One in flight at a time, so that none is dropped.
		if _, err := client.Write(msg); err != nil {
			b.Fatal(err)
		}
		if _, err := c.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
}
