package duplex_test

import (
	"io"
	"net"
	"testing"

	"github.com/djylb/netx"
	"github.com/djylb/netx/duplex"
)

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	server = <-accepted
	if server == nil {
		b.Fatal("accept failed")
	}
	b.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// BenchmarkCopyTCP copies TCP → duplex → TCP with netx.Copy, through
// the Conn's WriteTo and ReadFrom ("forwarded") and through Read and Write
// alone ("hidden").
func BenchmarkCopyTCP(b *testing.B) {
	const chunk = 64 << 10
	cases := []struct {
		name string
		ends func(in, out net.Conn) (io.Writer, io.Reader)
	}{
		{"direct", func(in, out net.Conn) (io.Writer, io.Reader) { return out, in }},
		{"read-half/forwarded", func(in, out net.Conn) (io.Writer, io.Reader) { return out, duplex.Join(in, nil) }},
		{"read-half/hidden", func(in, out net.Conn) (io.Writer, io.Reader) {
			return out, struct{ io.Reader }{duplex.Join(in, nil)}
		}},
		{"write-half/forwarded", func(in, out net.Conn) (io.Writer, io.Reader) { return duplex.Join(nil, out), in }},
		{"write-half/hidden", func(in, out net.Conn) (io.Writer, io.Reader) {
			return struct{ io.Writer }{duplex.Join(nil, out)}, in
		}},
	}
	for _, tc := range cases {
		for _, how := range []string{"io.Copy", "netx.Copy"} {
			b.Run(tc.name+"/"+how, func(b *testing.B) {
				feed, in := tcpPair(b)
				out, sink := tcpPair(b)
				dst, src := tc.ends(in, out)
				drained := make(chan struct{})
				go func() { _, _ = io.Copy(io.Discard, sink); close(drained) }()
				buf := make([]byte, chunk)
				b.SetBytes(chunk)
				b.ReportAllocs()
				go func() {
					for range b.N {
						if _, err := feed.Write(buf); err != nil {
							break
						}
					}
					_ = feed.Close()
				}()
				b.ResetTimer()
				var n int64
				var err error
				if how == "io.Copy" {
					n, err = io.Copy(dst, src)
				} else {
					n, err = netx.Copy(b.Context(), dst, src, nil)
				}
				b.StopTimer()
				if err != nil || n != int64(b.N)*chunk {
					b.Fatalf("copied %d, %v", n, err)
				}
				_ = out.Close()
				<-drained
			})
		}
	}
}

// BenchmarkReadWrite measures one small Read and Write through a Conn of
// plain halves and of a Reader and a Writer.
func BenchmarkReadWrite(b *testing.B) {
	var in duplex.Reader
	var up duplex.Writer
	_, _ = in.Append(zeroReader{})
	_ = up.Swap(b.Context(), io.Discard)
	for name, c := range map[string]*duplex.Conn{
		"plain":     duplex.Join(zeroReader{}, io.Discard),
		"swappable": duplex.Join(&in, &up),
	} {
		b.Run(name, func(b *testing.B) {
			buf := make([]byte, 64)
			b.ReportAllocs()
			for b.Loop() {
				_, _ = c.Read(buf)
				_, _ = c.Write(buf)
			}
		})
	}
}
