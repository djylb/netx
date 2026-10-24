package wsconn

import (
	"bytes"
	"net"
	"testing"
)

// discardConn is a net.Conn that discards what is written.
type discardConn struct{ memConn }

func (*discardConn) Write(p []byte) (int, error) { return len(p), nil }

func benchStream(b *testing.B, size int, fromServer, compress bool) {
	var so ServerOptions
	var co ClientOptions
	if compress {
		so.Compression = &Compression{}
		co.Compression = &Compression{}
	}
	srv, cli := pairB(b, &so, &co)
	w, r := NewStreamConn(srv), NewStreamConn(cli)
	if !fromServer {
		w, r = r, w
	}
	msg := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		total := int64(b.N) * int64(len(msg))
		for total > 0 {
			n, err := r.Read(buf)
			if err != nil {
				return
			}
			total -= int64(n)
		}
	}()
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := w.Write(msg); err != nil {
			b.Fatal(err)
		}
	}
	<-done
}

// pairB is pair for benchmarks.
func pairB(b *testing.B, so *ServerOptions, co *ClientOptions) (*Conn, *Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ch := make(chan *Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		c, _ := Accept(b.Context(), raw, so)
		ch <- c
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	cli, _, err := Client(b.Context(), raw, "ws://"+ln.Addr().String()+"/", co)
	if err != nil {
		b.Fatal(err)
	}
	srv := <-ch
	if srv == nil {
		b.Fatal("accept failed")
	}
	b.Cleanup(func() {
		_ = cli.NetConn().Close()
		_ = srv.NetConn().Close()
	})
	return srv, cli
}

func BenchmarkStreamServerToClient32K(b *testing.B) { benchStream(b, 32<<10, true, false) }
func BenchmarkStreamClientToServer32K(b *testing.B) { benchStream(b, 32<<10, false, false) }
func BenchmarkStreamServerToClient1K(b *testing.B)  { benchStream(b, 1<<10, true, false) }
func BenchmarkStreamClientToServer1K(b *testing.B)  { benchStream(b, 1<<10, false, false) }
func BenchmarkStreamDeflate32K(b *testing.B)        { benchStream(b, 32<<10, true, true) }

func BenchmarkWriteMessage(b *testing.B) {
	for _, client := range []bool{false, true} {
		b.Run(map[bool]string{false: "server", true: "client"}[client], func(b *testing.B) {
			c := NewConn(&discardConn{}, nil, client, nil)
			msg := make([]byte, 128)
			b.SetBytes(int64(len(msg)))
			b.ReportAllocs()
			for range b.N {
				if err := c.WriteMessage(Binary, msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// repeatReader reads a frame over and over.
type repeatReader struct {
	frame []byte
	off   int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		k := copy(p[n:], r.frame[r.off:])
		n += k
		r.off = (r.off + k) % len(r.frame)
	}
	return n, nil
}

func BenchmarkAppendMessage(b *testing.B) {
	f := frame(finBit|opBinary, true, make([]byte, 128))
	c := NewConn(&memConn{r: &repeatReader{frame: f}}, nil, false, nil)
	buf := make([]byte, 0, 256)
	b.SetBytes(128)
	b.ReportAllocs()
	for range b.N {
		_, p, err := c.AppendMessage(buf[:0])
		if err != nil || len(p) != 128 {
			b.Fatal(err)
		}
	}
}

func BenchmarkMask(b *testing.B) {
	p := make([]byte, 32<<10)
	b.SetBytes(int64(len(p)))
	for range b.N {
		mask(p, 0x12345678, 1)
	}
}
