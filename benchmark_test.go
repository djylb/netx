package netx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func BenchmarkFramedConnWrite(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 128)
	raw := &byteBufferConn{}
	conn := NewFramedConn(raw)

	b.ReportAllocs()
	for b.Loop() {
		raw.Reset()
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFramedConnRead(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 128)
	wire := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(wire[:2], uint16(len(payload)))
	copy(wire[2:], payload)
	raw := &loopReadConn{data: wire}
	conn := NewFramedConn(raw)
	buf := make([]byte, len(payload))

	b.ReportAllocs()
	for b.Loop() {
		n, err := conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}
		if n != len(payload) {
			b.Fatalf("Read() = %d, want %d", n, len(payload))
		}
	}
}

func benchmarkFramedConnReadSmallBuffer(b *testing.B, opts ...FramedOption) {
	payload := bytes.Repeat([]byte("x"), MaxFramePayload)
	wire := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(wire[:2], uint16(len(payload)))
	copy(wire[2:], payload)
	raw := &loopReadConn{data: wire}
	conn := NewFramedConn(raw, opts...)
	buf := make([]byte, 16)

	b.ReportAllocs()
	for b.Loop() {
		for read := 0; read < len(payload); {
			n, err := conn.Read(buf)
			if err != nil {
				b.Fatal(err)
			}
			read += n
		}
	}
}

func BenchmarkFramedConnReadSmallBuffer(b *testing.B) { benchmarkFramedConnReadSmallBuffer(b) }

func BenchmarkFramedConnReadSmallBufferBuffered(b *testing.B) {
	benchmarkFramedConnReadSmallBuffer(b, WithReadBuffer(64<<10))
}

type loopReadConn struct {
	data []byte
	off  int
}

func (c *loopReadConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	if c.off == len(c.data) {
		c.off = 0
	}
	n := copy(p, c.data[c.off:])
	c.off += n
	return n, nil
}

func (c *loopReadConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *loopReadConn) Close() error { return nil }

func (c *loopReadConn) LocalAddr() net.Addr  { return dummyAddr("local") }
func (c *loopReadConn) RemoteAddr() net.Addr { return dummyAddr("remote") }

func (c *loopReadConn) SetDeadline(time.Time) error      { return nil }
func (c *loopReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *loopReadConn) SetWriteDeadline(time.Time) error { return nil }

var netErrorKindSink string

func BenchmarkNetErrorKind(b *testing.B) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"closed", &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}},
		{"closed_text", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("use of closed network connection")}},
		{"reset_text", &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", errors.New("connection reset by peer"))}},
		{"eof", io.EOF},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				netErrorKindSink = NetErrorKind(tc.err)
			}
		})
	}
}
