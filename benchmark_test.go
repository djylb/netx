package netx

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
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

func BenchmarkProxyProtocolV1Header(b *testing.B) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 54321}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443}

	b.ReportAllocs()
	for b.Loop() {
		_ = ProxyProtocolV1Header(clientAddr, targetAddr)
	}
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

func BenchmarkProxyProtocolV2Header(b *testing.B) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 54321}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443}

	b.ReportAllocs()
	for b.Loop() {
		_ = ProxyProtocolV2Header(clientAddr, targetAddr)
	}
}
