package netx

import (
	"bytes"
	"net"
	"testing"
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

func BenchmarkProxyProtocolV1Header(b *testing.B) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 54321}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443}

	b.ReportAllocs()
	for b.Loop() {
		_ = ProxyProtocolV1Header(clientAddr, targetAddr)
	}
}

func BenchmarkProxyProtocolV2Header(b *testing.B) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 54321}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443}

	b.ReportAllocs()
	for b.Loop() {
		_ = ProxyProtocolV2Header(clientAddr, targetAddr)
	}
}
