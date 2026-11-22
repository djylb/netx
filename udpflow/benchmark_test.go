package udpflow

import (
	"net"
	"testing"
)

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
