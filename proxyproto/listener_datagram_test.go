package proxyproto

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/djylb/netx"
)

func newDatagramListener(t *testing.T, policy Policy, opts ...netx.PacketListenerOption) *Listener {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := netx.NewPacketListener(pc, opts...)
	t.Cleanup(func() { _ = pl.Close() })
	return &Listener{
		Listener:      pl,
		Policy:        func(net.Addr) Policy { return policy },
		HeaderTimeout: time.Second,
		Datagram:      true,
	}
}

// sendDatagrams sends each datagram from a new client socket and returns the
// connection the listener accepts for it.
func sendDatagrams(t *testing.T, l *Listener, datagrams ...[]byte) (server, client net.Conn) {
	t.Helper()
	client, err := net.Dial("udp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	for _, d := range datagrams {
		if _, err := client.Write(d); err != nil {
			t.Fatal(err)
		}
	}
	server, err = l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, client
}

func readDatagram(t *testing.T, c net.Conn, size int) string {
	t.Helper()
	buf := make([]byte, size)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	return string(buf[:n])
}

func TestListenerDatagramHeaderWithPayload(t *testing.T) {
	l := newDatagramListener(t, Required)
	// Version 1 has no UDP token: UDP senders such as Minecraft proxies use
	// TCP4 and send the header in the first datagram only.
	header := V1Header(udp("203.0.113.7", 40000), udp("198.51.100.1", 19132))
	if string(header[:10]) != "PROXY TCP4" {
		t.Fatalf("V1Header(udp) = %q", header)
	}
	server, client := sendDatagrams(t, l, append(header, "ping"...), []byte("second"), header)

	src, ok := server.RemoteAddr().(*net.UDPAddr)
	if !ok || src.String() != "203.0.113.7:40000" {
		t.Fatalf("RemoteAddr() = %#v", server.RemoteAddr())
	}
	if dst, ok := server.LocalAddr().(*net.UDPAddr); !ok || dst.String() != "198.51.100.1:19132" {
		t.Fatalf("LocalAddr() = %#v", server.LocalAddr())
	}
	if h, err := server.(*Conn).Header(); err != nil || h.Source != src {
		t.Fatalf("Header() = %v, %v", h, err)
	}
	if got := readDatagram(t, server, 64); got != "ping" {
		t.Fatalf("first payload = %q", got)
	}
	if got := readDatagram(t, server, 64); got != "second" {
		t.Fatalf("second datagram = %q", got)
	}
	// Only the first datagram carries a header; later ones are payload.
	if got := readDatagram(t, server, 64); got != string(header) {
		t.Fatalf("third datagram = %q, want it unchanged", got)
	}

	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if got := readDatagram(t, client, 64); got != "pong" {
		t.Fatalf("reply = %q", got)
	}
}

func TestListenerDatagramHeaderAlone(t *testing.T) {
	l := newDatagramListener(t, Required)
	header := V2Header(udp("2001:db8::7", 40000), udp("2001:db8::1", 53))
	server, _ := sendDatagrams(t, l, header, []byte("query"))
	if got := server.RemoteAddr().String(); got != "[2001:db8::7]:40000" {
		t.Fatalf("RemoteAddr() = %s", got)
	}
	// Datagrams are truncated to the buffer like a UDP socket's.
	if got := readDatagram(t, server, 3); got != "que" {
		t.Fatalf("Read() = %q", got)
	}
}

func TestListenerDatagramOptional(t *testing.T) {
	l := newDatagramListener(t, Optional)
	// A datagram as short as the start of a signature is payload.
	server, client := sendDatagrams(t, l, []byte("PRO"), []byte("next"))
	if got := readDatagram(t, server, 2); got != "PR" {
		t.Fatalf("Read() = %q", got)
	}
	if got := readDatagram(t, server, 64); got != "next" {
		t.Fatalf("Read() = %q", got)
	}
	if h, err := server.(*Conn).Header(); h != nil || err != nil {
		t.Fatalf("Header() = %v, %v; want none", h, err)
	}
	if got := server.RemoteAddr().String(); got != client.LocalAddr().String() {
		t.Fatalf("RemoteAddr() = %s, want the peer %s", got, client.LocalAddr())
	}
}

func TestListenerDatagramErrors(t *testing.T) {
	l := newDatagramListener(t, Required)
	server, _ := sendDatagrams(t, l, []byte("PRO"))
	if _, err := server.Read(make([]byte, 8)); !errors.Is(err, ErrNoHeader) {
		t.Fatalf("Read() error = %v, want %v", err, ErrNoHeader)
	}

	l = newDatagramListener(t, Optional)
	server, _ = sendDatagrams(t, l, []byte("PROXY TCP4 bad\r\npayload"))
	if _, err := server.Read(make([]byte, 8)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Read() error = %v, want %v", err, ErrMalformed)
	}
}

// datagramRecorder records each Write as one datagram.
type datagramRecorder struct{ writes []string }

func (r *datagramRecorder) Write(p []byte) (int, error) {
	r.writes = append(r.writes, string(p))
	return len(p), nil
}

func TestListenerDatagramWriteTo(t *testing.T) {
	l := newDatagramListener(t, Required, netx.WithIdleTimeout(200*time.Millisecond))
	header := V1Header(udp("192.0.2.1", 1), udp("192.0.2.2", 2))
	server, _ := sendDatagrams(t, l, append(header, "a"...), []byte("bb"), []byte("ccc"))
	var out datagramRecorder
	n, err := io.Copy(&out, server)
	if err != nil || n != 6 || len(out.writes) != 3 || out.writes[0] != "a" || out.writes[2] != "ccc" {
		t.Fatalf("io.Copy() = %d, %v, %q", n, err, out.writes)
	}
}
