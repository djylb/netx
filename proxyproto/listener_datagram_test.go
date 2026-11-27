package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/netx/udpflow"
)

func newDatagramListener(t *testing.T, policy Policy, opts ...udpflow.PacketListenerOption) *Listener {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := udpflow.NewPacketListener(pc, opts...)
	t.Cleanup(func() { _ = pl.Close() })
	return &Listener{
		Listener: pl,
		Config:   Config{Policy: policy, HeaderTimeout: time.Second, Datagram: DatagramFirst},
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
	// Version 1 has no UDP token: UDP senders use TCP4 and send the header in
	// the first datagram only.
	header := wireOf(V1, udp("203.0.113.7", 40000), udp("198.51.100.1", 19132))
	if string(header[:10]) != "PROXY TCP4" {
		t.Fatalf("wireOf(V1, udp) = %q", header)
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
	header := wireOf(V2, udp("2001:db8::7", 40000), udp("2001:db8::1", 53))
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
	later := append(wireOf(V1, udp("203.0.113.7", 40000), udp("198.51.100.1", 53)), "next"...)
	server, client := sendDatagrams(t, l, []byte("PRO"), later)
	if got := readDatagram(t, server, 2); got != "PR" {
		t.Fatalf("Read() = %q", got)
	}
	if got := readDatagram(t, server, len(later)); got != string(later) {
		t.Fatalf("Read() = %q, want later datagram unchanged", got)
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

// An Optional connection passes an empty first datagram on like any other.
func TestListenerDatagramOptionalEmptyFirstDatagram(t *testing.T) {
	l := newDatagramListener(t, Optional)
	server, _ := sendDatagrams(t, l, []byte{}, []byte("next"))
	buf := make([]byte, 64)
	if n, err := server.Read(buf); n != 0 || err != nil {
		t.Fatalf("first Read() = %q, %v; want the empty datagram", buf[:n], err)
	}
	if got := readDatagram(t, server, 64); got != "next" {
		t.Fatalf("second Read() = %q, want %q", got, "next")
	}
}

func TestListenerDatagramMalformedFirstHeader(t *testing.T) {
	v2 := wireOf(V2, udp("203.0.113.7", 40000), udp("198.51.100.1", 19132))
	for _, policy := range []Policy{Required, Optional} {
		for _, d := range [][]byte{
			[]byte("PROXY TCP4 203.0.113.7"),
			v2[:20],
			append(v2Wire(0x31, 0), "payload"...),
			append(v2Wire(0x21, 0x12, 'x'), "payload"...),
		} {
			l := newDatagramListener(t, policy)
			server, _ := sendDatagrams(t, l, d)
			if h, err := server.(*Conn).Header(); h != nil || !errors.Is(err, ErrMalformed) {
				t.Fatalf("policy %d, datagram %q: Header() = %v, %v; want %v", policy, d, h, err, ErrMalformed)
			}
			if n, err := server.Read(make([]byte, 64)); n != 0 || !errors.Is(err, ErrMalformed) {
				t.Fatalf("policy %d, datagram %q: Read() = %d, %v; want %v", policy, d, n, err, ErrMalformed)
			}
		}
	}
}

func TestEachAndAutoDatagrams(t *testing.T) {
	h, err := NewHeader(V2, udp("203.0.113.7", 40000), udp("198.51.100.1", 53))
	if err != nil {
		t.Fatal(err)
	}
	h.TLVs = h.TLVs.AppendCRC32C()
	v2, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	badChecksum := bytes.Clone(v2)
	badChecksum[len(badChecksum)-1] ^= 1
	shortAddr := bytes.Clone(v2[:v2HeadLen+1])
	binary.BigEndian.PutUint16(shortAddr[14:16], 1)
	shortTLV := bytes.Clone(v2[:len(v2)-1])
	binary.BigEndian.PutUint16(shortTLV[14:16], uint16(len(shortTLV)-v2HeadLen))
	plain := []byte("raw")
	partialV1, partialV2 := []byte(v1Prefix[:3]), []byte(v2Signature[:len(v2Signature)-1])
	packets := []struct {
		wire      []byte
		payload   string
		source    string
		version   Version
		malformed bool
	}{
		{wire: plain, payload: string(plain)},
		{wire: []byte{}},
		{wire: partialV1, payload: string(partialV1)},
		{wire: partialV2, payload: string(partialV2)},
		{wire: []byte("PROXY  tcp4  192.0.2.1 198.51.100.1 0001 53 extra\none"), payload: "one", source: "192.0.2.1:1", version: V1},
		{wire: []byte("PROXY TCP4 bad\r\n"), malformed: true},
		{wire: []byte("PROXY TCP4 192.0.2.1"), malformed: true},
		{wire: v2[:len(v2Signature)], malformed: true},
		{wire: v2[:len(v2)-1], malformed: true},
		{wire: append(v2Wire(0x31, 0), "payload"...), malformed: true},
		{wire: shortAddr, malformed: true},
		{wire: shortTLV, malformed: true},
		{wire: badChecksum, malformed: true},
		{wire: []byte("PROXY TCP6 2001:db8::2 2001:db8::1 2 53\r\ntwo"), payload: "two", source: "[2001:db8::2]:2", version: V1},
		{wire: []byte("PROXY udp4 192.0.2.3 198.51.100.1 3 53\nthree"), payload: "three", source: "192.0.2.3:3", version: V1},
		{wire: []byte("PROXY UDP6 2001:db8::4%eth0 2001:db8::1 4 53\nfour"), payload: "four", source: "[2001:db8::4]:4", version: V1},
		{wire: v2, source: "203.0.113.7:40000", version: V2},
		{wire: []byte(v1Prefix), malformed: true}, // Rejection immediately before EOF.
	}
	var msgs [][]byte
	for _, p := range packets {
		msgs = append(msgs, p.wire)
	}
	for _, tt := range []struct {
		name   string
		mode   DatagramMode
		policy Policy
	}{
		{"Each/Required", DatagramEach, Required},
		{"Each/Optional", DatagramEach, Optional},
		{"Auto/Required", DatagramAuto, Required},
		{"Auto/Optional", DatagramAuto, Optional},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConn(&datagramScript{msgs: msgs}, Config{Datagram: tt.mode, Policy: tt.policy})
			buf := make([]byte, len(partialV2))
			var dropped uint64
			var first *Header
			for _, p := range packets {
				if p.malformed || tt.mode == DatagramEach && p.source == "" {
					dropped++
					continue
				}
				n, h, err := c.ReadDatagram(buf)
				if err != nil || string(buf[:n]) != p.payload {
					t.Fatalf("ReadDatagram() = %q, %v; want %q", buf[:n], err, p.payload)
				}
				if p.source == "" {
					if h != nil {
						t.Fatalf("ReadDatagram() header = %+v, want nil", h)
					}
				} else {
					if h == nil || h.Version != p.version {
						t.Fatalf("ReadDatagram() header = %+v, want version %d", h, p.version)
					}
					if src, ok := h.Source.(*net.UDPAddr); !ok || src.String() != p.source {
						t.Fatalf("ReadDatagram() source = %v (%T), want UDP %s", h.Source, h.Source, p.source)
					}
					if first == nil {
						first = h
					}
				}
				if got := c.DroppedDatagrams(); got != dropped {
					t.Fatalf("DroppedDatagrams() = %d, want %d", got, dropped)
				}
			}
			if n, h, err := c.ReadDatagram(buf); n != 0 || h != nil || !errors.Is(err, io.EOF) {
				t.Fatalf("last ReadDatagram() = %d, %v, %v; want EOF", n, h, err)
			}
			if got := c.DroppedDatagrams(); got != dropped {
				t.Fatalf("DroppedDatagrams() after EOF = %d, want %d", got, dropped)
			}
			if got := first.Source.String(); got != "192.0.2.1:1" {
				t.Fatalf("saved header source = %s after later reads", got)
			}
		})
	}
}

func TestListenerPerDatagramTrust(t *testing.T) {
	header := wireOf(V2, udp("203.0.113.7", 40000), udp("198.51.100.1", 53))
	wire := append(bytes.Clone(header), "query"...)
	for _, mode := range []DatagramMode{DatagramEach, DatagramAuto} {
		l := newDatagramListener(t, Required)
		l.Config.Datagram = mode
		l.PolicyFor = TrustPrefixes(netip.MustParsePrefix("192.0.2.0/24"))
		server, _ := sendDatagrams(t, l, wire)
		if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, ok := server.(*Conn); ok {
			t.Fatal("Accept() wrapped an untrusted peer")
		}
		if got := readDatagram(t, server, len(wire)); got != string(wire) {
			t.Fatalf("untrusted datagram = %q, want its header bytes preserved", got)
		}

		l.PolicyFor = TrustPrefixes(netip.MustParsePrefix("127.0.0.0/8"))
		server, client := sendDatagrams(t, l, wire, wire)
		if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if h, err := HeaderOf(server); err != nil || h != nil {
			t.Fatalf("HeaderOf() before Read = %v, %v; want nil, nil", h, err)
		}
		if got := readDatagram(t, server, 3); got != "que" {
			t.Fatalf("Read() = %q, want truncated payload", got)
		}
		buf := make([]byte, 8)
		n, h, err := server.(*Conn).ReadDatagram(buf)
		if err != nil || string(buf[:n]) != "query" || h == nil || h.Source == nil || h.Source.String() != "203.0.113.7:40000" {
			t.Fatalf("ReadDatagram() = %q, %v, %v; want query and its proxy source", buf[:n], h, err)
		}
		if got, want := server.RemoteAddr().String(), client.LocalAddr().String(); got != want {
			t.Errorf("RemoteAddr() = %s, want %s", got, want)
		}
		if got, want := server.LocalAddr().String(), l.Addr().String(); got != want {
			t.Errorf("LocalAddr() = %s, want %s", got, want)
		}
		if h, err := HeaderOf(server); err != nil || h != nil {
			t.Fatalf("HeaderOf() after ReadDatagram = %v, %v; want nil, nil", h, err)
		}
	}
}

// datagramRecorder records each Write as one datagram.
type datagramRecorder struct{ writes []string }

func (r *datagramRecorder) Write(p []byte) (int, error) {
	r.writes = append(r.writes, string(p))
	return len(p), nil
}

func TestListenerDatagramWriteTo(t *testing.T) {
	l := newDatagramListener(t, Required, udpflow.WithPacketIdleTimeout(200*time.Millisecond))
	header := wireOf(V1, udp("192.0.2.1", 1), udp("192.0.2.2", 2))
	server, _ := sendDatagrams(t, l, append(header, "a"...), []byte("bb"), []byte("ccc"))
	var out datagramRecorder
	n, err := io.Copy(&out, server)
	if err != nil || n != 6 || len(out.writes) != 3 || out.writes[0] != "a" || out.writes[2] != "ccc" {
		t.Fatalf("io.Copy() = %d, %v, %q", n, err, out.writes)
	}
}

func TestDatagramEachWriteTo(t *testing.T) {
	header := wireOf(V2, udp("192.0.2.1", 1), udp("192.0.2.2", 2))
	c := NewConn(&datagramScript{msgs: [][]byte{
		[]byte("headless"),
		append(bytes.Clone(header), "a"...),
		header,
		[]byte(v1Prefix),
		append(bytes.Clone(header), "bb"...),
	}}, Config{Datagram: DatagramEach})
	var out datagramRecorder
	n, err := io.Copy(&out, c)
	if err != nil || n != 3 || !slices.Equal(out.writes, []string{"a", "", "bb"}) {
		t.Fatalf("io.Copy() = %d, %v, %q", n, err, out.writes)
	}
	if got := c.DroppedDatagrams(); got != 2 {
		t.Fatalf("DroppedDatagrams() = %d, want 2", got)
	}
}

type lastDatagram struct {
	net.Conn
	wire []byte
}

func (c lastDatagram) Read(b []byte) (int, error) {
	return copy(b, c.wire), io.EOF
}

func TestDatagramEachWriteToHeaderOnlyWithEOF(t *testing.T) {
	c := NewConn(lastDatagram{wire: []byte("PROXY UNKNOWN\r\n")}, Config{Datagram: DatagramEach})
	var out datagramRecorder
	n, err := io.Copy(&out, c)
	if err != nil || n != 0 || !slices.Equal(out.writes, []string{""}) {
		t.Fatalf("io.Copy() = %d, %v, %q; want one empty datagram", n, err, out.writes)
	}
}
