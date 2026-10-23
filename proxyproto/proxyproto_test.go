package proxyproto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

// wireOf returns the encoded header from NewHeader, for tests that need
// valid header bytes.
func wireOf(v Version, src, dst net.Addr) []byte {
	h, err := NewHeader(v, src, dst)
	if err != nil {
		panic(err)
	}
	b, err := h.AppendBinary(nil)
	if err != nil {
		panic(err)
	}
	return b
}

func TestNewHeaderNormalizesDestination(t *testing.T) {
	client := tcp("192.0.2.10", 1234)
	target := tcp("198.51.100.20", 8080)
	for _, tt := range []struct {
		name     string
		src, dst net.Addr
		v1       string
	}{
		{"explicit", client, target, "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n"},
		{"nil", client, nil, "PROXY TCP4 192.0.2.10 0.0.0.0 1234 0\r\n"},
		{"typed nil", client, (*net.TCPAddr)(nil), "PROXY TCP4 192.0.2.10 0.0.0.0 1234 0\r\n"},
		{"port only", client, &net.TCPAddr{Port: 443}, "PROXY TCP4 192.0.2.10 0.0.0.0 1234 443\r\n"},
		{"unspecified ipv6 for ipv4", client, tcp("::", 443), "PROXY TCP4 192.0.2.10 0.0.0.0 1234 443\r\n"},
		{"unspecified ipv4 for ipv6", tcp("2001:db8::10", 1), tcp("0.0.0.0", 2), "PROXY TCP6 2001:db8::10 :: 1 2\r\n"},
		{"udp nil", udp("192.0.2.10", 53), nil, "PROXY TCP4 192.0.2.10 0.0.0.0 53 0\r\n"},
		{"udp ipv6 nil", udp("2001:db8::10", 53), nil, "PROXY TCP6 2001:db8::10 :: 53 0\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(wireOf(V1, tt.src, tt.dst)); got != tt.v1 {
				t.Fatalf("v1 = %q, want %q", got, tt.v1)
			}
		})
	}
	if !target.IP.Equal(net.ParseIP("198.51.100.20")) || !net.IPv4zero.Equal(net.IPv4(0, 0, 0, 0)) {
		t.Fatal("NewHeader mutated an address")
	}

	// The header holds copies of the addresses.
	src := tcp("192.0.2.10", 1234)
	h, err := NewHeader(V2, src, target)
	if err != nil {
		t.Fatal(err)
	}
	src.IP[15], src.Port = 99, 1
	if got := h.Source.String(); got != "192.0.2.10:1234" {
		t.Fatalf("Source = %s after the caller changed its address", got)
	}
	if v2 := wireOf(V2, udp("2001:db8::10", 5353), nil); len(v2) != 52 || v2[13] != 0x22 {
		t.Fatalf("v2 udp = %x, want a 52-byte DGRAM over AF_INET6 header", v2)
	}
}

// NewHeader and AppendBinary reject address pairs a header cannot carry
// instead of sending a header without addresses.
func TestUnsupportedAddressPairs(t *testing.T) {
	unix := &net.UnixAddr{Name: "/a", Net: "unix"}
	for _, tt := range []struct {
		name     string
		v        Version
		src, dst net.Addr
	}{
		{"nil source", V2, nil, tcp("192.0.2.1", 1)},
		{"nil source and destination", V2, nil, nil},
		{"typed nil source", V1, (*net.TCPAddr)(nil), tcp("192.0.2.1", 1)},
		{"typed nil udp source", V2, (*net.UDPAddr)(nil), nil},
		{"typed nil unix source", V2, (*net.UnixAddr)(nil), nil},
		{"source without ip", V1, &net.TCPAddr{Port: 1234}, tcp("192.0.2.1", 1)},
		{"custom source", V2, dummyAddr("client"), tcp("192.0.2.1", 1)},
		{"custom destination", V2, tcp("192.0.2.1", 1), dummyAddr("server")},
		{"tcp and udp", V1, tcp("192.0.2.1", 1), udp("192.0.2.2", 2)},
		{"udp and tcp", V2, udp("192.0.2.1", 1), tcp("192.0.2.2", 2)},
		{"tcp and unix", V2, tcp("192.0.2.1", 1), unix},
		{"unix and tcp", V2, unix, tcp("192.0.2.1", 1)},
		{"unix stream and datagram", V2, unix, &net.UnixAddr{Name: "/b", Net: "unixgram"}},
		{"unix in version 1", V1, unix, unix},
		{"unix name too long", V2, &net.UnixAddr{Name: strings.Repeat("a", unixPathLen+1), Net: "unix"}, unix},
		{"port out of range", V2, tcp("192.0.2.1", 65536), tcp("192.0.2.2", 2)},
		{"negative port", V1, tcp("192.0.2.1", 1), tcp("192.0.2.2", -1)},
		{"no version", 0, tcp("192.0.2.1", 1), tcp("192.0.2.2", 2)},
		{"unknown version", 3, tcp("192.0.2.1", 1), tcp("192.0.2.2", 2)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if h, err := NewHeader(tt.v, tt.src, tt.dst); err == nil {
				t.Fatalf("NewHeader() = %+v, want an error", h)
			}
			if tt.src == nil && tt.dst == nil {
				return // a Header without addresses is encodable
			}
			h := Header{Version: tt.v, Source: tt.src, Destination: tt.dst}
			if b, err := h.AppendBinary([]byte("x")); err == nil || string(b) != "x" {
				t.Fatalf("AppendBinary() = %q, %v; want an error and b unchanged", b, err)
			}
		})
	}
}

// A header without addresses is encoded as such, and LOCAL only on request.
func TestHeaderWithoutAddresses(t *testing.T) {
	tlvs := mkTLVs(t, field{TLVAuthority, "example.com"})
	for _, tt := range []struct {
		name string
		h    Header
		want string
	}{
		{"v1 local", Header{Version: V1, Local: true}, "PROXY UNKNOWN\r\n"},
		{"v1 unspecified", Header{Version: V1}, "PROXY UNKNOWN\r\n"},
		{"v2 local", Header{Version: V2, Local: true}, string(mustDecodeHex(t, proxyV2Sig+"20000000"))},
		{"v2 local ignores addresses", Header{Version: V2, Local: true, Source: dummyAddr("a")}, string(mustDecodeHex(t, proxyV2Sig+"20000000"))},
		{"v2 unspecified", Header{Version: V2}, string(mustDecodeHex(t, proxyV2Sig+"21000000"))},
		{"v2 local tlvs", Header{Version: V2, Local: true, TLVs: tlvs}, string(mustDecodeHex(t, proxyV2Sig+"2000000e")) + string(tlvs)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.h.AppendBinary(nil)
			if err != nil || string(b) != tt.want {
				t.Fatalf("AppendBinary() = %q, %v; want %q", b, err, tt.want)
			}
			got, _, err := Decode(b)
			if err != nil || got.Local != tt.h.Local && tt.h.Version == V2 || got.Source != nil || got.Destination != nil {
				t.Fatalf("Decode() = %+v, %v", got, err)
			}
		})
	}
}

const proxyV2Sig = "0d0a0d0a000d0a515549540a"

func TestHeaderGolden(t *testing.T) {
	tcp := func(ip string, port int) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: port} }
	udp := func(ip string, port int) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: port} }
	tcp4 := func(ip string, port int) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip).To4(), Port: port} }

	tests := []struct {
		name   string
		client net.Addr
		target net.Addr
		v1     string
		v2     string // hex after the 12-byte signature
	}{
		{
			name:   "tcp ipv4",
			client: tcp("192.0.2.10", 1234),
			target: tcp("198.51.100.20", 8080),
			v1:     "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n",
			v2:     "2111000c" + "c000020a" + "c6336414" + "04d2" + "1f90",
		},
		{
			name:   "tcp ipv4 in 4-byte form",
			client: tcp4("192.0.2.10", 1234),
			target: tcp4("198.51.100.20", 8080),
			v1:     "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n",
			v2:     "2111000c" + "c000020a" + "c6336414" + "04d2" + "1f90",
		},
		{
			name:   "tcp ipv4-mapped client and ipv4 target",
			client: tcp("::ffff:192.0.2.10", 1234),
			target: tcp4("198.51.100.20", 8080),
			v1:     "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n",
			v2:     "2111000c" + "c000020a" + "c6336414" + "04d2" + "1f90",
		},
		{
			name:   "udp ipv4",
			client: udp("192.0.2.10", 53),
			target: udp("198.51.100.20", 5353),
			v1:     "PROXY TCP4 192.0.2.10 198.51.100.20 53 5353\r\n",
			v2:     "2112000c" + "c000020a" + "c6336414" + "0035" + "14e9",
		},
		{
			name:   "tcp ipv6",
			client: tcp("2001:db8::10", 1234),
			target: tcp("2001:db8::20", 443),
			v1:     "PROXY TCP6 2001:db8::10 2001:db8::20 1234 443\r\n",
			v2:     "21210024" + "20010db8000000000000000000000010" + "20010db8000000000000000000000020" + "04d2" + "01bb",
		},
		{
			name:   "tcp ipv6 client and ipv4 target",
			client: tcp("2001:db8::10", 1234),
			target: tcp("203.0.113.8", 443),
			v1:     "PROXY TCP6 2001:db8::10 ::ffff:203.0.113.8 1234 443\r\n",
			v2:     "21210024" + "20010db8000000000000000000000010" + "00000000000000000000ffffcb007108" + "04d2" + "01bb",
		},
		{
			name:   "tcp ipv6 client and 4-byte ipv4 target",
			client: tcp("2001:db8::10", 1234),
			target: tcp4("203.0.113.8", 443),
			v1:     "PROXY TCP6 2001:db8::10 ::ffff:203.0.113.8 1234 443\r\n",
			v2:     "21210024" + "20010db8000000000000000000000010" + "00000000000000000000ffffcb007108" + "04d2" + "01bb",
		},
		{
			name:   "tcp ipv6 client and ipv4-mapped target",
			client: tcp("2001:db8::10", 1234),
			target: tcp("::ffff:198.51.100.1", 443),
			v1:     "PROXY TCP6 2001:db8::10 ::ffff:198.51.100.1 1234 443\r\n",
			v2:     "21210024" + "20010db8000000000000000000000010" + "00000000000000000000ffffc6336401" + "04d2" + "01bb",
		},
		{
			name:   "tcp ipv4 client and ipv6 target",
			client: tcp("192.0.2.10", 1234),
			target: tcp("2001:db8::20", 443),
			v1:     "PROXY TCP6 ::ffff:192.0.2.10 2001:db8::20 1234 443\r\n",
			v2:     "21210024" + "00000000000000000000ffffc000020a" + "20010db8000000000000000000000020" + "04d2" + "01bb",
		},
		{
			name:   "udp ipv4 client and ipv6 target",
			client: udp("192.0.2.10", 53),
			target: udp("2001:db8::20", 5353),
			v1:     "PROXY TCP6 ::ffff:192.0.2.10 2001:db8::20 53 5353\r\n",
			v2:     "21220024" + "00000000000000000000ffffc000020a" + "20010db8000000000000000000000020" + "0035" + "14e9",
		},
		{
			name:   "udp ipv6 client and ipv4 target",
			client: udp("2001:db8::10", 53),
			target: udp("203.0.113.8", 5353),
			v1:     "PROXY TCP6 2001:db8::10 ::ffff:203.0.113.8 53 5353\r\n",
			v2:     "21220024" + "20010db8000000000000000000000010" + "00000000000000000000ffffcb007108" + "0035" + "14e9",
		},
		{
			name:   "tcp ipv4 client and unspecified ipv6 target",
			client: tcp("192.0.2.10", 1234),
			target: tcp("::", 443),
			v1:     "PROXY TCP4 192.0.2.10 0.0.0.0 1234 443\r\n",
			v2:     "2111000c" + "c000020a" + "00000000" + "04d2" + "01bb",
		},
		{
			name:   "tcp ipv6 client without target",
			client: tcp("2001:db8::10", 1234),
			target: nil,
			v1:     "PROXY TCP6 2001:db8::10 :: 1234 0\r\n",
			v2:     "21210024" + "20010db8000000000000000000000010" + "00000000000000000000000000000000" + "04d2" + "0000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wireOf(V1, tt.client, tt.target); string(got) != tt.v1 {
				t.Fatalf("v1 = %q, want %q", got, tt.v1)
			}
			want := mustDecodeHex(t, proxyV2Sig+tt.v2)
			if got := wireOf(V2, tt.client, tt.target); !bytes.Equal(got, want) {
				t.Fatalf("v2 = %x, want %x", got, want)
			}
		})
	}

	if !net.IPv4zero.Equal(net.IPv4(0, 0, 0, 0)) || !net.IPv6zero.Equal(make(net.IP, net.IPv6len)) {
		t.Fatalf("header building mutated net.IPv4zero=%v or net.IPv6zero=%v", net.IPv4zero, net.IPv6zero)
	}
}

// AppendBinary encodes the addresses it is given, without the rewriting of
// an unspecified destination that NewHeader does.
func TestAppendBinaryKeepsAddresses(t *testing.T) {
	h := Header{Version: V1, Source: tcp("192.0.2.10", 1234), Destination: &net.TCPAddr{IP: net.IPv6unspecified, Port: 443}}
	if got, err := h.AppendBinary(nil); err != nil || string(got) != "PROXY TCP6 ::ffff:192.0.2.10 :: 1234 443\r\n" {
		t.Fatalf("AppendBinary() = %q, %v", got, err)
	}
}

// The longest header of each version takes one allocation.
func TestAppendBinaryAllocatesOnce(t *testing.T) {
	client := tcp("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", 65535)
	target := tcp("255.255.255.255", 65535)
	h, err := NewHeader(V1, client, target)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := h.AppendBinary(nil)
	if want := "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe ::ffff:255.255.255.255 65535 65535\r\n"; string(got) != want {
		t.Fatalf("AppendBinary() = %q, want %q", got, want)
	}
	if len(got) > maxV1Len {
		t.Fatalf("header len = %d, want at most %d", len(got), maxV1Len)
	}
	h2 := Header{Version: V2, Source: &net.UnixAddr{Name: "/a", Net: "unix"}, Destination: &net.UnixAddr{Name: "/b", Net: "unix"},
		TLVs: mkTLVs(t, field{TLVUniqueID, strings.Repeat("u", 100)})}
	if raceEnabled {
		t.Skip("the race detector adds allocations")
	}
	for _, h := range []*Header{h, &h2} {
		if n := testing.AllocsPerRun(100, func() { _, _ = h.AppendBinary(nil) }); n != 1 {
			t.Fatalf("AppendBinary(nil) of version %d allocates %v times, want 1", h.Version, n)
		}
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

// addrConn is a net.Conn that only reports addresses.
type addrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c addrConn) LocalAddr() net.Addr  { return c.local }
func (c addrConn) RemoteAddr() net.Addr { return c.remote }

func TestHeaderFromConn(t *testing.T) {
	c := addrConn{
		local:  tcp("198.51.100.20", 8080),
		remote: tcp("192.0.2.10", 1234),
	}
	h, err := HeaderFromConn(V1, c)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := h.AppendBinary(nil); string(got) != "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n" {
		t.Fatalf("HeaderFromConn(v1) = %q", got)
	}
	if _, err := HeaderFromConn(V2, nil); err == nil {
		t.Fatal("HeaderFromConn(nil conn) succeeded")
	}
	if _, err := HeaderFromConn(V2, addrConn{remote: dummyAddr("a"), local: dummyAddr("b")}); err == nil {
		t.Fatal("HeaderFromConn() of custom addresses succeeded")
	}
}

func BenchmarkAppendBinaryV1(b *testing.B) {
	h, _ := NewHeader(V1, tcp("192.0.2.10", 54321), tcp("198.51.100.20", 443))
	buf := make([]byte, 0, maxV1Len)
	b.ReportAllocs()
	for b.Loop() {
		buf, _ = h.AppendBinary(buf[:0])
	}
}

func BenchmarkAppendBinaryV2(b *testing.B) {
	h, _ := NewHeader(V2, tcp("2001:db8::10", 54321), tcp("2001:db8::20", 443))
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	for b.Loop() {
		buf, _ = h.AppendBinary(buf[:0])
	}
}

// Custom fields go through a header unchanged.
func TestCustomTLVs(t *testing.T) {
	if !TLVCustomMin.IsCustom() || !TLVCustomMax.IsCustom() || TLVExperimentalMin.IsCustom() || TLVSSL.IsCustom() {
		t.Fatal("IsCustom does not match the custom range")
	}
	if !TLVExperimentalMin.IsExperimental() || !TLVExperimentalMax.IsExperimental() ||
		TLVCustomMax.IsExperimental() || (TLVExperimentalMax + 1).IsExperimental() {
		t.Fatal("IsExperimental does not match the experimental range")
	}
	h := Header{Version: V2, Source: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1},
		Destination: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 2}}
	h.TLVs, _ = h.TLVs.Append(TLVCustomMin, []byte("user-7"))
	h.TLVs, _ = h.TLVs.Append(TLVCustomMin+1, []byte("tunnel-9"))
	b, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := got.TLVs.Get(TLVCustomMin); string(v) != "user-7" {
		t.Fatalf("custom field = %q", v)
	}
	if v, _ := got.TLVs.Get(TLVCustomMin + 1); string(v) != "tunnel-9" {
		t.Fatalf("custom field = %q", v)
	}
}

// writeRecorder records each Write, writing at most limit bytes of it when
// limit is positive.
type writeRecorder struct {
	writes [][]byte
	limit  int
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.writes = append(w.writes, bytes.Clone(p))
	if w.limit > 0 && len(p) > w.limit {
		return w.limit, nil
	}
	return len(p), nil
}

func TestHeaderWriteTo(t *testing.T) {
	small, err := NewHeader(V2, tcp("192.0.2.1", 1), tcp("192.0.2.2", 2))
	if err != nil {
		t.Fatal(err)
	}
	big := *small
	big.TLVs = mkTLVs(t, field{TLVUniqueID, strings.Repeat("u", 1000)})
	for _, h := range []*Header{small, &big} {
		want, _ := h.AppendBinary(nil)
		var w writeRecorder
		n, err := h.WriteTo(&w)
		if err != nil || n != int64(len(want)) || len(w.writes) != 1 || !bytes.Equal(w.writes[0], want) {
			t.Fatalf("WriteTo() = %d, %v with %d writes; want %d bytes in one", n, err, len(w.writes), len(want))
		}
	}

	var w writeRecorder
	if _, err := (&Header{Version: V1, Source: dummyAddr("a"), Destination: dummyAddr("b")}).WriteTo(&w); err == nil || len(w.writes) != 0 {
		t.Fatalf("WriteTo() of an unsupported pair = %v with %d writes; want an error and no write", err, len(w.writes))
	}
	short := writeRecorder{limit: 3}
	if n, err := small.WriteTo(&short); n != 3 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteTo() of a short Write = %d, %v; want 3, %v", n, err, io.ErrShortWrite)
	}
}
