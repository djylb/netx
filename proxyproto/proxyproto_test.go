package proxyproto

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func TestNormalizeTargetIP(t *testing.T) {
	tests := []struct {
		name string
		src  net.IP
		dst  net.IP
		want net.IP
	}{
		{
			name: "ipv4 source without target",
			src:  net.ParseIP("192.0.2.10"),
			dst:  nil,
			want: net.IPv4zero,
		},
		{
			name: "ipv6 source without target",
			src:  net.ParseIP("2001:db8::10"),
			dst:  nil,
			want: net.IPv6zero,
		},
		{
			name: "ipv4 source with unspecified ipv6 target",
			src:  net.ParseIP("192.0.2.10"),
			dst:  net.IPv6unspecified,
			want: net.IPv4zero,
		},
		{
			name: "ipv6 source with unspecified ipv4 target",
			src:  net.ParseIP("2001:db8::10"),
			dst:  net.IPv4zero,
			want: net.IPv6zero,
		},
		{
			name: "ipv6 source keeps ipv4 target",
			src:  net.ParseIP("2001:db8::10"),
			dst:  net.ParseIP("203.0.113.8"),
			want: net.ParseIP("203.0.113.8"),
		},
		{
			name: "ipv4 source keeps ipv6 target",
			src:  net.ParseIP("192.0.2.10"),
			dst:  net.ParseIP("2001:db8::20"),
			want: net.ParseIP("2001:db8::20"),
		},
		{
			name: "matching family keeps target",
			src:  net.ParseIP("192.0.2.10"),
			dst:  net.ParseIP("198.51.100.8"),
			want: net.ParseIP("198.51.100.8"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeTargetIP(tt.src, tt.dst)
			if !got.Equal(tt.want) {
				t.Fatalf("normalizeTargetIP(%v, %v) = %v, want %v", tt.src, tt.dst, got, tt.want)
			}
		})
	}
}

func TestHeaderFromAddrs(t *testing.T) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 8080}

	if got := HeaderFromAddrs(clientAddr, nil, None); got != nil {
		t.Fatalf("HeaderFromAddrs(protocol=0) = %q, want nil", got)
	}
	if got := HeaderFromAddrs(clientAddr, nil, Version(9)); got != nil {
		t.Fatalf("HeaderFromAddrs(protocol=9) = %q, want nil", got)
	}

	v1 := HeaderFromAddrs(clientAddr, nil, V1)
	wantV1 := "PROXY TCP4 192.0.2.10 0.0.0.0 1234 0\r\n"
	if string(v1) != wantV1 {
		t.Fatalf("HeaderFromAddrs(v1) = %q, want %q", string(v1), wantV1)
	}
	explicitV1 := HeaderFromAddrs(clientAddr, targetAddr, V1)
	wantExplicitV1 := "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n"
	if string(explicitV1) != wantExplicitV1 {
		t.Fatalf("HeaderFromAddrs(explicit v1) = %q, want %q", string(explicitV1), wantExplicitV1)
	}
	if !targetAddr.IP.Equal(net.ParseIP("198.51.100.20")) {
		t.Fatalf("HeaderFromAddrs mutated target addr: %v", targetAddr)
	}
	udpV1 := HeaderFromAddrs(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 53}, nil, V1)
	wantUDPV1 := "PROXY TCP4 192.0.2.10 0.0.0.0 53 0\r\n"
	if string(udpV1) != wantUDPV1 {
		t.Fatalf("HeaderFromAddrs(udp v1) = %q, want %q", string(udpV1), wantUDPV1)
	}
	udpV1IPv6 := HeaderFromAddrs(&net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 53}, nil, V1)
	wantUDPV1IPv6 := "PROXY TCP6 2001:db8::10 :: 53 0\r\n"
	if string(udpV1IPv6) != wantUDPV1IPv6 {
		t.Fatalf("HeaderFromAddrs(udp v1 ipv6) = %q, want %q", string(udpV1IPv6), wantUDPV1IPv6)
	}

	v2 := HeaderFromAddrs(&net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 5353}, nil, V2)
	if len(v2) != 52 {
		t.Fatalf("HeaderFromAddrs(v2) len = %d, want 52", len(v2))
	}
	if !bytes.HasPrefix(v2, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		t.Fatalf("HeaderFromAddrs(v2) missing signature: %v", v2[:12])
	}
	if famProto := v2[13]; famProto != 0x22 {
		t.Fatalf("HeaderFromAddrs(v2) fam/proto = 0x%x, want 0x22", famProto)
	}
}

func TestHeaderFromAddrsTypedNilClient(t *testing.T) {
	tcpTarget := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 80}
	udpTarget := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 53}
	for _, tt := range []struct {
		name   string
		client net.Addr
		target net.Addr
	}{
		{name: "tcp", client: (*net.TCPAddr)(nil), target: tcpTarget},
		{name: "udp", client: (*net.UDPAddr)(nil), target: udpTarget},
		{name: "tcp without target", client: (*net.TCPAddr)(nil)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := HeaderFromAddrs(tt.client, tt.target, V1); string(got) != "PROXY UNKNOWN\r\n" {
				t.Fatalf("v1 = %q, want PROXY UNKNOWN", got)
			}
			if got := HeaderFromAddrs(tt.client, tt.target, V2); !bytes.Equal(got, mustDecodeHex(t, proxyV2Sig+"20000000")) {
				t.Fatalf("v2 = %x, want LOCAL header", got)
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
		{
			name:   "tcp client and udp target",
			client: tcp("192.0.2.10", 1234),
			target: udp("198.51.100.20", 53),
			v1:     "PROXY TCP4 192.0.2.10 0.0.0.0 1234 0\r\n",
			v2:     "2111000c" + "c000020a" + "00000000" + "04d2" + "0000",
		},
		{
			name:   "client without ip",
			client: &net.TCPAddr{Port: 1234},
			target: tcp("198.51.100.20", 8080),
			v1:     "PROXY UNKNOWN\r\n",
			v2:     "20000000",
		},
		{
			name:   "unsupported client",
			client: dummyAddr("client"),
			target: tcp("198.51.100.20", 8080),
			v1:     "PROXY UNKNOWN\r\n",
			v2:     "20000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HeaderFromAddrs(tt.client, tt.target, V1); string(got) != tt.v1 {
				t.Fatalf("v1 = %q, want %q", got, tt.v1)
			}
			want := mustDecodeHex(t, proxyV2Sig+tt.v2)
			if got := HeaderFromAddrs(tt.client, tt.target, V2); !bytes.Equal(got, want) {
				t.Fatalf("v2 = %x, want %x", got, want)
			}
		})
	}

	if !net.IPv4zero.Equal(net.IPv4(0, 0, 0, 0)) || !net.IPv6zero.Equal(make(net.IP, net.IPv6len)) {
		t.Fatalf("header building mutated net.IPv4zero=%v or net.IPv6zero=%v", net.IPv4zero, net.IPv6zero)
	}
}

func TestHeaderBuildersMixedFamilies(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	target := &net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443}

	if got, want := string(V1Header(client, target)), "PROXY TCP6 ::ffff:192.0.2.10 2001:db8::20 1234 443\r\n"; got != want {
		t.Fatalf("V1Header() = %q, want %q", got, want)
	}
	want := mustDecodeHex(t, proxyV2Sig+"21210024"+"00000000000000000000ffffc000020a"+"20010db8000000000000000000000020"+"04d2"+"01bb")
	if got := V2Header(client, target); !bytes.Equal(got, want) {
		t.Fatalf("V2Header() = %x, want %x", got, want)
	}
	// The direct builders do not rewrite an unspecified target.
	if got, want := string(V1Header(client, &net.TCPAddr{IP: net.IPv6unspecified, Port: 443})), "PROXY TCP6 ::ffff:192.0.2.10 :: 1234 443\r\n"; got != want {
		t.Fatalf("V1Header(unspecified target) = %q, want %q", got, want)
	}
}

func TestV1HeaderFitsCapacity(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), Port: 65535}
	target := &net.TCPAddr{IP: net.ParseIP("255.255.255.255"), Port: 65535}
	got := V1Header(client, target)
	if want := "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe ::ffff:255.255.255.255 65535 65535\r\n"; string(got) != want {
		t.Fatalf("V1Header() = %q, want %q", got, want)
	}
	if len(got) > maxV1Len || cap(got) != maxV1Len {
		t.Fatalf("header len = %d, cap = %d; want the longest header within one %d-byte allocation", len(got), cap(got), maxV1Len)
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

func TestHeaderFromConnAddrs(t *testing.T) {
	c := addrConn{
		local:  &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 8080},
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234},
	}
	if got := string(HeaderFromConn(c, V1)); got != "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n" {
		t.Fatalf("HeaderFromConn(v1) = %q", got)
	}
	if got := HeaderFromConn(c, None); got != nil {
		t.Fatalf("HeaderFromConn(None) = %q, want nil", got)
	}
	if got := HeaderFromConn(nil, V2); got != nil {
		t.Fatalf("HeaderFromConn(nil conn) = %q, want nil", got)
	}
}

func BenchmarkV1Header(b *testing.B) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 54321}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443}

	b.ReportAllocs()
	for b.Loop() {
		_ = V1Header(clientAddr, targetAddr)
	}
}

func BenchmarkV2Header(b *testing.B) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 54321}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443}

	b.ReportAllocs()
	for b.Loop() {
		_ = V2Header(clientAddr, targetAddr)
	}
}
