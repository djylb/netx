package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func tcp(ip string, port int) *net.TCPAddr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: port} }

func udp(ip string, port int) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: port} }

func TestHeaderRoundTrip(t *testing.T) {
	tlvs := []TLV{{Type: TLVAuthority, Value: []byte("example.com")}, {Type: TLVUniqueID, Value: []byte{1, 2, 3}}, {Type: TLVNoop}}
	tests := []struct {
		name     string
		h        Header
		src, dst string
	}{
		{"v1 tcp4", Header{Version: V1, Source: tcp("192.0.2.1", 5000), Destination: tcp("198.51.100.1", 443)}, "192.0.2.1:5000", "198.51.100.1:443"},
		{"v1 tcp6", Header{Version: V1, Source: tcp("2001:db8::1", 5000), Destination: tcp("2001:db8::2", 443)}, "[2001:db8::1]:5000", "[2001:db8::2]:443"},
		{"v1 unknown", Header{Version: V1, Local: true}, "", ""},
		{"v2 tcp4 tlvs", Header{Version: V2, Source: tcp("192.0.2.1", 5000), Destination: tcp("198.51.100.1", 443), TLVs: tlvs}, "192.0.2.1:5000", "198.51.100.1:443"},
		{"v2 tcp6", Header{Version: V2, Source: tcp("2001:db8::1", 1), Destination: tcp("2001:db8::2", 2)}, "[2001:db8::1]:1", "[2001:db8::2]:2"},
		{"v2 udp", Header{Version: V2, Source: udp("192.0.2.1", 53), Destination: udp("198.51.100.1", 5353)}, "192.0.2.1:53", "198.51.100.1:5353"},
		{"v2 unix", Header{Version: V2, Source: &net.UnixAddr{Name: "/run/client.sock", Net: "unix"}, Destination: &net.UnixAddr{Name: "/run/server.sock", Net: "unix"}}, "/run/client.sock", "/run/server.sock"},
		{"v2 local", Header{Version: V2, Local: true, TLVs: tlvs[:1]}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.h.AppendBinary([]byte("prefix"))
			if err != nil {
				t.Fatalf("AppendBinary() error = %v", err)
			}
			wire = append(wire, "payload"...)
			got, n, err := Parse(wire[len("prefix"):])
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", wire, err)
			}
			if rest := string(wire[len("prefix")+n:]); rest != "payload" {
				t.Fatalf("Parse() length leaves %q, want payload", rest)
			}
			if got.Version != tt.h.Version || got.Local != tt.h.Local {
				t.Fatalf("Parse() = version %d local %v", got.Version, got.Local)
			}
			if addrString(got.Source) != tt.src || addrString(got.Destination) != tt.dst {
				t.Fatalf("Parse() addresses = %v -> %v, want %s -> %s", got.Source, got.Destination, tt.src, tt.dst)
			}
			if len(got.TLVs) != len(tt.h.TLVs) {
				t.Fatalf("Parse() TLVs = %v, want %v", got.TLVs, tt.h.TLVs)
			}
			for i, tlv := range got.TLVs {
				if tlv.Type != tt.h.TLVs[i].Type || !bytes.Equal(tlv.Value, tt.h.TLVs[i].Value) {
					t.Fatalf("TLV %d = %v, want %v", i, tlv, tt.h.TLVs[i])
				}
			}
		})
	}
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func TestHeaderTLVAndErrors(t *testing.T) {
	h := &Header{TLVs: []TLV{{Type: TLVALPN, Value: []byte("h2")}, {Type: TLVALPN, Value: []byte("http/1.1")}}}
	if v, ok := h.TLV(TLVALPN); !ok || string(v) != "h2" {
		t.Fatalf("TLV(ALPN) = %q, %v", v, ok)
	}
	if _, ok := h.TLV(TLVAuthority); ok {
		t.Fatal("TLV(Authority) found")
	}
	if _, err := (&Header{Version: V1, TLVs: h.TLVs}).AppendBinary(nil); err == nil {
		t.Fatal("version 1 with TLVs encoded")
	}
	if _, err := (&Header{Version: V2, TLVs: []TLV{{Value: make([]byte, 0x10000)}}}).AppendBinary(nil); err == nil {
		t.Fatal("oversized TLV encoded")
	}
	big := []TLV{{Value: make([]byte, 0xfff0)}, {Value: make([]byte, 0xfff0)}}
	if got, err := (&Header{Version: V2, TLVs: big}).AppendBinary([]byte("x")); err == nil || string(got) != "x" {
		t.Fatalf("oversized header = %d bytes, %v; want an error and b unchanged", len(got), err)
	}
	if _, err := (&Header{Version: 7}).AppendBinary(nil); err == nil {
		t.Fatal("unknown version encoded")
	}
	// Mismatched families become UNKNOWN or LOCAL.
	if got, _ := (&Header{Version: V1, Source: tcp("192.0.2.1", 1), Destination: udp("192.0.2.2", 2)}).AppendBinary(nil); string(got) != "PROXY UNKNOWN\r\n" {
		t.Fatalf("mixed v1 = %q", got)
	}
}

func v2Wire(verCmd, fam byte, body ...byte) []byte {
	b := append([]byte(v2Signature), verCmd, fam, byte(len(body)>>8), byte(len(body)))
	return append(b, body...)
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"http", []byte("GET / HTTP/1.1\r\n"), ErrNoHeader},
		{"almost v1", []byte("PROXX TCP4"), ErrNoHeader},
		{"almost v2", []byte("\r\n\r\n\x00\r\nQUIX"), ErrNoHeader},
		{"v1 fields", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 1\r\n"), ErrMalformed},
		{"v1 address", []byte("PROXY TCP4 1.1.1 2.2.2.2 1 2\r\n"), ErrMalformed},
		{"v1 port sign", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 +1 2\r\n"), ErrMalformed},
		{"v1 port range", []byte("PROXY UDP4 1.1.1.1 2.2.2.2 65536 2\r\n"), ErrMalformed},
		{"v1 too long", []byte("PROXY TCP4 " + strings.Repeat("1", 300)), ErrMalformed},
	}
	for _, tt := range tests {
		if h, n, err := Parse(tt.in); !errors.Is(err, tt.want) || h != nil || n != 0 {
			t.Errorf("%s: Parse() = %v, %d, %v; want %v", tt.name, h, n, err, tt.want)
		}
	}

	valid := [][]byte{
		[]byte("PROXY TCP4 192.0.2.1 198.51.100.1 5000 443\r\n"),
		V2Header(tcp("2001:db8::1", 1), tcp("2001:db8::2", 2)),
	}
	for _, wire := range valid {
		for i := range len(wire) {
			if _, _, err := Parse(wire[:i]); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("Parse(%q) error = %v, want %v", wire[:i], err, io.ErrUnexpectedEOF)
			}
		}
	}
}

// TestParseLenient covers headers from non-standard senders that are
// accepted because they leave no doubt about the addresses, or fall back to
// the connection's own.
func TestParseLenient(t *testing.T) {
	addrs := append(net.ParseIP("192.0.2.1").To4(), 198, 51, 100, 1, 0x13, 0x88, 0x01, 0xbb)
	tlv := []byte{byte(TLVAuthority), 0, 1, 'a'}
	tests := []struct {
		name     string
		in       []byte
		src, dst string
		local    bool
		udp      bool
		tlvs     int
	}{
		{"v1 lf only", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 1 2\n"), "1.1.1.1:1", "2.2.2.2:2", false, false, 0},
		{"v1 spacing case padding", []byte("PROXY  tcp4   1.1.1.1  2.2.2.2  01  00002 \r\n"), "1.1.1.1:1", "2.2.2.2:2", false, false, 0},
		{"v1 family", []byte("PROXY TCP4 ::1 2.2.2.2 1 2\r\n"), "[::1]:1", "2.2.2.2:2", false, false, 0},
		{"v1 zone", []byte("PROXY TCP6 fe80::1%eth0 ::1 1 2\r\n"), "[fe80::1%eth0]:1", "[::1]:2", false, false, 0},
		{"v1 udp4", []byte("PROXY UDP4 1.1.1.1 2.2.2.2 1 2\r\n"), "1.1.1.1:1", "2.2.2.2:2", false, true, 0},
		{"v1 udp6", []byte("PROXY UDP6 ::1 ::2 1 2\r\n"), "[::1]:1", "[::2]:2", false, true, 0},
		{"v1 extra fields", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 1 2 x y\r\n"), "1.1.1.1:1", "2.2.2.2:2", false, false, 0},
		{"v1 padded line", []byte("PROXY TCP6 1.1.1.1 2.2.2.2 1 2" + strings.Repeat(" ", 150) + "\r\n"), "1.1.1.1:1", "2.2.2.2:2", false, false, 0},
		{"v1 unknown protocol", []byte("PROXY SCTP4 1.1.1.1 2.2.2.2 1 2\r\n"), "", "", true, false, 0},
		{"v1 no protocol", []byte("PROXY \r\n"), "", "", true, false, 0},
		{"v2 version", v2Wire(0x11, 0x11, addrs...), "192.0.2.1:5000", "198.51.100.1:443", false, false, 0},
		{"v2 command", v2Wire(0x22, 0x11, append(addrs, tlv...)...), "", "", true, false, 1},
		{"v2 family", v2Wire(0x21, 0x41, addrs...), "", "", false, false, 0},
		{"v2 transport", v2Wire(0x21, 0x13, append(addrs, tlv...)...), "", "", false, false, 1},
		{"v2 unspec transport", v2Wire(0x21, 0x10, addrs...), "", "", false, false, 0},
		{"v2 short addresses", v2Wire(0x21, 0x21, addrs...), "", "", false, false, 0},
		{"v2 truncated tlv", v2Wire(0x21, 0x12, append(append(addrs, tlv...), 1, 0, 5, 'x')...), "192.0.2.1:5000", "198.51.100.1:443", false, true, 1},
		{"v2 tlv header", v2Wire(0x21, 0x11, append(addrs, 1, 0)...), "192.0.2.1:5000", "198.51.100.1:443", false, false, 0},
	}
	for _, tt := range tests {
		h, n, err := Parse(append(tt.in, "rest"...))
		if err != nil || n != len(tt.in) {
			t.Errorf("%s: Parse() = %d, %v; want %d bytes", tt.name, n, err, len(tt.in))
			continue
		}
		if h.Local != tt.local || addrString(h.Source) != tt.src || addrString(h.Destination) != tt.dst || len(h.TLVs) != tt.tlvs {
			t.Errorf("%s: Parse() = local %v, %v -> %v, %d TLVs; want local %v, %s -> %s, %d TLVs",
				tt.name, h.Local, h.Source, h.Destination, len(h.TLVs), tt.local, tt.src, tt.dst, tt.tlvs)
		}
		if _, isUDP := h.Source.(*net.UDPAddr); tt.src != "" && isUDP != tt.udp {
			t.Errorf("%s: Source is %T", tt.name, h.Source)
		}
	}
}

func TestHeaderUDPAddrs(t *testing.T) {
	h, _, err := Parse(V1Header(udp("192.0.2.1", 5000), udp("198.51.100.1", 19132)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Source.(*net.TCPAddr); !ok {
		t.Fatalf("version 1 Source = %T, want *net.TCPAddr", h.Source)
	}
	src, dst := h.UDPAddrs()
	if s, ok := src.(*net.UDPAddr); !ok || s.String() != "192.0.2.1:5000" {
		t.Fatalf("UDPAddrs() source = %#v", src)
	}
	if d, ok := dst.(*net.UDPAddr); !ok || d.String() != "198.51.100.1:19132" {
		t.Fatalf("UDPAddrs() destination = %#v", dst)
	}
	unix := &net.UnixAddr{Name: "/a", Net: "unixgram"}
	if src, dst := (&Header{Source: unix}).UDPAddrs(); src != unix || dst != nil {
		t.Fatalf("UDPAddrs() = %v, %v; want the unix address and nil", src, dst)
	}
}

func TestRead(t *testing.T) {
	header := V1Header(tcp("192.0.2.1", 5000), tcp("198.51.100.1", 443))
	r := bufio.NewReader(bytes.NewReader(append(header, "hello"...)))
	h, err := Read(r)
	if err != nil || h.Source.String() != "192.0.2.1:5000" {
		t.Fatalf("Read() = %v, %v", h, err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "hello" {
		t.Fatalf("rest = %q", rest)
	}

	// Without a header nothing is consumed.
	r = bufio.NewReader(strings.NewReader("SSH-2.0-test\r\n"))
	if _, err := Read(r); !errors.Is(err, ErrNoHeader) {
		t.Fatalf("Read(ssh) error = %v", err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "SSH-2.0-test\r\n" {
		t.Fatalf("rest = %q", rest)
	}

	// A version 2 header larger than the reader's buffer.
	big := &Header{Version: V2, Source: tcp("192.0.2.1", 1), Destination: tcp("192.0.2.2", 2), TLVs: []TLV{{Type: TLVUniqueID, Value: bytes.Repeat([]byte("u"), 1000)}}}
	wire, _ := big.AppendBinary(nil)
	r = bufio.NewReaderSize(bytes.NewReader(append(wire, "x"...)), 64)
	if h, err := Read(r); err != nil || len(h.TLVs) != 1 || len(h.TLVs[0].Value) != 1000 {
		t.Fatalf("Read(big) = %v, %v", h, err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "x" {
		t.Fatalf("rest = %q", rest)
	}

	for in, want := range map[string]error{
		"":                  io.EOF,
		"PROX":              io.ErrUnexpectedEOF,
		"PROXY TCP4 1.1.1.": io.ErrUnexpectedEOF,
		"PROXY TCP4 x\r\n":  ErrMalformed,
	} {
		if _, err := Read(bufio.NewReader(strings.NewReader(in))); !errors.Is(err, want) {
			t.Errorf("Read(%q) error = %v, want %v", in, err, want)
		}
	}
	if _, err := Read(bufio.NewReaderSize(strings.NewReader("PROXY UNKNOWN"+strings.Repeat(" ", 50)+"\r\n"), 16)); err == nil {
		t.Fatal("Read() with a 16-byte buffer parsed a long version 1 header")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("PROXY TCP4 192.0.2.1 198.51.100.1 5000 443\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add([]byte("PROXY udp6 fe80::1%eth0 ::ffff:1.2.3.4 01 2\n"))
	f.Add(v2Wire(0x21, 0x12, append(make([]byte, 12), 1, 0, 5, 'x')...))
	f.Add([]byte("PROXY TCP4 ::1 2.2.2.2 1 2\r\n"))
	f.Add(V2Header(tcp("2001:db8::1", 1), tcp("2001:db8::2", 2)))
	f.Add(V2Header(&net.UnixAddr{Name: "/a", Net: "unix"}, &net.UnixAddr{Name: "/b", Net: "unix"}))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, n, err := Parse(b)
		if err != nil {
			return
		}
		if n <= 0 || n > len(b) {
			t.Fatalf("Parse() length %d of %d bytes", n, len(b))
		}
		if h.Version == V1 && len(h.TLVs) > 0 {
			t.Fatal("version 1 header with TLVs")
		}
		wire, err := h.AppendBinary(nil)
		if err != nil {
			t.Fatalf("AppendBinary() error = %v", err)
		}
		h2, _, err := Parse(wire)
		// A PROXY command without addresses is re-encoded as LOCAL; both mean
		// that the connection's own addresses apply. Zones are not encoded.
		sameLocal := h2.Local == h.Local || h.Source == nil
		if err != nil || !sameLocal || addrKey(h2.Source) != addrKey(h.Source) || addrKey(h2.Destination) != addrKey(h.Destination) || len(h2.TLVs) != len(h.TLVs) {
			t.Fatalf("round trip of %q = %+v, %v; want %+v", b, h2, err, h)
		}
	})
}

// addrKey identifies an address the way an encoded header does: without the
// IPv6 zone, the IPv4-mapped form of mixed families and the TCP or UDP type
// of version 1.
func addrKey(a net.Addr) string {
	switch a := a.(type) {
	case *net.TCPAddr:
		return netip.AddrPortFrom(a.AddrPort().Addr().Unmap().WithZone(""), uint16(a.Port)).String()
	case *net.UDPAddr:
		return netip.AddrPortFrom(a.AddrPort().Addr().Unmap().WithZone(""), uint16(a.Port)).String()
	}
	return addrString(a)
}

func TestTLVTypeString(t *testing.T) {
	names := map[TLVType]string{
		TLVALPN: "ALPN", TLVAuthority: "AUTHORITY", TLVCRC32C: "CRC32C", TLVNoop: "NOOP",
		TLVUniqueID: "UNIQUE_ID", TLVSSL: "SSL", TLVNetNS: "NETNS", 0xe0: "0xe0",
	}
	for typ, want := range names {
		if got := typ.String(); got != want {
			t.Errorf("TLVType(0x%02x).String() = %q, want %q", byte(typ), got, want)
		}
	}
}
