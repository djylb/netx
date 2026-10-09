package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
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

func TestParseErrors(t *testing.T) {
	v2 := func(verCmd, fam byte, body ...byte) []byte {
		b := append([]byte(v2Signature), verCmd, fam, byte(len(body)>>8), byte(len(body)))
		return append(b, body...)
	}
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"http", []byte("GET / HTTP/1.1\r\n"), ErrNoHeader},
		{"almost v1", []byte("PROXX TCP4"), ErrNoHeader},
		{"almost v2", []byte("\r\n\r\n\x00\r\nQUIX"), ErrNoHeader},
		{"v1 protocol", []byte("PROXY TCP5 1.1.1.1 2.2.2.2 1 2\r\n"), ErrMalformed},
		{"v1 lf only", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 1 2\n"), ErrMalformed},
		{"v1 fields", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 1\r\n"), ErrMalformed},
		{"v1 family", []byte("PROXY TCP4 ::1 2.2.2.2 1 2\r\n"), ErrMalformed},
		{"v1 port zero padded", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 01 2\r\n"), ErrMalformed},
		{"v1 port sign", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 +1 2\r\n"), ErrMalformed},
		{"v1 port range", []byte("PROXY TCP4 1.1.1.1 2.2.2.2 65536 2\r\n"), ErrMalformed},
		{"v1 too long", []byte("PROXY TCP4 " + strings.Repeat("1", 100)), ErrMalformed},
		{"v2 version", v2(0x31, 0x11, make([]byte, 12)...), ErrMalformed},
		{"v2 command", v2(0x22, 0x11, make([]byte, 12)...), ErrMalformed},
		{"v2 family", v2(0x21, 0x41, make([]byte, 12)...), ErrMalformed},
		{"v2 short addresses", v2(0x21, 0x21, make([]byte, 12)...), ErrMalformed},
		{"v2 truncated tlv", v2(0x21, 0x11, append(make([]byte, 12), 1, 0, 5, 'x')...), ErrMalformed},
		{"v2 tlv header", v2(0x21, 0x11, append(make([]byte, 12), 1, 0)...), ErrMalformed},
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
		"PROXY TCP9 x\r\n":  ErrMalformed,
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
		// that the connection's own addresses apply.
		sameLocal := h2.Local == h.Local || h.Source == nil
		if err != nil || !sameLocal || addrString(h2.Source) != addrString(h.Source) || addrString(h2.Destination) != addrString(h.Destination) || len(h2.TLVs) != len(h.TLVs) {
			t.Fatalf("round trip of %q = %+v, %v; want %+v", b, h2, err, h)
		}
	})
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
