package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestAddrEncoding(t *testing.T) {
	tests := []struct {
		name string
		addr Addr
		wire []byte
		str  string
	}{
		{"ipv4", Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 80}, []byte{1, 192, 0, 2, 1, 0, 80}, "192.0.2.1:80"},
		{"mapped ipv4", Addr{IP: netip.MustParseAddr("::ffff:192.0.2.1"), Port: 80}, []byte{1, 192, 0, 2, 1, 0, 80}, "192.0.2.1:80"},
		{"ipv6", Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
			append(append([]byte{4}, netip.MustParseAddr("2001:db8::1").AsSlice()...), 1, 187), "[2001:db8::1]:443"},
		{"domain", Addr{Name: "example.com", Port: 8080}, append(append([]byte{3, 11}, "example.com"...), 0x1f, 0x90), "example.com:8080"},
		{"zero", Addr{}, []byte{1, 0, 0, 0, 0, 0, 0}, "0.0.0.0:0"},
		{"ip wins over name", Addr{IP: netip.MustParseAddr("10.0.0.1"), Name: "ignored", Port: 1}, []byte{1, 10, 0, 0, 1, 0, 1}, "10.0.0.1:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.addr.AppendBinary(nil)
			if err != nil || !bytes.Equal(got, tt.wire) {
				t.Fatalf("AppendBinary() = %v, %v; want %v", got, err, tt.wire)
			}
			if s := tt.addr.String(); s != tt.str {
				t.Fatalf("String() = %q, want %q", s, tt.str)
			}
			decoded, err := ReadAddr(bytes.NewReader(tt.wire))
			if err != nil {
				t.Fatalf("ReadAddr() error = %v", err)
			}
			if decoded.String() != tt.str {
				t.Fatalf("ReadAddr() = %v, want %s", decoded, tt.str)
			}
		})
	}

	if _, err := (Addr{Name: strings.Repeat("a", 256)}).AppendBinary(nil); !errors.Is(err, ErrInvalidAddr) {
		t.Fatalf("AppendBinary(long name) error = %v", err)
	}
}

func TestReadAddrErrors(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{"unknown type", []byte{2, 0, 0, 0}, ErrAddrType},
		{"empty domain", []byte{3, 0, 0, 80}, ErrMalformed},
		{"truncated ipv4", []byte{1, 127, 0}, io.ErrUnexpectedEOF},
		{"truncated domain", []byte{3, 5, 'a', 'b'}, io.ErrUnexpectedEOF},
		{"one byte", []byte{1}, io.ErrUnexpectedEOF},
		{"empty", nil, io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		if _, err := ReadAddr(bytes.NewReader(tt.wire)); !errors.Is(err, tt.want) {
			t.Errorf("%s: ReadAddr() error = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestAddrConversions(t *testing.T) {
	tests := []struct {
		in   net.Addr
		want string
	}{
		{nil, "0.0.0.0:0"},
		{(*net.TCPAddr)(nil), "0.0.0.0:0"},
		{&net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 22}, "192.0.2.9:22"},
		{&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 53, Zone: "eth0"}, "[fe80::1]:53"},
		{&net.UDPAddr{Port: 53}, "0.0.0.0:53"},
		{dummyAddr("host.example:99"), "host.example:99"},
		{dummyAddr("pipe"), "0.0.0.0:0"},
	}
	for _, tt := range tests {
		if got := AddrFromNetAddr(tt.in).String(); got != tt.want {
			t.Errorf("AddrFromNetAddr(%v) = %s, want %s", tt.in, got, tt.want)
		}
	}

	for in, want := range map[string]string{
		"[::ffff:1.2.3.4]:5":    "1.2.3.4:5",
		"[fe80::1%eth0]:6":      "[fe80::1]:6",
		"example.com:443":       "example.com:443",
		"[2001:db8::2]:65535":   "[2001:db8::2]:65535",
		"localhost:0":           "localhost:0",
		"xn--bcher-kva.ch:8443": "xn--bcher-kva.ch:8443",
	} {
		addr, err := ParseAddr(in)
		if err != nil || addr.String() != want {
			t.Errorf("ParseAddr(%q) = %v, %v; want %s", in, addr, err, want)
		}
	}
	for _, in := range []string{"", "example.com", ":80", "host:65536", "host:-1", strings.Repeat("a", 256) + ":1"} {
		if _, err := ParseAddr(in); !errors.Is(err, ErrInvalidAddr) {
			t.Errorf("ParseAddr(%q) error = %v, want %v", in, err, ErrInvalidAddr)
		}
	}
}

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

func TestHandshakeRoundTrip(t *testing.T) {
	var wire bytes.Buffer

	if err := WriteMethods(&wire, MethodNoAuth, MethodUserPass); err != nil {
		t.Fatal(err)
	}
	methods, err := ReadMethods(&wire)
	if err != nil || len(methods) != 2 || methods[0] != MethodNoAuth || methods[1] != MethodUserPass {
		t.Fatalf("ReadMethods() = %v, %v", methods, err)
	}

	if err := WriteMethod(&wire, MethodUserPass); err != nil {
		t.Fatal(err)
	}
	if m, err := ReadMethod(&wire); err != nil || m != MethodUserPass {
		t.Fatalf("ReadMethod() = %v, %v", m, err)
	}
	if err := WriteMethod(&wire, MethodNoAcceptable); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMethod(&wire); !errors.Is(err, ErrNoAcceptableMethod) {
		t.Fatalf("ReadMethod(no acceptable) error = %v", err)
	}

	user, pass := strings.Repeat("u", 255), "p@ss"
	if err := WriteUserPass(&wire, user, pass); err != nil {
		t.Fatal(err)
	}
	if u, p, err := ReadUserPass(&wire); err != nil || u != user || p != pass {
		t.Fatalf("ReadUserPass() = %q, %q, %v", u, p, err)
	}
	if err := WriteUserPass(&wire, "", ""); err != nil {
		t.Fatal(err)
	}
	if u, p, err := ReadUserPass(&wire); err != nil || u != "" || p != "" {
		t.Fatalf("ReadUserPass(empty) = %q, %q, %v", u, p, err)
	}
	if err := WriteUserPass(&wire, strings.Repeat("u", 256), ""); !errors.Is(err, ErrMalformed) {
		t.Fatalf("WriteUserPass(long) error = %v", err)
	}

	for _, ok := range []bool{true, false} {
		if err := WriteUserPassStatus(&wire, ok); err != nil {
			t.Fatal(err)
		}
		err := ReadUserPassStatus(&wire)
		if ok && err != nil || !ok && !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("ReadUserPassStatus(%v) error = %v", ok, err)
		}
	}

	dst := Addr{Name: "example.com", Port: 443}
	if err := WriteRequest(&wire, CmdConnect, dst); err != nil {
		t.Fatal(err)
	}
	if cmd, addr, err := ReadRequest(&wire); err != nil || cmd != CmdConnect || addr != dst {
		t.Fatalf("ReadRequest() = %v, %v, %v", cmd, addr, err)
	}

	bound := Addr{IP: netip.MustParseAddr("198.51.100.1"), Port: 1080}
	if err := WriteReply(&wire, ReplySucceeded, bound); err != nil {
		t.Fatal(err)
	}
	if addr, err := ReadReply(&wire); err != nil || addr != bound {
		t.Fatalf("ReadReply() = %v, %v", addr, err)
	}
	if err := WriteReply(&wire, ReplyConnectionRefused, Addr{}); err != nil {
		t.Fatal(err)
	}
	_, err = ReadReply(&wire)
	var replyErr *ReplyError
	if !errors.As(err, &replyErr) || replyErr.Reply != ReplyConnectionRefused {
		t.Fatalf("ReadReply(refused) error = %v", err)
	}
	if err.Error() != "socks5: connection refused" {
		t.Fatalf("ReplyError text = %q", err.Error())
	}
	if wire.Len() != 0 {
		t.Fatalf("%d unread bytes left", wire.Len())
	}
}

func TestMessageErrors(t *testing.T) {
	read := func(b ...byte) io.Reader { return bytes.NewReader(b) }
	if _, err := ReadMethods(read(4, 1, 0)); !errors.Is(err, ErrVersion) {
		t.Errorf("ReadMethods(v4) error = %v", err)
	}
	if _, err := ReadMethods(read(5, 2, 0)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadMethods(short) error = %v", err)
	}
	if _, err := ReadMethods(read()); !errors.Is(err, io.EOF) {
		t.Errorf("ReadMethods(empty) error = %v", err)
	}
	if methods, err := ReadMethods(read(5, 0)); err != nil || len(methods) != 0 {
		t.Errorf("ReadMethods(none) = %v, %v", methods, err)
	}
	if err := WriteMethods(io.Discard); !errors.Is(err, ErrMalformed) {
		t.Errorf("WriteMethods() error = %v", err)
	}
	if _, err := ReadMethod(read(4, 0)); !errors.Is(err, ErrVersion) {
		t.Errorf("ReadMethod(v4) error = %v", err)
	}
	// Lenient for non-standard peers: sub-negotiation versions and the
	// reserved byte are not checked.
	if u, p, err := ReadUserPass(read(5, 1, 'u', 1, 'p')); err != nil || u != "u" || p != "p" {
		t.Errorf("ReadUserPass(v5) = %q, %q, %v", u, p, err)
	}
	if _, _, err := ReadUserPass(read(1, 3, 'a')); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadUserPass(short) error = %v", err)
	}
	if err := ReadUserPassStatus(read(5, 0)); err != nil {
		t.Errorf("ReadUserPassStatus(v5) error = %v", err)
	}
	if err := ReadUserPassStatus(read(5, 0xff)); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("ReadUserPassStatus(failure) error = %v", err)
	}
	if _, _, err := ReadRequest(read(4, 1, 0, 1, 0, 0, 0, 0, 0, 0)); !errors.Is(err, ErrVersion) {
		t.Errorf("ReadRequest(v4) error = %v", err)
	}
	if cmd, _, err := ReadRequest(read(5, 1, 1, 1, 0, 0, 0, 0, 0, 0)); err != nil || cmd != CmdConnect {
		t.Errorf("ReadRequest(rsv) = %v, %v", cmd, err)
	}
	if _, _, err := ReadRequest(read(5, 1, 0, 9)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadRequest(short) error = %v", err)
	}
	if _, _, err := ReadRequest(read(5, 1, 0, 9, 0)); !errors.Is(err, ErrAddrType) {
		t.Errorf("ReadRequest(atyp) error = %v", err)
	}
	if cmd, _, err := ReadRequest(read(5, 9, 0, 1, 0, 0, 0, 0, 0, 0)); err != nil || cmd != 9 {
		t.Errorf("ReadRequest(unknown command) = %v, %v", cmd, err)
	}
	if _, err := ReadReply(read(4, 0, 0, 1, 0, 0, 0, 0, 0, 0)); !errors.Is(err, ErrVersion) {
		t.Errorf("ReadReply(v4) error = %v", err)
	}
	if err := WriteRequest(io.Discard, CmdConnect, Addr{Name: strings.Repeat("a", 256)}); !errors.Is(err, ErrInvalidAddr) {
		t.Errorf("WriteRequest(long name) error = %v", err)
	}
	if err := WriteMethod(shortWriter{}, MethodNoAuth); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("WriteMethod(short writer) error = %v", err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) / 2, nil }

func TestDatagram(t *testing.T) {
	dst := Addr{IP: netip.MustParseAddr("203.0.113.5"), Port: 53}
	payload := []byte("query")
	packet, err := AppendDatagram(make([]byte, 0, 64), dst, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0, 0, 0, 1, 203, 0, 113, 5, 0, 53}, payload...)
	if !bytes.Equal(packet, want) {
		t.Fatalf("AppendDatagram() = %v, want %v", packet, want)
	}
	addr, data, err := ParseDatagram(packet)
	if err != nil || addr != dst || !bytes.Equal(data, payload) {
		t.Fatalf("ParseDatagram() = %v, %q, %v", addr, data, err)
	}

	// Senders that put the payload length in the reserved field are accepted.
	withLength := append([]byte{0, 5}, packet[2:]...)
	if _, data, err := ParseDatagram(withLength); err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("ParseDatagram(rsv length) = %q, %v", data, err)
	}
	if _, data, err := ParseDatagram(packet[:10]); err != nil || len(data) != 0 {
		t.Fatalf("ParseDatagram(empty payload) = %q, %v", data, err)
	}
	if _, _, err := ParseDatagram([]byte{0, 0, 1, 1, 0, 0, 0, 0, 0, 0}); !errors.Is(err, ErrFragmented) {
		t.Fatalf("ParseDatagram(fragment) error = %v", err)
	}
	for _, short := range [][]byte{nil, {0, 0}, {0, 0, 0}, {0, 0, 0, 1, 1, 2}, {0, 0, 0, 3, 4, 'a'}} {
		if _, _, err := ParseDatagram(short); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseDatagram(%v) error = %v, want %v", short, err, ErrMalformed)
		}
	}
	if _, _, err := ParseDatagram([]byte{0, 0, 0, 7, 0}); !errors.Is(err, ErrAddrType) {
		t.Fatalf("ParseDatagram(atyp) error = %v", err)
	}

	prefix := []byte("keep")
	if got, err := AppendDatagram(prefix, Addr{Name: strings.Repeat("a", 256)}, payload); !errors.Is(err, ErrInvalidAddr) || string(got) != "keep" {
		t.Fatalf("AppendDatagram(long name) = %q, %v", got, err)
	}
	long := Addr{Name: strings.Repeat("a", 255), Port: 1}
	header, _ := AppendDatagram(nil, long, nil)
	if len(header) != MaxDatagramHeaderLen {
		t.Fatalf("longest header = %d bytes, want %d", len(header), MaxDatagramHeaderLen)
	}
}

func TestStrings(t *testing.T) {
	for _, tt := range []struct{ got, want string }{
		{CmdConnect.String(), "connect"},
		{CmdBind.String(), "bind"},
		{CmdUDPAssociate.String(), "udp associate"},
		{Command(9).String(), "command 9"},
		{MethodNoAuth.String(), "no authentication"},
		{MethodGSSAPI.String(), "gssapi"},
		{MethodUserPass.String(), "username/password"},
		{MethodNoAcceptable.String(), "no acceptable methods"},
		{Method(9).String(), "method 9"},
		{ReplyTTLExpired.String(), "TTL expired"},
		{Reply(42).String(), "reply 42"},
		{Reply4Rejected.String(), "request rejected or failed"},
	} {
		if tt.got != tt.want {
			t.Errorf("String() = %q, want %q", tt.got, tt.want)
		}
	}
	named := []Reply{Reply4Granted, Reply4Rejected, Reply4IdentdUnreached, Reply4IdentdMismatch}
	for r := ReplySucceeded; r <= ReplyAddrTypeNotSupported; r++ {
		named = append(named, r)
	}
	for _, r := range named {
		if strings.HasPrefix(r.String(), "reply ") {
			t.Errorf("Reply(%d) has no name", r)
		}
	}
}

func FuzzParseDatagram(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 'x'})
	f.Add([]byte{0, 0, 0, 3, 3, 'a', 'b', 'c', 0, 80})
	f.Add([]byte{0, 0, 0, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		addr, payload, err := ParseDatagram(b)
		if err != nil {
			return
		}
		again, err := AppendDatagram(nil, addr, payload)
		if err != nil {
			t.Fatalf("AppendDatagram() error = %v", err)
		}
		addr2, payload2, err := ParseDatagram(again)
		if err != nil || addr2.String() != addr.String() || !bytes.Equal(payload, payload2) {
			t.Fatalf("round trip = %v, %q, %v; want %v, %q", addr2, payload2, err, addr, payload)
		}
	})
}

func FuzzReadRequest(f *testing.F) {
	f.Add([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{5, 1, 0, 3, 1, 'a', 0, 80})
	f.Fuzz(func(t *testing.T, b []byte) {
		cmd, addr, err := ReadRequest(bytes.NewReader(b))
		if err != nil {
			return
		}
		var wire bytes.Buffer
		if err := WriteRequest(&wire, cmd, addr); err != nil {
			t.Fatalf("WriteRequest() error = %v", err)
		}
		cmd2, addr2, err := ReadRequest(&wire)
		if err != nil || cmd2 != cmd || addr2.String() != addr.String() {
			t.Fatalf("round trip = %v, %v, %v", cmd2, addr2, err)
		}
	})
}

func TestDecodeAddr(t *testing.T) {
	wire := append([]byte{3, 7}, "example80rest"...)
	wire[9], wire[10] = 0, 80
	addr, n, err := DecodeAddr(wire)
	if err != nil || n != 11 || addr != (Addr{Name: "example", Port: 80}) {
		t.Fatalf("DecodeAddr() = %v, %d, %v", addr, n, err)
	}
	for _, bad := range [][]byte{nil, {1, 127, 0, 0, 1, 0}, {4}, {3, 0, 0, 80}} {
		if _, _, err := DecodeAddr(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("DecodeAddr(%v) error = %v, want %v", bad, err, ErrMalformed)
		}
	}
	if _, _, err := DecodeAddr([]byte{2, 0}); !errors.Is(err, ErrAddrType) {
		t.Errorf("DecodeAddr(atyp 2) error = %v, want %v", err, ErrAddrType)
	}
}
