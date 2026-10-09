package socks5

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

func TestSOCKS4RoundTrip(t *testing.T) {
	for _, dst := range []Addr{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 80},
		{IP: netip.MustParseAddr("::ffff:192.0.2.1"), Port: 81}, // sent as IPv4
		{Name: "example.com", Port: 443},
	} {
		var buf bytes.Buffer
		if err := WriteRequest4(&buf, CmdConnect, dst, "alice"); err != nil {
			t.Fatalf("WriteRequest4(%v) error = %v", dst, err)
		}
		buf.WriteString("payload")
		cmd, got, user, err := ReadRequest4(&buf)
		if err != nil || cmd != CmdConnect || user != "alice" || got.String() != dst.String() {
			t.Fatalf("ReadRequest4() = %v, %v, %q, %v; want %v", cmd, got, user, err, dst)
		}
		if rest := buf.String(); rest != "payload" {
			t.Fatalf("ReadRequest4 consumed %q", rest)
		}
	}

	var buf bytes.Buffer
	bound := Addr{IP: netip.MustParseAddr("198.51.100.1"), Port: 1080}
	if err := WriteReply4(&buf, ReplySucceeded, bound); err != nil {
		t.Fatal(err)
	}
	if b := buf.Bytes(); b[0] != 0 || Reply(b[1]) != Reply4Granted {
		t.Fatalf("WriteReply4(ReplySucceeded) = % x", b)
	}
	if got, err := ReadReply4(&buf); err != nil || got != bound {
		t.Fatalf("ReadReply4() = %v, %v", got, err)
	}
	for in, want := range map[Reply]Reply{
		ReplyConnectionRefused: Reply4Rejected,
		Reply4IdentdMismatch:   Reply4IdentdMismatch,
	} {
		buf.Reset()
		_ = WriteReply4(&buf, in, Addr{IP: netip.MustParseAddr("::1")})
		_, err := ReadReply4(&buf)
		var replyErr *ReplyError
		if !errors.As(err, &replyErr) || replyErr.Reply != want {
			t.Errorf("reply %v read as %v, want %v", in, err, want)
		}
	}
	// Servers that send version 4 instead of 0 are accepted.
	if _, err := ReadReply4(bytes.NewReader([]byte{4, 90, 0, 0, 0, 0, 0, 0})); err != nil {
		t.Fatalf("ReadReply4(version 4) error = %v", err)
	}
}

func TestSOCKS4Errors(t *testing.T) {
	ipv6 := Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 1}
	if err := WriteRequest4(io.Discard, CmdConnect, ipv6, ""); !errors.Is(err, ErrAddrType) {
		t.Errorf("IPv6 error = %v, want %v", err, ErrAddrType)
	}
	for _, tt := range []struct {
		dst  Addr
		user string
	}{
		{Addr{Port: 1}, ""},
		{Addr{Name: "a\x00b", Port: 1}, ""},
		{Addr{Name: strings.Repeat("a", 256), Port: 1}, ""},
		{Addr{Name: "a", Port: 1}, "u\x00"},
		{Addr{Name: "a", Port: 1}, strings.Repeat("u", 1024)},
	} {
		if err := WriteRequest4(io.Discard, CmdConnect, tt.dst, tt.user); !errors.Is(err, ErrMalformed) {
			t.Errorf("WriteRequest4(%q, %q) error = %v, want %v", tt.dst.Name, tt.user, err, ErrMalformed)
		}
	}

	for in, want := range map[string]error{
		"":                                         io.EOF,
		"\x04\x01\x00\x50":                         io.ErrUnexpectedEOF,
		"\x05\x01\x00\x50\x01\x02\x03\x04\x00":     ErrVersion,
		"\x04\x01\x00\x50\x01\x02\x03\x04u":        io.ErrUnexpectedEOF,
		"\x04\x01\x00\x50\x00\x00\x00\x01\x00":     io.ErrUnexpectedEOF,
		"\x04\x01\x00\x50\x00\x00\x00\x01\x00\x00": ErrMalformed, // empty SOCKS4a name
		"\x04\x01\x00\x50\x01\x02\x03\x04" + strings.Repeat("u", 1024): ErrMalformed,
	} {
		if _, _, _, err := ReadRequest4(strings.NewReader(in)); !errors.Is(err, want) {
			t.Errorf("ReadRequest4(%q) error = %v, want %v", in, err, want)
		}
	}
	if _, err := ReadReply4(strings.NewReader("\x00\x5a\x00")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadReply4(short) error = %v", err)
	}
}

func FuzzReadRequest4(f *testing.F) {
	f.Add([]byte("\x04\x01\x00\x50\x01\x02\x03\x04user\x00"))
	f.Add([]byte("\x04\x01\x00\x50\x00\x00\x00\x01\x00example.com\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		cmd, dst, user, err := ReadRequest4(bytes.NewReader(b))
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if err := WriteRequest4(&buf, cmd, dst, user); err != nil {
			t.Fatalf("WriteRequest4(%v, %v, %q) error = %v", cmd, dst, user, err)
		}
		cmd2, dst2, user2, err := ReadRequest4(&buf)
		if err != nil || cmd2 != cmd || dst2 != dst || user2 != user {
			t.Fatalf("round trip of %q = %v %v %q %v", b, cmd2, dst2, user2, err)
		}
	})
}
