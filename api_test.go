package netx

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestPublicConnectionHelpers(t *testing.T) {
	parsed := ParseAddr("127.0.0.1:8080")
	if parsed.String() != "127.0.0.1:8080" {
		t.Fatalf("ParseAddr() = %q, want %q", parsed.String(), "127.0.0.1:8080")
	}

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	local := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 8080}
	overridden := NewAddrOverrideFromAddr(&countedCloseConn{}, remote, local)
	header := BuildProxyProtocolHeader(overridden, 1)
	if string(header) != "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n" {
		t.Fatalf("BuildProxyProtocolHeader() = %q", string(header))
	}

	stringOverride, err := NewAddrOverrideConn(&countedCloseConn{}, "203.0.113.10:443", "127.0.0.1:80")
	if err != nil {
		t.Fatalf("NewAddrOverrideConn() error = %v", err)
	}
	if stringOverride.RemoteAddr().String() != "203.0.113.10:443" {
		t.Fatalf("RemoteAddr() = %q", stringOverride.RemoteAddr().String())
	}

	base := &countedCloseConn{}
	wrapped := WrapConnWithoutParentClose(base, base)
	if err := wrapped.Close(); err != nil {
		t.Fatalf("WrapConnWithoutParentClose Close() error = %v", err)
	}
	if calls := base.Calls(); calls != 1 {
		t.Fatalf("base Close() calls = %d, want 1", calls)
	}

	tee := NewTeeConn(&teeTestConn{readBuf: bytes.NewBufferString("xy")}, 1)
	buf := make([]byte, 2)
	n, err := tee.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("NewTeeConn Read() error = %v", err)
	}
	if n != 2 || string(tee.Buffered()) != "x" {
		t.Fatalf("tee read = %d buffered=%q, want 2 and %q", n, string(tee.Buffered()), "x")
	}
}
