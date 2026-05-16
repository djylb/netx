package netx

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestPublicConnectionHelpers(t *testing.T) {
	parsed, err := ParseTCPAddr("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("ParseTCPAddr() error = %v", err)
	}
	if parsed.String() != "127.0.0.1:8080" {
		t.Fatalf("ParseTCPAddr() = %q, want %q", parsed.String(), "127.0.0.1:8080")
	}

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	local := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 8080}
	baseConn := &countedCloseConn{}
	overridden := NewAddrOverrideConn(baseConn, remote, local)
	if got := RawConnOf(overridden); got != baseConn {
		t.Fatalf("RawConnOf() = %v, want base conn", got)
	}
	header := ProxyProtocolHeader(overridden, ProxyProtocolV1)
	if string(header) != "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n" {
		t.Fatalf("ProxyProtocolHeader() = %q", string(header))
	}

	stringRemote, err := ParseTCPAddr("203.0.113.10:443")
	if err != nil {
		t.Fatalf("ParseTCPAddr(remote) error = %v", err)
	}
	stringOverride := NewAddrOverrideConn(&countedCloseConn{}, stringRemote, nil)
	if stringOverride.RemoteAddr().String() != "203.0.113.10:443" {
		t.Fatalf("RemoteAddr() = %q", stringOverride.RemoteAddr().String())
	}

	base := &countedCloseConn{}
	chain := NewFramedConn(NewTimeoutConn(NewTeeConn(base), time.Second))
	if got := RawConnOf(chain); got != base {
		t.Fatalf("RawConnOf(wrapper chain) = %v, want base conn", got)
	}

	wrapped := WrapConn(base, base)
	if err := wrapped.Close(); err != nil {
		t.Fatalf("WrapConn Close() error = %v", err)
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
