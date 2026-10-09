package proxyproto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// acceptOne returns the server end of one connection accepted by l after the
// client wrote data.
func acceptOne(t *testing.T, l *Listener, data []byte) (server, client net.Conn) {
	t.Helper()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if len(data) > 0 {
		if _, err := client.Write(data); err != nil {
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

func newTestListener(t *testing.T) *Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &Listener{Listener: ln, HeaderTimeout: time.Second}
}

func TestListenerUsesHeader(t *testing.T) {
	l := newTestListener(t)
	header := V2Header(tcp("203.0.113.7", 40000), tcp("198.51.100.1", 443))
	server, _ := acceptOne(t, l, append(header, "hello"...))

	if got := server.RemoteAddr().String(); got != "203.0.113.7:40000" {
		t.Fatalf("RemoteAddr() = %s", got)
	}
	if got := server.LocalAddr().String(); got != "198.51.100.1:443" {
		t.Fatalf("LocalAddr() = %s", got)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(server, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("Read() = %q, %v", buf, err)
	}
	h, err := server.(*Conn).Header()
	if err != nil || h.Version != V2 {
		t.Fatalf("Header() = %v, %v", h, err)
	}
	if _, ok := server.(*Conn).RawConn().(*net.TCPConn); !ok {
		t.Fatal("RawConn() is not the accepted TCP connection")
	}
}

func TestListenerRequiredRejectsMissingHeader(t *testing.T) {
	l := newTestListener(t)
	server, client := acceptOne(t, l, []byte("GET / HTTP/1.1\r\n\r\n"))
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, ErrNoHeader) {
		t.Fatalf("Read() error = %v, want %v", err, ErrNoHeader)
	}
	if got := server.RemoteAddr().String(); got != client.LocalAddr().String() {
		t.Fatalf("RemoteAddr() = %s, want the peer %s", got, client.LocalAddr())
	}
}

func TestListenerOptionalPassesStream(t *testing.T) {
	l := newTestListener(t)
	l.Policy = func(net.Addr) Policy { return Optional }
	server, client := acceptOne(t, l, []byte("PRO"))
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = client.Write([]byte("TOCOL"))
		_ = client.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(server)
	if err != nil || string(got) != "PROTOCOL" {
		t.Fatalf("ReadAll() = %q, %v", got, err)
	}
	if h, err := server.(*Conn).Header(); h != nil || err != nil {
		t.Fatalf("Header() = %v, %v; want none", h, err)
	}
}

func TestListenerIgnore(t *testing.T) {
	l := newTestListener(t)
	l.Policy = func(net.Addr) Policy { return Ignore }
	server, _ := acceptOne(t, l, nil)
	if _, ok := server.(*net.TCPConn); !ok {
		t.Fatalf("Accept() = %T, want the plain connection", server)
	}
}

func TestListenerHeaderTimeoutAndDeadlines(t *testing.T) {
	l := newTestListener(t)
	l.HeaderTimeout = 50 * time.Millisecond
	server, _ := acceptOne(t, l, nil)
	start := time.Now()
	_, err := server.Read(make([]byte, 1))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() || time.Since(start) > 2*time.Second {
		t.Fatalf("Read() error = %v after %v, want a header timeout", err, time.Since(start))
	}

	// A deadline set before the header is read applies afterwards.
	l.HeaderTimeout = time.Second
	header := V1Header(tcp("192.0.2.1", 1), tcp("192.0.2.2", 2))
	server, _ = acceptOne(t, l, header)
	if err := server.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if h, err := server.(*Conn).Header(); err != nil || h.Source.String() != "192.0.2.1:1" {
		t.Fatalf("Header() = %v, %v", h, err)
	}
	if _, err := server.Read(make([]byte, 1)); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read() error = %v, want the caller's past deadline", err)
	}
}

func TestConnWriteTo(t *testing.T) {
	l := newTestListener(t)
	header := V1Header(tcp("192.0.2.1", 1), tcp("192.0.2.2", 2))
	server, client := acceptOne(t, l, append(header, "data"...))
	_ = client.(*net.TCPConn).CloseWrite()
	var out bytes.Buffer
	if n, err := io.Copy(&out, server); err != nil || n != 4 || out.String() != "data" {
		t.Fatalf("io.Copy() = %d, %v, %q", n, err, out.String())
	}
	if err := server.(*Conn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("client Read() error = %v, want EOF", err)
	}
}
