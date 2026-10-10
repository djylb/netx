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

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestListenerCallerDeadlineBoundsHeader(t *testing.T) {
	l := newTestListener(t)
	l.HeaderTimeout = 5 * time.Second
	header := V1Header(tcp("192.0.2.1", 1), tcp("192.0.2.2", 2))
	server, client := acceptOne(t, l, header[:8])

	// A shorter caller deadline ends the header read without failing it.
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	start := time.Now()
	buf := make([]byte, 8)
	if _, err := server.Read(buf); !isTimeout(err) || time.Since(start) > 2*time.Second {
		t.Fatalf("Read() error = %v after %v, want the caller's timeout", err, time.Since(start))
	}
	if _, err := client.Write(append(header[8:], "hi"...)); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Time{})
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "hi" {
		t.Fatalf("resumed Read() = %q, %v", buf[:n], err)
	}
	if got := server.RemoteAddr().String(); got != "192.0.2.1:1" {
		t.Fatalf("RemoteAddr() = %s", got)
	}

	// The header timeout runs from the first attempt and still applies.
	l.HeaderTimeout = 300 * time.Millisecond
	server, _ = acceptOne(t, l, nil)
	_ = server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start = time.Now()
	if _, err := server.Read(buf); !isTimeout(err) {
		t.Fatalf("Read() error = %v, want the caller's timeout", err)
	}
	_ = server.SetReadDeadline(time.Time{})
	if _, err := server.Read(buf); !isTimeout(err) || time.Since(start) > 2*time.Second {
		t.Fatalf("Read() error = %v after %v, want the header timeout", err, time.Since(start))
	}
	// Later reads fail for good, with an error that is not a timeout, so
	// that a loop retrying timeouts does not spin.
	for range 3 {
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := server.Read(buf); isTimeout(err) || !errors.Is(err, ErrNoHeader) {
			t.Fatalf("Read() after the header timeout = %v, want ErrNoHeader and no timeout", err)
		}
	}
	if _, err := server.(*Conn).Header(); isTimeout(err) || !errors.Is(err, ErrNoHeader) {
		t.Fatalf("Header() after the header timeout = %v, want ErrNoHeader and no timeout", err)
	}

	// Clearing the caller's deadline during a header read keeps the header
	// timeout.
	server, _ = acceptOne(t, l, nil)
	done := make(chan error, 1)
	go func() {
		_, err := server.Read(buf)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = server.SetReadDeadline(time.Time{})
	select {
	case err := <-done:
		if !isTimeout(err) {
			t.Fatalf("Read() error = %v, want the header timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read() outlived the header timeout")
	}
}

// A Read whose deadline passes while another call, such as RemoteAddr, reads
// the header returns the timeout instead of waiting for that read.
func TestListenerReadDeadlineWhileHeaderPending(t *testing.T) {
	l := newTestListener(t)
	l.HeaderTimeout = 2 * time.Second
	server, client := acceptOne(t, l, nil) // the peer sends nothing yet
	go func() { _ = server.RemoteAddr() }()
	time.Sleep(50 * time.Millisecond)

	_ = server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	if _, err := server.Read(make([]byte, 1)); !isTimeout(err) || time.Since(start) > time.Second {
		t.Fatalf("Read() = %v after %v, want the caller's timeout", err, time.Since(start))
	}

	// Moving the deadline into the past wakes a waiting Read.
	_ = server.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = server.SetReadDeadline(time.Now())
	select {
	case err := <-done:
		if !isTimeout(err) {
			t.Fatalf("Read() = %v, want a timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read() kept waiting after its deadline was moved into the past")
	}

	// The header still arrives for the call that reads it.
	_ = server.SetReadDeadline(time.Time{})
	if _, err := client.Write(append(V1Header(tcp("192.0.2.1", 1), tcp("192.0.2.2", 2)), 'x')); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "x" {
		t.Fatalf("Read() = %q, %v, want the payload", buf[:n], err)
	}
}

// A version 2 header that claims 64 KiB does not make the connection
// allocate that before the bytes arrive.
func TestListenerGrowsHeaderBufferWithData(t *testing.T) {
	l := newTestListener(t)
	l.HeaderTimeout = 2 * time.Second
	prefix := []byte(v2Signature + "\x21\x11\xff\xff")
	server, _ := acceptOne(t, l, prefix)
	c := server.(*Conn)
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := server.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("Read() = %v, want the caller's timeout", err)
	}
	if got := cap(c.hbuf); got > 2*headerReadSize {
		t.Fatalf("header buffer of %d bytes after %d bytes received", got, len(prefix))
	}
}

// noDeadlineConn cannot set deadlines, as some tunneled streams cannot.
type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

type noDeadlineListener struct{ net.Listener }

func (l noDeadlineListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return noDeadlineConn{c}, nil
}

// The header timeout also ends the wait of a connection without deadlines.
func TestListenerHeaderTimeoutWithoutDeadlines(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &Listener{Listener: noDeadlineListener{ln}, HeaderTimeout: 100 * time.Millisecond}
	t.Cleanup(func() { _ = l.Close() })
	server, _ := acceptOne(t, l, []byte("PROXY "))
	done := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if !isTimeout(err) {
			t.Fatalf("Read() error = %v, want the header timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read() outlived the header timeout")
	}
	if _, err := server.Read(make([]byte, 1)); isTimeout(err) || !errors.Is(err, ErrNoHeader) {
		t.Fatalf("Read() after the header timeout = %v, want ErrNoHeader and no timeout", err)
	}
}

func TestListenerOptionalSignaturePrefix(t *testing.T) {
	l := newTestListener(t)
	l.HeaderTimeout = 100 * time.Millisecond
	l.Policy = func(net.Addr) Policy { return Optional }
	buf := make([]byte, 16)

	// A peer that sends a bare CRLF, the start of a version 2 signature, and
	// waits.
	server, client := acceptOne(t, l, []byte("\r\n"))
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "\r\n" {
		t.Fatalf("Read() = %q, %v; want the CRLF", buf[:n], err)
	}
	if _, err := client.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "more" {
		t.Fatalf("Read() = %q, %v", buf[:n], err)
	}

	// A peer that waits for the server to speak first.
	server, client = acceptOne(t, l, nil)
	if got := server.RemoteAddr().String(); got != client.LocalAddr().String() {
		t.Fatalf("RemoteAddr() = %s, want the peer %s", got, client.LocalAddr())
	}
	if _, err := server.Write([]byte("220 ready\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("HELO")); err != nil {
		t.Fatal(err)
	}
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "HELO" {
		t.Fatalf("Read() = %q, %v", buf[:n], err)
	}

	// A peer that ends the stream after the start of a version 1 signature.
	server, client = acceptOne(t, l, []byte("PROX"))
	_ = client.(*net.TCPConn).CloseWrite()
	if got, err := io.ReadAll(server); err != nil || string(got) != "PROX" {
		t.Fatalf("ReadAll() = %q, %v", got, err)
	}

	// Required still fails.
	l.Policy = nil
	server, _ = acceptOne(t, l, []byte("\r\n"))
	if _, err := server.Read(buf); !isTimeout(err) {
		t.Fatalf("Read() error = %v, want the header timeout", err)
	}
}
