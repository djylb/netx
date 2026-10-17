package netx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type teeTestConn struct {
	readBuf  *bytes.Buffer
	writeBuf bytes.Buffer
	closed   bool
}

func (c *teeTestConn) Read(p []byte) (int, error) {
	if c == nil || c.readBuf == nil {
		return 0, io.EOF
	}
	return c.readBuf.Read(p)
}

func (c *teeTestConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	return c.writeBuf.Write(p)
}

func (c *teeTestConn) Close() error {
	if c == nil {
		return nil
	}
	c.closed = true
	return nil
}

func (c *teeTestConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *teeTestConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *teeTestConn) SetDeadline(time.Time) error      { return nil }
func (c *teeTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *teeTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestRecordingConnHelpersHandleNilState(t *testing.T) {
	var nilConn *RecordingConn
	assertClosedConnState(t, "nil", nilConn)
	if got := nilConn.Buffered(); got != nil {
		t.Fatalf("nil Buffered() = %v, want nil", got)
	}
	if nilConn.Truncated() {
		t.Fatal("nil Truncated() = true")
	}
	if raw, data := nilConn.Release(); raw != nil || data != nil {
		t.Fatalf("nil Release() = (%v, %v), want (nil, nil)", raw, data)
	}
	nilConn.Stop(true)

	malformed := &RecordingConn{}
	assertClosedConnState(t, "malformed", malformed)

	lazy := &RecordingConn{
		underlying:  &teeTestConn{readBuf: bytes.NewBufferString("abc")},
		maxBufBytes: 8,
	}
	buf := make([]byte, 3)
	n, err := lazy.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("lazy Read() error = %v", err)
	}
	if n != 3 || string(buf[:n]) != "abc" {
		t.Fatalf("lazy Read() = %d %q, want 3 %q", n, string(buf[:n]), "abc")
	}
	if got := string(lazy.Buffered()); got != "abc" {
		t.Fatalf("lazy Buffered() = %q, want %q", got, "abc")
	}
}

func TestRecordingConnReleaseTransfersOwnership(t *testing.T) {
	base := &teeTestConn{readBuf: bytes.NewBufferString("abcdef")}
	tee := NewRecordingConn(base, 8)
	buf := make([]byte, 3)
	if n, err := tee.Read(buf); err != nil || n != 3 {
		t.Fatalf("Read() = %d, %v; want 3, nil", n, err)
	}

	raw, data := tee.Release()
	if raw != base {
		t.Fatalf("Release() raw = %v, want base", raw)
	}
	if string(data) != "abc" {
		t.Fatalf("Release() data = %q, want %q", string(data), "abc")
	}
	if err := tee.Close(); err != nil {
		t.Fatalf("Close() after Release() error = %v", err)
	}
	if base.closed {
		t.Fatal("Close() after Release() closed released conn")
	}
	if _, err := tee.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() after Release() error = %v, want %v", err, net.ErrClosed)
	}
}

func TestRecordingConnDiscardBufferStopsCapture(t *testing.T) {
	tee := NewRecordingConn(&teeTestConn{readBuf: bytes.NewBufferString("abcdef")}, 8)
	buf := make([]byte, 3)
	if n, err := tee.Read(buf); err != nil || n != 3 {
		t.Fatalf("Read() = %d, %v; want 3, nil", n, err)
	}
	tee.Stop(true)
	if got := tee.Buffered(); len(got) != 0 {
		t.Fatalf("Buffered() after Stop(true) = %q, want empty", string(got))
	}
	if n, err := tee.Read(buf); err != nil && err != io.EOF || n != 3 {
		t.Fatalf("Read() after Stop(true) = %d, %v; want 3, nil/eof", n, err)
	}
	if got := tee.Buffered(); len(got) != 0 {
		t.Fatalf("Buffered() after stopped capture = %q, want empty", string(got))
	}
}

// Reads past the limit are reported as truncated, and Stop without discard
// keeps what was recorded.
func TestRecordingConnTruncatedAndStop(t *testing.T) {
	rc := NewRecordingConn(&teeTestConn{readBuf: bytes.NewBufferString("abcdef")}, 4)
	_, _ = io.ReadFull(rc, make([]byte, 3))
	if rc.Truncated() {
		t.Fatal("Truncated() before the limit")
	}
	rc.Stop(false)
	_, _ = io.ReadFull(rc, make([]byte, 3))
	if got := string(rc.Buffered()); got != "abc" || rc.Truncated() {
		t.Fatalf("after Stop(false): Buffered() = %q, Truncated() = %v", got, rc.Truncated())
	}
	rc2 := NewRecordingConn(&teeTestConn{readBuf: bytes.NewBufferString("abcdef")}, 4)
	_, _ = io.ReadFull(rc2, make([]byte, 6))
	if got := string(rc2.Buffered()); got != "abcd" || !rc2.Truncated() {
		t.Fatalf("Buffered() = %q, Truncated() = %v; want abcd, true", got, rc2.Truncated())
	}
}

// Peek returns after the first read, with at most n bytes, and a connection
// that replays them; PeekFull waits for n.
func TestPeek(t *testing.T) {
	ctx := context.Background()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	go func() { _, _ = a.Write([]byte("GET / HTTP/1.1\r\n")); _ = a.Close() }()
	c, first, err := PeekFull(ctx, b, 4)
	if err != nil || string(first) != "GET " {
		t.Fatalf("PeekFull() = %q, %v", first, err)
	}
	all, _ := io.ReadAll(c)
	if string(all) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("replayed %q", all)
	}

	// A short first message, such as a SOCKS5 greeting, does not stall Peek.
	p, q := net.Pipe()
	defer func() { _ = p.Close() }()
	go func() { _, _ = p.Write([]byte{5, 1, 0}) }()
	c, first, err = Peek(ctx, q, 5)
	if err != nil || !bytes.Equal(first, []byte{5, 1, 0}) {
		t.Fatalf("Peek() = %v, %v", first, err)
	}
	if got := make([]byte, 3); func() bool { _, err := io.ReadFull(c, got); return err != nil }() || !bytes.Equal(got, first) {
		t.Fatalf("Peek replayed %v", got)
	}

	// PeekFull of a stream that ends early returns what came.
	p2, q2 := net.Pipe()
	go func() { _, _ = p2.Write([]byte("ab")); _ = p2.Close() }()
	c, first, err = PeekFull(ctx, q2, 4)
	if !errors.Is(err, io.ErrUnexpectedEOF) || string(first) != "ab" {
		t.Fatalf("short PeekFull() = %q, %v", first, err)
	}
	if all, _ := io.ReadAll(c); string(all) != "ab" {
		t.Fatalf("short PeekFull replayed %q", all)
	}

	// ctx bounds the wait, and the deadline it set is cleared on success.
	p3, q3 := net.Pipe()
	defer func() { _ = p3.Close() }()
	tctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, _, err := Peek(tctx, q3, 4); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("idle Peek() error = %v, want the deadline", err)
	}
}

// On a datagram connection Peek keeps the first datagram whole.
func TestPeekDatagram(t *testing.T) {
	l := newUDPListener(t)
	peer := dialUDP(t, l)
	big := bytes.Repeat([]byte("d"), 1000)
	_, _ = peer.Write(big)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, first, err := PeekFull(ctx, c, 16)
	if err != nil || len(first) != 16 {
		t.Fatalf("PeekFull() = %d bytes, %v", len(first), err)
	}
	buf := make([]byte, 2000)
	if n, err := pc.Read(buf); err != nil || n != len(big) {
		t.Fatalf("replayed datagram = %d bytes, %v; want %d", n, err, len(big))
	}
}
