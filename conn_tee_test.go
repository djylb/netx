package netx

import (
	"bytes"
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

func TestTeeConnHelpersHandleNilState(t *testing.T) {
	var nilConn *TeeConn
	assertClosedConnState(t, "nil", nilConn)
	if got := nilConn.Buffered(); got != nil {
		t.Fatalf("nil Buffered() = %v, want nil", got)
	}
	nilConn.ResetBuffer()
	if got := nilConn.ExtractAndReset(); got != nil {
		t.Fatalf("nil ExtractAndReset() = %v, want nil", got)
	}
	if raw, data := nilConn.Release(); raw != nil || data != nil {
		t.Fatalf("nil Release() = (%v, %v), want (nil, nil)", raw, data)
	}
	nilConn.StopBuffering()
	nilConn.DiscardBuffer()

	malformed := &TeeConn{}
	assertClosedConnState(t, "malformed", malformed)

	lazy := &TeeConn{
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

func TestTeeConnReleaseTransfersOwnership(t *testing.T) {
	base := &teeTestConn{readBuf: bytes.NewBufferString("abcdef")}
	tee := NewTeeConn(base, 8)
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

func TestTeeConnDiscardBufferStopsCapture(t *testing.T) {
	tee := NewTeeConn(&teeTestConn{readBuf: bytes.NewBufferString("abcdef")}, 8)
	buf := make([]byte, 3)
	if n, err := tee.Read(buf); err != nil || n != 3 {
		t.Fatalf("Read() = %d, %v; want 3, nil", n, err)
	}
	tee.DiscardBuffer()
	if got := tee.Buffered(); got != nil && len(got) != 0 {
		t.Fatalf("Buffered() after DiscardBuffer() = %q, want empty", string(got))
	}
	if n, err := tee.Read(buf); err != nil && err != io.EOF || n != 3 {
		t.Fatalf("Read() after DiscardBuffer() = %d, %v; want 3, nil/eof", n, err)
	}
	if got := tee.Buffered(); got != nil && len(got) != 0 {
		t.Fatalf("Buffered() after stopped capture = %q, want empty", string(got))
	}
}
