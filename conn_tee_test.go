package netx

import (
	"bytes"
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
	nilConn.StopAndClean()

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
