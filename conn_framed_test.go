package netx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

type byteBufferConn struct {
	bytes.Buffer
}

func (c *byteBufferConn) Close() error                     { return nil }
func (c *byteBufferConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *byteBufferConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *byteBufferConn) SetDeadline(time.Time) error      { return nil }
func (c *byteBufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *byteBufferConn) SetWriteDeadline(time.Time) error { return nil }

type writeFailConn struct {
	byteBufferConn
	err error
}

func (c *writeFailConn) Write([]byte) (int, error) { return 0, c.err }

func TestFramedConnWriteRejectsOversizedPayload(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	payload := bytes.Repeat([]byte("a"), MaxFramePayload+123)

	n, err := fc.Write(payload)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Write() error = %v, want %v", err, ErrFrameTooLarge)
	}
	if n != 0 {
		t.Fatalf("Write() n = %d, want 0", n)
	}
	if raw.Len() != 0 {
		t.Fatalf("wire len = %d, want 0", raw.Len())
	}
}

func TestFramedConnWriteReturnsZeroOnUnderlyingError(t *testing.T) {
	writeErr := errors.New("write failed")
	fc := NewFramedConn(&writeFailConn{err: writeErr})

	n, err := fc.Write([]byte("payload"))
	if !errors.Is(err, writeErr) {
		t.Fatalf("Write() error = %v, want %v", err, writeErr)
	}
	if n != 0 {
		t.Fatalf("Write() n = %d, want 0", n)
	}
}

func TestFramedConnReadKeepsFrameTailForSmallBuffer(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	if err := fc.WriteFrame([]byte("abcdef")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	buf := make([]byte, 2)
	n, err := fc.Read(buf)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "ab" {
		t.Fatalf("first Read() = %q, want %q", got, "ab")
	}
	n, err = fc.Read(buf)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "cd" {
		t.Fatalf("second Read() = %q, want %q", got, "cd")
	}
	n, err = fc.Read(buf)
	if err != nil {
		t.Fatalf("third Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "ef" {
		t.Fatalf("third Read() = %q, want %q", got, "ef")
	}
}

func TestFramedConnReadWriteFrame(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	if err := fc.WriteFrame([]byte("hello")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if got := int(binary.BigEndian.Uint16(raw.Bytes()[:2])); got != 5 {
		t.Fatalf("wire frame len = %d, want 5", got)
	}
	frame, err := fc.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if string(frame) != "hello" {
		t.Fatalf("ReadFrame() = %q, want %q", string(frame), "hello")
	}

	if err := fc.WriteFrame(nil); err != nil {
		t.Fatalf("WriteFrame(nil) error = %v", err)
	}
	frame, err = fc.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame(empty) error = %v", err)
	}
	if len(frame) != 0 {
		t.Fatalf("ReadFrame(empty) len = %d, want 0", len(frame))
	}
}

func TestFramedConnHelpersHandleNilUnderlyingConn(t *testing.T) {
	var nilConn *FramedConn
	if _, err := nilConn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := nilConn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Close() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if got := nilConn.LocalAddr(); got != nil {
		t.Fatalf("nil LocalAddr() = %v, want nil", got)
	}
	if got := nilConn.RemoteAddr(); got != nil {
		t.Fatalf("nil RemoteAddr() = %v, want nil", got)
	}

	malformed := &FramedConn{}
	if _, err := malformed.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := malformed.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Close() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if got := malformed.LocalAddr(); got != nil {
		t.Fatalf("malformed LocalAddr() = %v, want nil", got)
	}
	if got := malformed.RemoteAddr(); got != nil {
		t.Fatalf("malformed RemoteAddr() = %v, want nil", got)
	}
}
