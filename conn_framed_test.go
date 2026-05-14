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

func TestFramedConnWriteSplitsOversizedPayload(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	payload := bytes.Repeat([]byte("a"), MaxFramePayload+123)

	n, err := fc.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() n = %d, want %d", n, len(payload))
	}

	wire := raw.Bytes()
	if len(wire) != 2+MaxFramePayload+2+123 {
		t.Fatalf("wire len = %d, want %d", len(wire), 2+MaxFramePayload+2+123)
	}
	if got := int(binary.BigEndian.Uint16(wire[:2])); got != MaxFramePayload {
		t.Fatalf("first frame len = %d, want %d", got, MaxFramePayload)
	}
	if !bytes.Equal(wire[2:2+MaxFramePayload], payload[:MaxFramePayload]) {
		t.Fatal("first frame payload mismatch")
	}
	offset := 2 + MaxFramePayload
	if got := int(binary.BigEndian.Uint16(wire[offset : offset+2])); got != 123 {
		t.Fatalf("second frame len = %d, want %d", got, 123)
	}
	if !bytes.Equal(wire[offset+2:], payload[MaxFramePayload:]) {
		t.Fatal("second frame payload mismatch")
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
