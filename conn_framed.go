package netx

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// MaxFramePayload is the maximum payload size of one framed message.
const MaxFramePayload = 65535

// ErrFrameTooLarge is returned when a frame exceeds MaxFramePayload.
var ErrFrameTooLarge = errors.New("framed: frame size exceeds MaxFramePayload")

// FramedConn reads and writes length-prefixed messages over a reliable stream.
type FramedConn struct {
	net.Conn
	rmu     sync.Mutex
	wmu     sync.Mutex
	pending []byte
}

// NewFramedConn wraps c with length-prefixed message I/O.
func NewFramedConn(c net.Conn) *FramedConn { return &FramedConn{Conn: c} }

func (fc *FramedConn) Read(p []byte) (int, error) {
	if fc == nil || fc.Conn == nil {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	fc.rmu.Lock()
	defer fc.rmu.Unlock()

	if len(fc.pending) > 0 {
		return fc.readPending(p), nil
	}

	frame, err := fc.readFrameLocked()
	if err != nil {
		return 0, err
	}
	if len(frame) == 0 {
		return 0, nil
	}
	n := copy(p, frame)
	if n < len(frame) {
		fc.pending = append(fc.pending[:0], frame[n:]...)
	}
	return n, nil
}

// ReadFrame reads and returns one complete frame.
// If Read has already partially consumed a frame, ReadFrame returns the remaining bytes.
func (fc *FramedConn) ReadFrame() ([]byte, error) {
	if fc == nil || fc.Conn == nil {
		return nil, net.ErrClosed
	}
	fc.rmu.Lock()
	defer fc.rmu.Unlock()

	if len(fc.pending) > 0 {
		frame := append([]byte(nil), fc.pending...)
		fc.pending = nil
		return frame, nil
	}
	return fc.readFrameLocked()
}

func (fc *FramedConn) readFrameLocked() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(fc.Conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > MaxFramePayload {
		return nil, ErrFrameTooLarge
	}
	if n == 0 {
		return []byte{}, nil
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(fc.Conn, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func (fc *FramedConn) readPending(p []byte) int {
	n := copy(p, fc.pending)
	if n == len(fc.pending) {
		fc.pending = nil
		return n
	}
	copy(fc.pending, fc.pending[n:])
	fc.pending = fc.pending[:len(fc.pending)-n]
	return n
}

func (fc *FramedConn) Write(p []byte) (int, error) {
	if fc == nil || fc.Conn == nil {
		return 0, net.ErrClosed
	}
	if len(p) > MaxFramePayload {
		return 0, ErrFrameTooLarge
	}
	fc.wmu.Lock()
	defer fc.wmu.Unlock()

	if err := fc.writeFrameLocked(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteFrame writes one complete frame.
func (fc *FramedConn) WriteFrame(p []byte) error {
	if fc == nil || fc.Conn == nil {
		return net.ErrClosed
	}
	if len(p) > MaxFramePayload {
		return ErrFrameTooLarge
	}
	fc.wmu.Lock()
	defer fc.wmu.Unlock()

	return fc.writeFrameLocked(p)
}

func (fc *FramedConn) SetDeadline(t time.Time) error {
	if fc == nil || fc.Conn == nil {
		return net.ErrClosed
	}
	return fc.Conn.SetDeadline(t)
}

func (fc *FramedConn) SetReadDeadline(t time.Time) error {
	if fc == nil || fc.Conn == nil {
		return net.ErrClosed
	}
	return fc.Conn.SetReadDeadline(t)
}

func (fc *FramedConn) SetWriteDeadline(t time.Time) error {
	if fc == nil || fc.Conn == nil {
		return net.ErrClosed
	}
	return fc.Conn.SetWriteDeadline(t)
}

func (fc *FramedConn) LocalAddr() net.Addr {
	if fc == nil || fc.Conn == nil {
		return nil
	}
	return fc.Conn.LocalAddr()
}

func (fc *FramedConn) RemoteAddr() net.Addr {
	if fc == nil || fc.Conn == nil {
		return nil
	}
	return fc.Conn.RemoteAddr()
}

func (fc *FramedConn) Close() error {
	if fc == nil || fc.Conn == nil {
		return net.ErrClosed
	}
	return fc.Conn.Close()
}

func (fc *FramedConn) RawConn() net.Conn {
	if fc == nil {
		return nil
	}
	return rawConnOf(fc.Conn)
}

func (fc *FramedConn) writeFrameLocked(p []byte) error {
	if fc == nil || fc.Conn == nil {
		return net.ErrClosed
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	if err := writeAll(fc.Conn, hdr[:]); err != nil {
		return err
	}
	if len(p) == 0 {
		return nil
	}
	return writeAll(fc.Conn, p)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
