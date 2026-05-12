package netx

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const MaxFramePayload = 65535

var ErrFrameTooLarge = errors.New("framed: frame size exceeds MaxFramePayload")

type FramedConn struct {
	net.Conn
	rmu sync.Mutex
	wmu sync.Mutex
}

func WrapFramed(c net.Conn) *FramedConn { return &FramedConn{Conn: c} }

func (fc *FramedConn) Read(p []byte) (int, error) {
	if fc == nil || fc.Conn == nil {
		return 0, net.ErrClosed
	}
	fc.rmu.Lock()
	defer fc.rmu.Unlock()

	var hdr [2]byte
	if _, err := io.ReadFull(fc.Conn, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))

	if n == 0 {
		return 0, nil
	}
	if n > MaxFramePayload {
		return 0, ErrFrameTooLarge
	}

	if len(p) >= n {
		_, err := io.ReadFull(fc.Conn, p[:n])
		return n, err
	}

	read := 0
	if len(p) > 0 {
		if _, err := io.ReadFull(fc.Conn, p[:]); err != nil {
			return 0, err
		}
		read = len(p)
	}
	remain := n - read
	if remain > 0 {
		if _, err := io.CopyN(io.Discard, fc.Conn, int64(remain)); err != nil {
			return read, err
		}
	}
	return read, nil
}

func (fc *FramedConn) Write(p []byte) (int, error) {
	if fc == nil || fc.Conn == nil {
		return 0, net.ErrClosed
	}
	fc.wmu.Lock()
	defer fc.wmu.Unlock()

	if len(p) == 0 {
		return 0, fc.writeFrame(nil)
	}

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxFramePayload {
			chunk = chunk[:MaxFramePayload]
		}
		if err := fc.writeFrame(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}

	return written, nil
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

func (fc *FramedConn) writeFrame(p []byte) error {
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
