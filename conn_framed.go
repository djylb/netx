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

// ErrFrameTooLarge is returned by Write and WriteFrame when the payload exceeds MaxFramePayload.
var ErrFrameTooLarge = errors.New("framed: frame size exceeds MaxFramePayload")

// ErrFrameDesync is returned after a read or write failed in the middle of a frame.
// Frame boundaries in that direction are lost, so the error is sticky and the
// connection should be closed. Use errors.Is to detect it. The returned error
// also wraps the failure that caused it, so errors.Is and errors.As still see
// that cause (an EOF inside a frame as io.ErrUnexpectedEOF), except that a
// timeout cause is hidden and the error never reports a timeout.
var ErrFrameDesync = errors.New("framed: stream desynchronized by a partial frame")

// FramedConn reads and writes length-prefixed messages over a reliable stream.
//
// Each frame is a 2-byte big-endian length followed by the payload. Write and
// WriteFrame send p as exactly one frame and reject payloads longer than
// MaxFramePayload instead of splitting them.
//
// By default Read is stream-oriented: a frame longer than p is returned across
// several Reads. Use WithDatagramReads, ReadFrame or a buffer of at least
// MaxFramePayload bytes when message boundaries matter.
//
// An error before any byte of a frame was transferred, such as a deadline that
// expires between frames, is returned unchanged and may be retried. An error
// after part of a frame was transferred is reported as ErrFrameDesync wrapping
// its cause, is not a timeout, and is returned again by every later call in
// that direction.
//
// Reads and writes may run concurrently with each other.
type FramedConn struct {
	net.Conn
	rerr     error
	werr     error
	pending  []byte
	rmu      sync.Mutex
	wmu      sync.Mutex
	rhdr     [2]byte
	datagram bool
}

type framedOptions struct {
	datagramReads bool
}

// FramedOption configures NewFramedConn.
type FramedOption func(*framedOptions)

// WithDatagramReads makes Read return exactly one frame per call.
// Bytes of a frame that do not fit in p are discarded, like a UDP socket
// truncating a datagram. ReadFrame is not affected.
func WithDatagramReads() FramedOption {
	return func(o *framedOptions) {
		o.datagramReads = true
	}
}

// NewFramedConn wraps c with length-prefixed message I/O.
func NewFramedConn(c net.Conn, opts ...FramedOption) *FramedConn {
	var cfg framedOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return &FramedConn{Conn: c, datagram: cfg.datagramReads}
}

// Read reads frame payload into p.
//
// In the default stream mode, a frame longer than p is returned across several
// Reads. With WithDatagramReads, each call consumes exactly one frame and
// discards what does not fit in p; an empty p consumes and discards one frame.
func (fc *FramedConn) Read(p []byte) (int, error) {
	if fc == nil || fc.Conn == nil {
		return 0, net.ErrClosed
	}
	if len(p) == 0 && !fc.datagram {
		return 0, nil
	}
	fc.rmu.Lock()
	defer fc.rmu.Unlock()

	if fc.rerr != nil {
		return 0, fc.rerr
	}
	if len(fc.pending) > 0 {
		return fc.readPending(p), nil
	}

	return fc.readFrameIntoLocked(p)
}

// ReadFrame reads and returns one complete frame.
// If Read has already partially consumed a frame, ReadFrame returns the remaining bytes.
func (fc *FramedConn) ReadFrame() ([]byte, error) {
	if fc == nil || fc.Conn == nil {
		return nil, net.ErrClosed
	}
	fc.rmu.Lock()
	defer fc.rmu.Unlock()

	if fc.rerr != nil {
		return nil, fc.rerr
	}
	if len(fc.pending) > 0 {
		frame := fc.pending
		fc.pending = nil
		return frame, nil
	}
	return fc.readFrameLocked()
}

// readHeaderLocked reads the next frame length.
// An error before any header byte arrived leaves the stream on a frame boundary.
func (fc *FramedConn) readHeaderLocked() (int, error) {
	if n, err := io.ReadFull(fc.Conn, fc.rhdr[:]); err != nil {
		if n > 0 {
			return 0, fc.failReadLocked(err)
		}
		return 0, err
	}
	// The uint16 header cannot exceed MaxFramePayload.
	return int(binary.BigEndian.Uint16(fc.rhdr[:])), nil
}

func (fc *FramedConn) readFrameLocked() ([]byte, error) {
	n, err := fc.readHeaderLocked()
	if err != nil {
		return nil, err
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(fc.Conn, frame); err != nil {
		return nil, fc.failReadLocked(err)
	}
	return frame, nil
}

func (fc *FramedConn) readFrameIntoLocked(p []byte) (int, error) {
	n, err := fc.readHeaderLocked()
	if err != nil {
		return 0, err
	}
	if n <= len(p) {
		if _, err := io.ReadFull(fc.Conn, p[:n]); err != nil {
			return 0, fc.failReadLocked(err)
		}
		return n, nil
	}
	if _, err := io.ReadFull(fc.Conn, p); err != nil {
		return 0, fc.failReadLocked(err)
	}
	if fc.datagram {
		_, err = io.CopyN(io.Discard, fc.Conn, int64(n-len(p)))
	} else {
		pending := make([]byte, n-len(p))
		if _, err = io.ReadFull(fc.Conn, pending); err == nil {
			fc.pending = pending
		}
	}
	if err != nil {
		return 0, fc.failReadLocked(err)
	}
	return len(p), nil
}

func (fc *FramedConn) readPending(p []byte) int {
	n := copy(p, fc.pending)
	fc.pending = fc.pending[n:]
	if len(fc.pending) == 0 {
		fc.pending = nil
	}
	return n
}

// failReadLocked records a read error that hit the middle of a frame.
func (fc *FramedConn) failReadLocked(err error) error {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	fc.pending = nil
	fc.rerr = &frameDesyncError{cause: err}
	return fc.rerr
}

// Write sends p as exactly one frame.
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

// RawConn returns the innermost connection beneath fc; see RawConnProvider.
func (fc *FramedConn) RawConn() net.Conn {
	if fc == nil {
		return nil
	}
	return rawConnOf(fc.Conn)
}

// framedWriteBufPool holds frame buffers for conns without a writev fast path.
// Write and WriteFrame bound their capacity to 2+MaxFramePayload.
var framedWriteBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 2+2048)
		return &buf
	},
}

func (fc *FramedConn) writeFrameLocked(p []byte) error {
	if fc == nil || fc.Conn == nil {
		return net.ErrClosed
	}
	if fc.werr != nil {
		return fc.werr
	}
	var (
		written int64
		err     error
	)
	if _, ok := fc.Conn.(*net.TCPConn); ok {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
		written, err = writeBuffers(fc.Conn, hdr[:], p)
	} else {
		// One Write per frame, so wrappers such as TLS or mux streams do not
		// emit a separate record or packet for the 2-byte header.
		bp := framedWriteBufPool.Get().(*[]byte)
		buf := binary.BigEndian.AppendUint16((*bp)[:0], uint16(len(p)))
		buf = append(buf, p...)
		var n int
		n, err = writeAll(fc.Conn, buf)
		written = int64(n)
		*bp = buf[:0]
		framedWriteBufPool.Put(bp)
	}
	if err != nil && written > 0 && written < int64(2+len(p)) {
		fc.werr = &frameDesyncError{cause: err}
		return fc.werr
	}
	return err
}

// frameDesyncError matches ErrFrameDesync and, unless it is a timeout, its cause.
// It never reports a timeout, so retry-on-timeout loops do not spin on it.
type frameDesyncError struct {
	cause error
}

func (e *frameDesyncError) Error() string {
	return ErrFrameDesync.Error() + ": " + e.cause.Error()
}

func (e *frameDesyncError) Unwrap() []error {
	if IsTimeout(e.cause) {
		return []error{ErrFrameDesync}
	}
	return []error{ErrFrameDesync, e.cause}
}

func (e *frameDesyncError) Timeout() bool   { return false }
func (e *frameDesyncError) Temporary() bool { return false }

func writeAll(w io.Writer, p []byte) (int, error) {
	written := 0
	for written < len(p) {
		n, err := w.Write(p[written:])
		if n > 0 {
			written += n
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func writeBuffers(w io.Writer, first, second []byte) (int64, error) {
	want := int64(len(first) + len(second))
	buffers := net.Buffers{first, second}
	n, err := buffers.WriteTo(w)
	if err == nil && n != want {
		err = io.ErrShortWrite
	}
	return n, err
}
