package netx

import (
	"bufio"
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

// ErrFrameDesync is returned after a read or write failed in a way that lost
// frame bytes, such as the end of the stream inside a frame (see FramedConn).
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
// By default Read is stream-oriented: it returns the bytes of the current
// frame that one read of the connection delivers, up to len(p), and the rest
// of the frame continues in the next Reads without being buffered. Empty
// frames are skipped, as they carry no stream bytes. Use WithDatagramReads,
// ReadFrame or a buffer of at least MaxFramePayload bytes when message
// boundaries matter, and WithReadBuffer to serve small frames or small
// buffers from one read of the connection.
//
// An error that loses no frame bytes is returned unchanged and may be
// retried: one between frames or inside a frame header, such as an expired
// deadline, or, since stream Reads keep their place, one anywhere in a frame
// read by Read in stream mode. A ReadFrame or datagram Read that fails after
// part of the payload was read, the end of the stream inside a frame, and a
// write that fails after part of a frame was written lose the frame
// boundaries in that direction: they are reported as ErrFrameDesync wrapping
// their cause, which is not a timeout and is returned again by every later
// call in that direction.
//
// Reads and writes may run concurrently with each other.
type FramedConn struct {
	net.Conn
	br       *bufio.Reader // set by WithReadBuffer
	rerr     error
	werr     error
	remain   int // payload bytes of the current frame not yet read
	rhdrN    int // bytes of rhdr read so far
	rmu      sync.Mutex
	wmu      sync.Mutex
	wbufs    net.Buffers // header and payload of a vectored write, guarded by wmu
	wvec     [2][]byte   // backing array of wbufs
	rhdr     [2]byte
	whdr     [2]byte // header of a vectored write, guarded by wmu
	datagram bool
}

type framedOptions struct {
	datagramReads bool
	readBuffer    int
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

// WithReadBuffer reads the stream through a buffer of size bytes, so a burst
// of small frames costs one read of the wrapped connection instead of two per
// frame. Bytes already in the buffer are lost to anyone who reads the wrapped
// connection directly, for example through RawConnOf.
func WithReadBuffer(size int) FramedOption {
	return func(o *framedOptions) {
		o.readBuffer = size
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
	fc := &FramedConn{Conn: c, datagram: cfg.datagramReads}
	if cfg.readBuffer > 0 && c != nil {
		fc.br = bufio.NewReaderSize(c, cfg.readBuffer)
	}
	return fc
}

// reader returns the source of frame bytes.
func (fc *FramedConn) reader() io.Reader {
	if fc.br != nil {
		return fc.br
	}
	return fc.Conn
}

// Read reads frame payload into p.
//
// In the default stream mode, a frame longer than p, or not yet received in
// full, is returned across several Reads and empty frames are skipped. With
// WithDatagramReads, each call consumes exactly one frame, an empty one
// included, and discards what does not fit in p; an empty p consumes and
// discards one frame.
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
	if fc.datagram {
		return fc.readDatagramLocked(p)
	}
	// In stream mode empty frames carry no bytes and are skipped, so that a
	// Read with a non-empty p does not return 0, nil for them.
	for fc.remain == 0 {
		n, err := fc.readHeaderLocked()
		if err != nil {
			return 0, err
		}
		fc.remain = n
	}
	return fc.readPayloadLocked(p)
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
	n := fc.remain
	if n == 0 {
		var err error
		if n, err = fc.readHeaderLocked(); err != nil {
			return nil, err
		}
	}
	frame := make([]byte, n)
	if m, err := io.ReadFull(fc.reader(), frame); err != nil {
		if m == 0 && !errors.Is(err, io.EOF) {
			// No payload byte was lost: the next call reads the frame.
			fc.remain = n
			return nil, err
		}
		return nil, fc.failReadLocked(err)
	}
	fc.remain = 0
	return frame, nil
}

// readHeaderLocked reads the next frame length. The bytes of a header cut
// short by an error are kept for the next call; only the end of the stream
// inside a header loses the frame boundaries.
func (fc *FramedConn) readHeaderLocked() (int, error) {
	n, err := io.ReadFull(fc.reader(), fc.rhdr[fc.rhdrN:])
	fc.rhdrN += n
	if err != nil {
		if fc.rhdrN > 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			return 0, fc.failReadLocked(err)
		}
		return 0, err
	}
	fc.rhdrN = 0
	// The uint16 header cannot exceed MaxFramePayload.
	return int(binary.BigEndian.Uint16(fc.rhdr[:])), nil
}

// readPayloadLocked reads up to len(p) bytes of the current frame with one
// read of the connection. The frame's remaining length is kept across errors,
// so a failed read can be retried; only the end of the stream inside the
// frame loses the frame boundaries.
func (fc *FramedConn) readPayloadLocked(p []byte) (int, error) {
	n, err := fc.reader().Read(p[:min(len(p), fc.remain)])
	fc.remain -= n
	if errors.Is(err, io.EOF) {
		if fc.remain > 0 {
			return n, fc.failReadLocked(err)
		}
		err = nil // the frame is complete; the next Read reports the end
	}
	return n, err
}

// readDatagramLocked reads the next frame, or the one whose payload a failed
// read left pending, into p and discards the bytes that do not fit.
func (fc *FramedConn) readDatagramLocked(p []byte) (int, error) {
	n := fc.remain
	if n == 0 {
		var err error
		if n, err = fc.readHeaderLocked(); err != nil {
			return 0, err
		}
	}
	k := min(len(p), n)
	if m, err := io.ReadFull(fc.reader(), p[:k]); err != nil {
		if m == 0 && !errors.Is(err, io.EOF) {
			// No payload byte was lost: the next call reads the frame.
			fc.remain = n
			return 0, err
		}
		return 0, fc.failReadLocked(err)
	}
	fc.remain = 0
	if rest := n - k; rest > 0 {
		var err error
		if fc.br != nil {
			_, err = fc.br.Discard(rest)
		} else {
			_, err = io.CopyN(io.Discard, fc.Conn, int64(rest))
		}
		if err != nil {
			return 0, fc.failReadLocked(err)
		}
	}
	return k, nil
}

// failReadLocked records a read error that hit the middle of a frame.
func (fc *FramedConn) failReadLocked(err error) error {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	fc.remain, fc.rhdrN = 0, 0
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

// CloseWrite shuts down the writing side of the wrapped connection after the
// frames written so far; see TimeoutConn.CloseWrite.
func (fc *FramedConn) CloseWrite() error {
	if fc == nil || fc.Conn == nil {
		return net.ErrClosed
	}
	fc.wmu.Lock()
	defer fc.wmu.Unlock()
	return closeWrite(fc.Conn)
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
		// The header and vector live in fc, so the writev does not allocate.
		binary.BigEndian.PutUint16(fc.whdr[:], uint16(len(p)))
		fc.wvec = [2][]byte{fc.whdr[:], p}
		fc.wbufs = fc.wvec[:]
		written, err = writeBuffers(fc.Conn, &fc.wbufs)
		fc.wvec = [2][]byte{} // do not keep p reachable
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

// writeBuffers writes every buffer of bufs to w, consuming bufs.
func writeBuffers(w io.Writer, bufs *net.Buffers) (int64, error) {
	var want int64
	for _, b := range *bufs {
		want += int64(len(b))
	}
	n, err := bufs.WriteTo(w)
	if err == nil && n != want {
		err = io.ErrShortWrite
	}
	return n, err
}
