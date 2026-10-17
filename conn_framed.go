package netx

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MaxFramePayload is the maximum payload size of one framed message.
const MaxFramePayload = 65535

// ErrFrameTooLarge is returned by WriteFrame, and by Write in datagram mode,
// for a payload longer than MaxFramePayload.
var ErrFrameTooLarge = errors.New("netx: frame size exceeds MaxFramePayload")

// ErrFrameDesync is returned after a read or write failed in a way that lost
// frame bytes, such as the end of the stream inside a frame (see FramedConn).
// Frame boundaries in that direction are lost, so the error is sticky and the
// connection should be closed. Use errors.Is to detect it. The returned error
// also wraps the failure that caused it, so errors.Is and errors.As still see
// that cause (an EOF inside a frame as io.ErrUnexpectedEOF), except that a
// timeout cause is hidden and the error never reports a timeout.
var ErrFrameDesync = errors.New("netx: framed stream desynchronized by a partial frame")

// FramedConn reads and writes length-prefixed messages over a reliable stream.
//
// Each frame is a 2-byte big-endian length followed by the payload.
//
// By default the connection is a stream: Write sends p as one frame, or as
// several when it is longer than MaxFramePayload, which Reads join up again.
// Read it returns the current frame, or as
// much of it as fits in p, and a longer frame continues in the next Reads
// without being buffered. Empty frames are skipped, as they carry no stream
// bytes, and an error inside a frame splits it between two Reads.
//
// With WithFramedDatagrams each frame is a message, as a datagram is: Write
// sends p as exactly one frame and fails with ErrFrameTooLarge for a longer
// one, and Read returns one frame per call. WriteFrame and ReadFrame work on
// one frame in either mode. WithFramedReadBuffer serves small frames or small
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
	conn     net.Conn
	br       *bufio.Reader // set by WithFramedReadBuffer
	rerr     error
	rpend    error  // error that cut a stream Read short, for the next Read
	rpendAt  uint64 // rdeadlines before the read that left rpend
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
	// rdeadlines counts the read deadlines set, without rmu, which a
	// blocked Read holds.
	rdeadlines atomic.Uint64
}

type framedOptions struct {
	datagramReads bool
	readBuffer    int
}

// FramedOption configures NewFramedConn.
type FramedOption func(*framedOptions)

// WithFramedDatagrams makes each frame a message, as a datagram is: Read
// returns exactly one frame per call, discarding the bytes that do not fit
// in p like a UDP socket truncating a datagram, and Write sends exactly one
// frame, failing for a payload longer than MaxFramePayload. ReadFrame and
// WriteFrame are not affected.
func WithFramedDatagrams() FramedOption {
	return func(o *framedOptions) {
		o.datagramReads = true
	}
}

// WithFramedReadBuffer reads the stream through a buffer of size bytes, so a burst
// of small frames costs one read of the wrapped connection instead of two per
// frame. Bytes already in the buffer are lost to anyone who reads the wrapped
// connection directly, for example through InnermostConn.
func WithFramedReadBuffer(size int) FramedOption {
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
	fc := &FramedConn{conn: c, datagram: cfg.datagramReads}
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
	return fc.conn
}

// Read reads frame payload into p.
//
// In the default stream mode, a frame longer than p, or one whose reading an
// error interrupts, is returned across several Reads and empty frames are
// skipped; a Read that an error cuts short returns the bytes it read and
// leaves the error to the next Read. With
// WithFramedDatagrams, each call consumes exactly one frame, an empty one
// included, and discards what does not fit in p; an empty p consumes and
// discards one frame.
func (fc *FramedConn) Read(p []byte) (int, error) {
	if fc == nil || fc.conn == nil {
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
	if err := fc.takePendingLocked(); err != nil {
		return 0, err
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
	if fc == nil || fc.conn == nil {
		return nil, net.ErrClosed
	}
	fc.rmu.Lock()
	defer fc.rmu.Unlock()

	if fc.rerr != nil {
		return nil, fc.rerr
	}
	if err := fc.takePendingLocked(); err != nil {
		return nil, err
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
		if m == 0 && !streamEnded(err) {
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
		if fc.rhdrN > 0 && streamEnded(err) {
			return 0, fc.failReadLocked(err)
		}
		return 0, err
	}
	fc.rhdrN = 0
	// The uint16 header cannot exceed MaxFramePayload.
	return int(binary.BigEndian.Uint16(fc.rhdr[:])), nil
}

// readPayloadLocked reads as much of the current frame as fits in p. The
// frame's remaining length is kept across errors, so a failed read can be
// retried; only the end of the stream inside the frame loses the frame
// boundaries.
func (fc *FramedConn) readPayloadLocked(p []byte) (int, error) {
	// Taken before the read, so that a deadline set while it runs drops a
	// timeout it returns.
	deadlines := fc.rdeadlines.Load()
	n, err := io.ReadFull(fc.reader(), p[:min(len(p), fc.remain)])
	fc.remain -= n
	if streamEnded(err) {
		err = fc.failReadLocked(io.EOF)
	}
	if n > 0 && err != nil {
		// Return the bytes alone, as a connection does, so that callers
		// that retry after a timeout do not lose them.
		if fc.rerr == nil {
			fc.rpend, fc.rpendAt = err, deadlines
		}
		err = nil
	}
	return n, err
}

// streamEnded reports whether err ends the stream, as io.EOF, or the
// io.ErrUnexpectedEOF of io.ReadFull or of a TLS connection cut inside a
// record.
func streamEnded(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// takePendingLocked returns and clears the error left by a stream Read. A
// timeout is dropped once the read deadline was set again, as the next read
// of the connection then reports whether the new one has passed.
func (fc *FramedConn) takePendingLocked() error {
	err := fc.rpend
	fc.rpend = nil
	if err != nil && fc.rpendAt != fc.rdeadlines.Load() && IsTimeout(err) {
		return nil
	}
	return err
}

// nextDatagram reads the next frame, as a datagram Read does, into a pooled
// buffer that fits it, for Relay; see datagramSource. It waits for the
// frame's header without a buffer.
func (fc *FramedConn) nextDatagram() (*[]byte, error) {
	if fc == nil || fc.conn == nil {
		return nil, net.ErrClosed
	}
	fc.rmu.Lock()
	defer fc.rmu.Unlock()
	if fc.rerr != nil {
		return nil, fc.rerr
	}
	if err := fc.takePendingLocked(); err != nil {
		return nil, err
	}
	n := fc.remain
	if n == 0 {
		var err error
		if n, err = fc.readHeaderLocked(); err != nil {
			return nil, err
		}
	}
	bp := getDatagramBuf(n)
	if m, err := io.ReadFull(fc.reader(), *bp); err != nil {
		putDatagramBuf(bp)
		if m == 0 && !streamEnded(err) {
			// No payload byte was lost: the next call reads the frame.
			fc.remain = n
			return nil, err
		}
		return nil, fc.failReadLocked(err)
	}
	fc.remain = 0
	return bp, nil
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
		if m == 0 && !streamEnded(err) {
			// No payload byte was lost: the next call reads the frame.
			fc.remain = n
			return 0, err
		}
		return 0, fc.failReadLocked(err)
	}
	fc.remain = 0
	if rest := n - k; rest > 0 {
		var discarded int64
		var err error
		if fc.br != nil {
			var d int
			d, err = fc.br.Discard(rest)
			discarded = int64(d)
		} else {
			discarded, err = io.CopyN(io.Discard, fc.conn, int64(rest))
		}
		if err != nil {
			if k == 0 && discarded == 0 && !streamEnded(err) {
				// No payload byte was lost: the next call reads the frame.
				fc.remain = n
				return 0, err
			}
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

// Write sends p as one frame. With stream reads, the default, a p longer than
// MaxFramePayload is sent as several frames, which the reader joins up again,
// so that io.Copy into a FramedConn works with any buffer; it returns the
// bytes of the frames sent whole. With WithFramedDatagrams, where each
// frame is a message, such a p fails with ErrFrameTooLarge, as WriteFrame
// does in both modes.
func (fc *FramedConn) Write(p []byte) (int, error) {
	if fc == nil || fc.conn == nil {
		return 0, net.ErrClosed
	}
	if len(p) > MaxFramePayload && fc.datagram {
		return 0, ErrFrameTooLarge
	}
	fc.wmu.Lock()
	defer fc.wmu.Unlock()

	written := 0
	for {
		n := min(len(p)-written, MaxFramePayload)
		if err := fc.writeFrameLocked(p[written : written+n]); err != nil {
			return written, err
		}
		if written += n; written == len(p) {
			return written, nil
		}
	}
}

// WriteFrame writes one complete frame.
func (fc *FramedConn) WriteFrame(p []byte) error {
	if fc == nil || fc.conn == nil {
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
	if fc == nil || fc.conn == nil {
		return net.ErrClosed
	}
	// Counted once set, so that a Read that times out at the old deadline
	// before it does not keep that timeout.
	defer fc.rdeadlines.Add(1)
	return fc.conn.SetDeadline(t)
}

func (fc *FramedConn) SetReadDeadline(t time.Time) error {
	if fc == nil || fc.conn == nil {
		return net.ErrClosed
	}
	defer fc.rdeadlines.Add(1) // as in SetDeadline
	return fc.conn.SetReadDeadline(t)
}

func (fc *FramedConn) SetWriteDeadline(t time.Time) error {
	if fc == nil || fc.conn == nil {
		return net.ErrClosed
	}
	return fc.conn.SetWriteDeadline(t)
}

func (fc *FramedConn) LocalAddr() net.Addr {
	if fc == nil || fc.conn == nil {
		return nil
	}
	return fc.conn.LocalAddr()
}

func (fc *FramedConn) RemoteAddr() net.Addr {
	if fc == nil || fc.conn == nil {
		return nil
	}
	return fc.conn.RemoteAddr()
}

func (fc *FramedConn) Close() error {
	if fc == nil || fc.conn == nil {
		return nil
	}
	return fc.conn.Close()
}

// CloseWrite shuts down the writing side of the wrapped connection after the
// frames written so far; see TimeoutConn.CloseWrite.
func (fc *FramedConn) CloseWrite() error {
	if fc == nil || fc.conn == nil {
		return net.ErrClosed
	}
	fc.wmu.Lock()
	defer fc.wmu.Unlock()
	return closeWrite(fc.conn)
}

// NetConn returns the connection that fc wraps, as *tls.Conn's NetConn does;
// see InnermostConn and ConnAs. Reading or writing it directly breaks the
// framing.
func (fc *FramedConn) NetConn() net.Conn {
	if fc == nil {
		return nil
	}
	return fc.conn
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
	if fc == nil || fc.conn == nil {
		return net.ErrClosed
	}
	if fc.werr != nil {
		return fc.werr
	}
	var (
		written int64
		err     error
	)
	if _, ok := fc.conn.(*net.TCPConn); ok {
		// The header and vector live in fc, so the writev does not allocate.
		binary.BigEndian.PutUint16(fc.whdr[:], uint16(len(p)))
		fc.wvec = [2][]byte{fc.whdr[:], p}
		fc.wbufs = fc.wvec[:]
		written, err = writeBuffers(fc.conn, &fc.wbufs)
		fc.wvec = [2][]byte{} // do not keep p reachable
	} else {
		// One Write per frame, so wrappers such as TLS or mux streams do not
		// emit a separate record or packet for the 2-byte header.
		bp := framedWriteBufPool.Get().(*[]byte)
		buf := binary.BigEndian.AppendUint16((*bp)[:0], uint16(len(p)))
		buf = append(buf, p...)
		var n int
		n, err = writeAll(fc.conn, buf)
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
