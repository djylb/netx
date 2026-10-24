package wsconn

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/djylb/netx/httphead"
)

// Conn is a WebSocket connection after the opening handshake. See the
// package documentation for the rules of concurrent use.
type Conn struct {
	conn   net.Conn
	br     *bufio.Reader
	client bool
	// writev is set for connections whose net.Buffers writes are one
	// writev(2), so that a server writes a header and a payload at once
	// without copying the payload.
	writev bool

	subprotocol string
	request     *httphead.Request
	response    *httphead.Response

	readLimit    int64
	closeTimeout time.Duration
	onPing       func(*Conn, []byte)
	onPong       func(*Conn, []byte)
	deflate      *deflateConfig // nil without permessage-deflate

	// The read side, used by the one reader and by Close, which may drain
	// it: rsem is held through each read call.
	rsem    chan struct{}
	rerr    error // sticky
	rmsg    byte  // opcode of the message being read; 0 between messages
	rfin    bool  // the current frame is its message's last
	rcomp   bool  // the message is compressed
	rmasked bool
	rkey    uint32
	rpos    int
	rremain int64 // payload bytes left in the current frame
	rlen    int64 // bytes of the message delivered
	rlimit  int64 // bound of the current message; negative for none
	rtail   int   // bytes of deflateTail handed to the inflater
	rseq    uint64
	rutf    utf8State
	rawErr  error // the last error that raw returned to the inflater
	inflate io.ReadCloser
	raw     rawReader
	ctrl    [maxControlPayload]byte

	// msgMu is held from the first to the last frame of a data message,
	// frameMu through the writing of one frame.
	msgMu   sync.Mutex
	frameMu sync.Mutex
	werr    error // sticky; under frameMu
	whb     [maxHeaderLen]byte
	wctrl   [maxHeaderLen + maxControlPayload]byte
	wbufArr [2][]byte
	wbufs   net.Buffers

	// wdMu guards wd, the write deadline set through the Conn or by
	// Close, and pongBound, the bound of a pong that the reader writes.
	wdMu      sync.Mutex
	wd        time.Time
	rd        time.Time // the read deadline set through the Conn
	pongBound time.Time

	closeSent   atomic.Bool // set under frameMu, or when Close gave up on it
	pongPending atomic.Bool
	pongMu      sync.Mutex
	pongLen     int
	pongData    [maxControlPayload]byte

	closing   atomic.Bool  // Close was called
	closeBy   atomic.Int64 // Close's deadline, in Unix nanoseconds
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	done      chan struct{} // closed with the connection beneath
}

// NewConn returns a connection over conn, whose opening handshake is done,
// as the client when client is set and otherwise as the server: for a
// handshake of another kind, such as WebSocket over HTTP/2 (RFC 8441), or
// for tests. br, if not nil, is the buffered reader over conn that holds
// what the peer sent after the handshake. A set opts.Compression means
// that permessage-deflate was negotiated without context takeover in
// either direction. opts may be nil.
func NewConn(conn net.Conn, br *bufio.Reader, client bool, opts *Options) *Conn {
	if opts == nil {
		opts = &Options{}
	}
	var dc *deflateConfig
	if opts.Compression != nil {
		dc = opts.Compression.config()
	}
	return newConn(conn, br, client, opts, dc)
}

func newConn(conn net.Conn, br *bufio.Reader, client bool, o *Options, dc *deflateConfig) *Conn {
	size := o.readBufferSize()
	switch {
	case br == nil:
		br = bufio.NewReaderSize(conn, size)
	case br.Size() < minReadBufferSize:
		// Whole control frames must fit in the buffer; the new reader
		// reads what br holds first.
		br = bufio.NewReaderSize(br, minReadBufferSize)
	}
	c := &Conn{
		conn:         conn,
		br:           br,
		client:       client,
		readLimit:    o.readLimit(),
		closeTimeout: o.closeTimeout(),
		onPing:       o.OnPing,
		onPong:       o.OnPong,
		deflate:      dc,
		rsem:         make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
	c.raw.c = c
	switch conn.(type) {
	case *net.TCPConn, *net.UnixConn:
		c.writev = true
	}
	return c
}

// Subprotocol returns the negotiated subprotocol, or "" for none.
func (c *Conn) Subprotocol() string { return c.subprotocol }

// Compressed reports whether permessage-deflate was negotiated.
func (c *Conn) Compressed() bool { return c.deflate != nil }

// Request returns the handshake request of a server connection, nil for a
// client or a connection from NewConn.
func (c *Conn) Request() *httphead.Request { return c.request }

// Response returns the handshake response of a client connection, nil for
// a server or a connection from NewConn.
func (c *Conn) Response() *httphead.Response { return c.response }

// NetConn returns the connection beneath, as *tls.Conn's NetConn does. It
// carries frames: reading or writing it corrupts the WebSocket connection.
func (c *Conn) NetConn() net.Conn { return c.conn }

// LocalAddr returns the local address of the connection beneath.
func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the remote address of the connection beneath.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline sets the read and write deadlines of the connection beneath.
// A read or write that a deadline cuts short leaves the connection usable,
// except one that wrote part of a frame or read part of a compressed
// message, which fails it.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline of the connection beneath. It
// also bounds the automatic pongs that the reader writes.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.wdMu.Lock()
	c.rd = t
	c.wdMu.Unlock()
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline of the connection beneath.
// While the reader writes an automatic pong, which it bounds by the close
// timeout and the read deadline, the earlier of the two applies.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.wdMu.Lock()
	defer c.wdMu.Unlock()
	c.wd = t
	return c.conn.SetWriteDeadline(c.effectiveWD())
}

// effectiveWD returns the write deadline in effect: the user's, or the
// earlier pong bound of the reader. wdMu is held.
func (c *Conn) effectiveWD() time.Time {
	if !c.pongBound.IsZero() && (c.wd.IsZero() || c.pongBound.Before(c.wd)) {
		return c.pongBound
	}
	return c.wd
}

// errStaleReader is returned by a reader from NextReader once the next
// message was begun.
var errStaleReader = errors.New("wsconn: read from a reader of an earlier message")

// errCloseSent is returned by writes after the close frame was sent.
var errCloseSent = fmt.Errorf("wsconn: close frame sent: %w", net.ErrClosed)

// NextReader returns the type of the next data message and a reader of its
// payload, which reads io.EOF at its end and is valid until the next call
// of NextReader, ReadMessage or AppendMessage, which discards what is left
// of it. After the peer's close frame it returns a *CloseError.
func (c *Conn) NextReader() (MessageType, io.Reader, error) {
	c.rsem <- struct{}{}
	defer func() { <-c.rsem }()
	typ, err := c.beginMessage(c.readLimit)
	if err != nil {
		return 0, nil, err
	}
	return typ, &messageReader{c: c, seq: c.rseq}, nil
}

// ReadMessage reads the next data message.
func (c *Conn) ReadMessage() (MessageType, []byte, error) {
	return c.AppendMessage(nil)
}

// AppendMessage reads the next data message, appends its payload to b and
// returns the extended slice, so that a reused b reads messages without
// allocating.
func (c *Conn) AppendMessage(b []byte) (MessageType, []byte, error) {
	c.rsem <- struct{}{}
	defer func() { <-c.rsem }()
	typ, err := c.beginMessage(c.readLimit)
	if err != nil {
		return 0, b, err
	}
	for {
		need := 0
		switch {
		case c.rcomp:
			need = 4096
		case c.rremain > 0:
			need = int(min(c.rremain, 1<<20))
		}
		if cap(b)-len(b) < need {
			b = slices.Grow(b, need)
		}
		n, err := c.readMessage(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err == io.EOF {
			return typ, b, nil
		}
		if err != nil {
			return 0, b, err
		}
	}
}

// messageReader reads one message for NextReader.
type messageReader struct {
	c   *Conn
	seq uint64
}

func (r *messageReader) Read(p []byte) (int, error) {
	c := r.c
	c.rsem <- struct{}{}
	defer func() { <-c.rsem }()
	if r.seq != c.rseq {
		return 0, errStaleReader
	}
	if len(p) == 0 {
		return 0, nil
	}
	return c.readMessage(p)
}

// readEntry returns the error that reads return before reading anything.
func (c *Conn) readEntry() error {
	if c.rerr != nil {
		return c.rerr
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	return nil
}

// beginMessage discards what is left of the current message and reads up
// to the first frame of the next one, which limit bounds.
func (c *Conn) beginMessage(limit int64) (MessageType, error) {
	if err := c.readEntry(); err != nil {
		return 0, err
	}
	if c.rmsg != 0 {
		if err := c.skipMessage(); err != nil {
			return 0, err
		}
	}
	c.rlimit = limit
	if err := c.nextDataFrame(); err != nil {
		return 0, err
	}
	c.rseq++
	return MessageType(c.rmsg), nil
}

// readMessage reads the payload of the current message into p, returning
// io.EOF at its end.
func (c *Conn) readMessage(p []byte) (int, error) {
	if err := c.readEntry(); err != nil {
		return 0, err
	}
	if c.rmsg == 0 {
		return 0, io.EOF
	}
	var n int
	var err error
	if c.rcomp {
		n, err = c.inflateRead(p)
	} else {
		n, err = c.readRaw(p)
	}
	if n > 0 {
		c.rlen += int64(n)
		if c.rlimit >= 0 && c.rlen > c.rlimit {
			return 0, c.fail(StatusMessageTooBig, ErrMessageTooLarge)
		}
		if c.rmsg == opText && !c.rutf.write(p[:n]) {
			return 0, c.fail(StatusInvalidPayload, ErrInvalidUTF8)
		}
	}
	if err == io.EOF {
		if c.rmsg == opText && !c.rutf.done() {
			return 0, c.fail(StatusInvalidPayload, ErrInvalidUTF8)
		}
		c.endMessage()
	}
	return n, err
}

// endMessage ends the current message.
func (c *Conn) endMessage() {
	if c.inflate != nil {
		putInflater(c.inflate)
		c.inflate = nil
	}
	c.rmsg = 0
	c.rremain = 0
	c.rutf = utf8State{}
}

// skipMessage discards the rest of the current message.
func (c *Conn) skipMessage() error {
	if err := c.discardRaw(); err != nil {
		return err
	}
	c.endMessage()
	return nil
}

// discardRaw discards the payload left in the frames of the current
// message.
func (c *Conn) discardRaw() error {
	for {
		for c.rremain > 0 {
			n, err := c.br.Discard(int(min(c.rremain, 1<<30)))
			c.rremain -= int64(n)
			if err != nil {
				return c.readErr(err, true)
			}
		}
		if c.rfin {
			return nil
		}
		if err := c.nextDataFrame(); err != nil {
			return err
		}
	}
}

// readRaw reads payload of the current message, across its frames, and
// returns io.EOF after its last frame.
func (c *Conn) readRaw(p []byte) (int, error) {
	for c.rremain == 0 {
		if c.rfin {
			return 0, io.EOF
		}
		if err := c.nextDataFrame(); err != nil {
			return 0, err
		}
	}
	if int64(len(p)) > c.rremain {
		p = p[:c.rremain]
	}
	n, err := c.br.Read(p)
	c.rremain -= int64(n)
	if c.rmasked {
		c.rpos = mask(p[:n], c.rkey, c.rpos)
	}
	if err != nil {
		if n > 0 {
			// The error comes again with the next read.
			return n, nil
		}
		return 0, c.readErr(err, true)
	}
	return n, nil
}

// readErr returns the error for err of the connection beneath: io.EOF
// becomes io.ErrUnexpectedEOF inside a frame or a message. Errors other
// than timeouts are sticky; a timeout leaves the frame state as it was.
func (c *Conn) readErr(err error, inside bool) error {
	if err == io.EOF && (inside || c.rmsg != 0) {
		err = io.ErrUnexpectedEOF
	}
	if !isTimeout(err) {
		c.rerr = err
	}
	return err
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// nextDataFrame reads frames up to the next data frame, handling the
// control frames before it, and makes it the current frame. A frame header
// and a control frame's payload are read at once, so that a read cut short
// by a deadline leaves no frame half read.
func (c *Conn) nextDataFrame() error {
	for {
		h, err := c.br.Peek(2)
		if err != nil {
			return c.readErr(err, len(h) > 0)
		}
		b0, b1 := h[0], h[1]
		op := b0 & 0x0f
		control := op&0x8 != 0
		masked := b1&maskBit != 0
		n := int64(b1 & 0x7f)
		hl := 2
		switch n {
		case 126:
			hl += 2
		case 127:
			hl += 8
		}
		if masked {
			hl += 4
		}
		total := hl
		if control && n <= maxControlPayload {
			total += int(n)
		}
		if h, err = c.br.Peek(total); err != nil {
			return c.readErr(err, true)
		}
		switch n {
		case 126:
			n = int64(binary.BigEndian.Uint16(h[2:]))
		case 127:
			v := binary.BigEndian.Uint64(h[2:])
			if v>>63 != 0 {
				return c.fail(StatusProtocolError, protocolError("payload length over 2^63-1"))
			}
			n = int64(v)
		}
		var key uint32
		if masked {
			key = binary.LittleEndian.Uint32(h[hl-4:])
		}
		fin := b0&finBit != 0
		rsv := b0 & (rsv1Bit | rsv2Bit | rsv3Bit)
		switch {
		case masked && c.client:
			return c.fail(StatusProtocolError, protocolError("masked frame from the server"))
		case !masked && !c.client:
			return c.fail(StatusProtocolError, protocolError("unmasked frame from the client"))
		}
		if control {
			switch {
			case op > opPong:
				return c.fail(StatusProtocolError, protocolError(fmt.Sprintf("reserved opcode %#x", op)))
			case !fin:
				return c.fail(StatusProtocolError, protocolError("fragmented control frame"))
			case n > maxControlPayload:
				return c.fail(StatusProtocolError, protocolError("control frame over 125 bytes"))
			case rsv != 0:
				return c.fail(StatusProtocolError, protocolError("reserved bits set on a control frame"))
			}
			payload := c.ctrl[:n]
			copy(payload, h[hl:total])
			_, _ = c.br.Discard(total)
			if masked {
				mask(payload, key, 0)
			}
			if err := c.control(op, payload); err != nil {
				return err
			}
			continue
		}
		inMessage := c.rmsg != 0
		switch {
		case op > opBinary:
			return c.fail(StatusProtocolError, protocolError(fmt.Sprintf("reserved opcode %#x", op)))
		case rsv&(rsv2Bit|rsv3Bit) != 0:
			return c.fail(StatusProtocolError, protocolError("reserved bits set"))
		case op == opContinuation && !inMessage:
			return c.fail(StatusProtocolError, protocolError("continuation frame outside a message"))
		case op != opContinuation && inMessage:
			return c.fail(StatusProtocolError, protocolError("data frame inside a fragmented message"))
		case rsv&rsv1Bit != 0 && (c.deflate == nil || op == opContinuation):
			return c.fail(StatusProtocolError, protocolError("RSV1 set without a compressed message"))
		}
		_, _ = c.br.Discard(hl)
		if op != opContinuation {
			c.rmsg = op
			c.rcomp = rsv != 0
			c.rlen = 0
			c.rtail = 0
		}
		c.rfin = fin
		c.rremain = n
		c.rmasked = masked
		c.rkey = key
		c.rpos = 0
		if !c.rcomp && c.rlimit >= 0 && n > c.rlimit-c.rlen {
			return c.fail(StatusMessageTooBig, ErrMessageTooLarge)
		}
		return nil
	}
}

// control handles a control frame.
func (c *Conn) control(op byte, payload []byte) error {
	switch op {
	case opPing:
		if c.onPing != nil {
			c.onPing(c, payload)
		}
		c.queuePong(payload)
	case opPong:
		if c.onPong != nil {
			c.onPong(c, payload)
		}
	case opClose:
		return c.peerClose(payload)
	}
	return nil
}

// peerClose handles the peer's close frame: it answers it, unless a close
// frame was sent, and ends the connection.
func (c *Conn) peerClose(p []byte) error {
	ce := &CloseError{Code: StatusNoStatusReceived}
	switch {
	case len(p) == 1:
		return c.fail(StatusProtocolError, protocolError("close frame with a 1-byte payload"))
	case len(p) >= 2:
		ce.Code = StatusCode(binary.BigEndian.Uint16(p))
		if !ce.Code.Sendable() {
			return c.fail(StatusProtocolError, protocolError(fmt.Sprintf("close code %d", ce.Code)))
		}
		if !utf8.Valid(p[2:]) {
			return c.fail(StatusInvalidPayload, ErrInvalidUTF8)
		}
		ce.Reason = string(p[2:])
	}
	c.rerr = ce
	echo := ce.Code
	if echo == StatusNoStatusReceived {
		echo = 0
	}
	_ = c.sendClose(echo, "", c.closeDeadline())
	c.finish()
	return ce
}

// finish ends the connection after the closing handshake. The server
// closes the connection beneath first (RFC 6455, section 7.1.1); the client
// waits for that, within the close timeout.
func (c *Conn) finish() {
	if c.client && c.closeTimeout > 0 {
		_ = c.conn.SetReadDeadline(c.closeDeadline())
		_, _ = io.Copy(io.Discard, c.br)
	}
	c.closeConn()
}

// closeDeadline returns the deadline of the closing handshake: Close's, or
// one close timeout ahead for a handshake that the peer started.
func (c *Conn) closeDeadline() time.Time {
	if ns := c.closeBy.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Now().Add(c.closeTimeout.Abs())
}

// fail fails the connection with err after sending a close frame with
// code.
func (c *Conn) fail(code StatusCode, err error) error {
	c.rerr = err
	_ = c.sendClose(code, "", c.closeDeadline())
	c.closeConn()
	return err
}

func (c *Conn) closeConn() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = c.conn.Close()
		close(c.done)
	})
}

// Close sends a close frame with StatusNormalClosure, waits for the peer's
// and closes the connection beneath, all within the close timeout, also
// when a write is blocked, which then fails. Called from Options.OnPing or
// OnPong, which hold the reader, it waits the whole close timeout. A
// second Close returns an error matching net.ErrClosed.
func (c *Conn) Close() error { return c.CloseWithStatus(StatusNormalClosure, "") }

// CloseWithStatus is Close with a status code, which must be Sendable, and
// a reason of at most 123 bytes of UTF-8, which may be empty.
func (c *Conn) CloseWithStatus(code StatusCode, reason string) error {
	if !code.Sendable() {
		return fmt.Errorf("wsconn: close code %d cannot be sent", code)
	}
	if !validCloseReason(reason) {
		return errors.New("wsconn: close reason over 123 bytes or not UTF-8")
	}
	if c.closing.Swap(true) {
		return fmt.Errorf("wsconn: close: %w", net.ErrClosed)
	}
	deadline := time.Now().Add(c.closeTimeout.Abs())
	c.closeBy.Store(deadline.UnixNano())
	if c.sendClose(code, reason, deadline) == nil && c.closeTimeout > 0 {
		c.awaitPeer(deadline)
	}
	c.closeConn()
	if c.closeErr != nil && !errors.Is(c.closeErr, net.ErrClosed) {
		return c.closeErr
	}
	return nil
}

// awaitPeer waits for the end of the closing handshake until deadline: for
// the reader to get the peer's close frame, or, while no read is in
// progress, it reads itself, discarding messages.
func (c *Conn) awaitPeer(deadline time.Time) {
	_ = c.conn.SetReadDeadline(deadline)
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case c.rsem <- struct{}{}:
		for c.rerr == nil && !c.closed.Load() {
			if c.rmsg != 0 {
				if c.skipMessage() != nil {
					break
				}
				continue
			}
			c.rlimit = -1
			if c.nextDataFrame() != nil {
				break
			}
		}
		<-c.rsem
	case <-c.done:
	case <-t.C:
	}
}

// sendClose sends a close frame with code, none for 0, unless one was
// sent. deadline bounds the write, also a write of another goroutine that
// holds the connection, which then fails; with a negative close timeout it
// sends the frame only when no write is in progress.
func (c *Conn) sendClose(code StatusCode, reason string, deadline time.Time) error {
	if c.closeTimeout < 0 {
		if !c.frameMu.TryLock() {
			c.closeSent.Store(true)
			return errCloseSent
		}
		c.boundWrites(deadline)
	} else {
		c.boundWrites(deadline)
		c.frameMu.Lock()
	}
	defer c.unlockFrame()
	if c.closeSent.Load() {
		return nil
	}
	c.closeSent.Store(true)
	if c.werr != nil {
		return c.werr
	}
	var p [maxControlPayload]byte
	n := 0
	if code != 0 {
		binary.BigEndian.PutUint16(p[:], uint16(code))
		n = 2 + copy(p[2:], reason)
	}
	return c.writeControlLocked(opClose, p[:n])
}

// boundWrites brings the write deadline forward to deadline, for the
// closing handshake.
func (c *Conn) boundWrites(deadline time.Time) {
	c.wdMu.Lock()
	defer c.wdMu.Unlock()
	if c.wd.IsZero() || deadline.Before(c.wd) {
		c.wd = deadline
	}
	_ = c.conn.SetWriteDeadline(c.effectiveWD())
}

// Ping sends a ping with data, at most 125 bytes. The peer's pong reaches
// Options.OnPong while reading.
func (c *Conn) Ping(data []byte) error { return c.writeControl(opPing, data) }

// Pong sends an unsolicited pong with data, at most 125 bytes, as a
// heartbeat that needs no answer. Pings are answered automatically.
func (c *Conn) Pong(data []byte) error { return c.writeControl(opPong, data) }

func (c *Conn) writeControl(op byte, data []byte) error {
	if len(data) > maxControlPayload {
		return errors.New("wsconn: control frame payload over 125 bytes")
	}
	c.frameMu.Lock()
	defer c.unlockFrame()
	if err := c.writableLocked(); err != nil {
		return err
	}
	return c.writeControlLocked(op, data)
}

// queuePong answers a ping without waiting for a write in progress: the
// writer that holds frameMu sends the pong when it lets go. Only the pong
// for the last ping is sent, as RFC 6455 allows. When no write is in
// progress the reader writes the pong itself, bounded by the close timeout
// (DefaultCloseTimeout when negative), so that a peer that sends pings but
// does not read cannot hold the reader, nor past its read deadline: a pong
// that does not go out in time is dropped, and one that went out in part
// fails the writes.
func (c *Conn) queuePong(data []byte) {
	c.pongMu.Lock()
	c.pongLen = copy(c.pongData[:], data)
	c.pongMu.Unlock()
	c.pongPending.Store(true)
	for c.pongPending.Load() && c.frameMu.TryLock() {
		d := c.closeTimeout
		if d <= 0 {
			d = DefaultCloseTimeout
		}
		c.wdMu.Lock()
		c.pongBound = time.Now().Add(d)
		if !c.rd.IsZero() && c.rd.Before(c.pongBound) {
			c.pongBound = c.rd
		}
		_ = c.conn.SetWriteDeadline(c.effectiveWD())
		c.wdMu.Unlock()
		c.flushPongLocked()
		c.wdMu.Lock()
		c.pongBound = time.Time{}
		_ = c.conn.SetWriteDeadline(c.wd)
		c.wdMu.Unlock()
		c.frameMu.Unlock()
	}
}

// flushPongLocked sends the queued pong.
func (c *Conn) flushPongLocked() {
	c.pongMu.Lock()
	var p [maxControlPayload]byte
	n := copy(p[:], c.pongData[:c.pongLen])
	c.pongPending.Store(false)
	c.pongMu.Unlock()
	if c.writableLocked() == nil {
		_ = c.writeControlLocked(opPong, p[:n])
	}
}

// unlockFrame sends a queued pong and unlocks frameMu, and sends a pong
// queued while it unlocked.
func (c *Conn) unlockFrame() {
	for {
		if c.pongPending.Load() {
			c.flushPongLocked()
		}
		c.frameMu.Unlock()
		if !c.pongPending.Load() || !c.frameMu.TryLock() {
			return
		}
	}
}

// writableLocked returns the error that writes fail with.
func (c *Conn) writableLocked() error {
	if c.closeSent.Load() {
		return errCloseSent
	}
	return c.werr
}

// writeDone makes a write error sticky unless the write timed out before
// it wrote anything of its frame.
func (c *Conn) writeDone(wrote bool, err error) error {
	if err != nil && (wrote || !isTimeout(err)) {
		c.werr = err
	}
	return err
}

// maskKey returns a masking key. The key keeps a peer's script from
// choosing the bytes on the wire (RFC 6455, section 10.3); the runtime's
// generator, ChaCha8 seeded from the system, is unpredictable enough for
// that, and crypto/rand would add its FIPS machinery to a program.
func maskKey() uint32 { return rand.Uint32() }

// writeControlLocked writes a control frame in one write.
func (c *Conn) writeControlLocked(op byte, data []byte) error {
	var key uint32
	if c.client {
		key = maskKey()
	}
	off := putHeader(&c.whb, finBit|op, len(data), c.client, key)
	m := copy(c.wctrl[:], c.whb[off:])
	if c.client {
		maskCopy(c.wctrl[m:], data, key, 0)
	} else {
		copy(c.wctrl[m:], data)
	}
	n, err := c.conn.Write(c.wctrl[:m+len(data)])
	return c.writeDone(n > 0, err)
}

// writevThreshold is the payload size from which a server writes a frame
// with writev rather than copying it behind its header: one that does not
// fit the write buffer, which would take two writes. Smaller frames are
// copied, as one write costs the same on Linux and less on macOS.
const writevThreshold = writeBufSize + 1

// writeFrameLocked writes a data frame with payload p, whose first header
// byte is first.
func (c *Conn) writeFrameLocked(first byte, p []byte) error {
	if err := c.writableLocked(); err != nil {
		return err
	}
	var key uint32
	if c.client {
		key = maskKey()
	}
	off := putHeader(&c.whb, first, len(p), c.client, key)
	hdr := c.whb[off:]
	if !c.client && c.writev && len(p) >= writevThreshold {
		c.wbufs = append(c.wbufArr[:0], hdr, p)
		n, err := c.wbufs.WriteTo(c.conn)
		c.wbufArr = [2][]byte{}
		return c.writeDone(n > 0, err)
	}
	bp := getWriteBuf()
	defer putWriteBuf(bp)
	buf := *bp
	m := copy(buf, hdr)
	pos := 0
	wrote := false
	for {
		k := min(len(p), len(buf)-m)
		if c.client {
			pos = maskCopy(buf[m:], p[:k], key, pos)
		} else {
			copy(buf[m:], p[:k])
		}
		n, err := c.conn.Write(buf[:m+k])
		wrote = wrote || n > 0
		if err != nil {
			return c.writeDone(wrote, err)
		}
		p = p[k:]
		m = 0
		if len(p) == 0 {
			return nil
		}
		if !c.client {
			// The header went out with the first chunk; the rest needs no
			// copy.
			_, err := c.conn.Write(p)
			return c.writeDone(true, err)
		}
	}
}

// writeBufferedLocked writes a data frame whose payload is buf[maxHeaderLen:
// maxHeaderLen+n], putting the header before it and masking it in place.
func (c *Conn) writeBufferedLocked(first byte, buf []byte, n int) error {
	if err := c.writableLocked(); err != nil {
		return err
	}
	var key uint32
	if c.client {
		key = maskKey()
	}
	off := putHeader(&c.whb, first, n, c.client, key)
	start := off
	copy(buf[start:maxHeaderLen], c.whb[off:])
	if c.client {
		mask(buf[maxHeaderLen:maxHeaderLen+n], key, 0)
	}
	w, err := c.conn.Write(buf[start : maxHeaderLen+n])
	return c.writeDone(w > 0, err)
}

// WriteMessage sends p as a message of type typ in one frame, compressed
// when permessage-deflate was negotiated and p is not shorter than the
// compression threshold. A server copies at most 32 KiB of p: a frame that
// fits the write buffer goes out with its header in one write, and a
// larger one with writev on TCP and Unix connections, or else as its
// header with the first 32 KiB and then the rest. A client masks p into
// the write buffer, 32 KiB at a time.
func (c *Conn) WriteMessage(typ MessageType, p []byte) error {
	if typ != Text && typ != Binary {
		return fmt.Errorf("wsconn: cannot write a message of type %v", typ)
	}
	if c.deflate != nil && len(p) >= c.deflate.threshold {
		w := c.newWriter(typ)
		_, err := w.Write(p)
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		return err
	}
	c.msgMu.Lock()
	defer c.msgMu.Unlock()
	c.frameMu.Lock()
	defer c.unlockFrame()
	return c.writeFrameLocked(finBit|byte(typ), p)
}

// NextWriter returns a writer of a message of type typ, which is sent in
// frames of up to 32 KiB, or of what a larger Write gets, and ends with
// Close. Other messages wait until it is closed, while control frames go
// out between its frames. When permessage-deflate was negotiated, the
// message is compressed.
func (c *Conn) NextWriter(typ MessageType) (io.WriteCloser, error) {
	if typ != Text && typ != Binary {
		return nil, fmt.Errorf("wsconn: cannot write a message of type %v", typ)
	}
	return c.newWriter(typ), nil
}

const writeBufSize = 32 << 10

var writeBufPool = sync.Pool{New: func() any {
	b := make([]byte, maxHeaderLen+writeBufSize)
	return &b
}}

func getWriteBuf() *[]byte  { return writeBufPool.Get().(*[]byte) }
func putWriteBuf(b *[]byte) { writeBufPool.Put(b) }

// messageWriter writes a message for NextWriter.
type messageWriter struct {
	c     *Conn
	bp    *[]byte
	n     int // payload bytes in the buffer, after maxHeaderLen
	fw    flateWriter
	err   error
	first byte // the first header byte of the next frame
	done  bool
}

func (c *Conn) newWriter(typ MessageType) *messageWriter {
	c.msgMu.Lock()
	w := &messageWriter{c: c, first: byte(typ), bp: getWriteBuf()}
	if c.deflate != nil {
		w.first |= rsv1Bit
		w.fw = getDeflater(c.deflate.level, (*deflateSink)(w))
	}
	return w
}

func (w *messageWriter) Write(p []byte) (int, error) {
	if w.done {
		return 0, errors.New("wsconn: write to a closed message writer")
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.fw != nil {
		n, err := w.fw.Write(p)
		if err != nil && w.err == nil {
			w.err = err
		}
		return n, err
	}
	total := len(p)
	buf := *w.bp
	for len(p) > 0 {
		if w.n == 0 && len(p) >= writeBufSize {
			// A large write goes out as a frame of its own.
			if err := w.frame(p, false); err != nil {
				return total - len(p), err
			}
			return total, nil
		}
		if w.n == writeBufSize {
			if err := w.flush(w.n, false); err != nil {
				return total - len(p), err
			}
		}
		k := copy(buf[maxHeaderLen+w.n:], p)
		w.n += k
		p = p[k:]
	}
	return total, nil
}

// frame writes p as the next frame.
func (w *messageWriter) frame(p []byte, fin bool) error {
	first := w.first
	if fin {
		first |= finBit
	}
	c := w.c
	c.frameMu.Lock()
	err := c.writeFrameLocked(first, p)
	w.failLocked(err)
	c.unlockFrame()
	w.first = opContinuation
	if err != nil {
		w.err = err
	}
	return err
}

// flush writes the first n buffered bytes as the next frame and moves what
// follows them to the front.
func (w *messageWriter) flush(n int, fin bool) error {
	first := w.first
	if fin {
		first |= finBit
	}
	c := w.c
	buf := *w.bp
	c.frameMu.Lock()
	err := c.writeBufferedLocked(first, buf, n)
	w.failLocked(err)
	c.unlockFrame()
	w.first = opContinuation
	w.n = copy(buf[maxHeaderLen:], buf[maxHeaderLen+n:maxHeaderLen+w.n])
	if err != nil {
		w.err = err
	}
	return err
}

// failLocked fails the connection's writes on an error after the first
// frame of the message went out: the message cannot be finished, and a
// frame of another message would break the order of fragments.
func (w *messageWriter) failLocked(err error) {
	if err != nil && w.first == opContinuation && w.c.werr == nil {
		w.c.werr = err
	}
}

// Close sends the last frame of the message and lets other messages go
// out.
func (w *messageWriter) Close() error {
	if w.done {
		return nil
	}
	err := w.err
	if err == nil {
		if w.fw != nil {
			err = w.fw.Flush()
			if err == nil {
				// A flushed deflate stream ends in 00 00 ff ff, which
				// RFC 7692 leaves out.
				err = w.flush(w.n-len(syncTail), true)
			}
		} else {
			err = w.flush(w.n, true)
		}
	}
	w.done = true
	if w.fw != nil {
		putDeflater(w.c.deflate.level, w.fw)
		w.fw = nil
	}
	putWriteBuf(w.bp)
	w.bp = nil
	w.c.msgMu.Unlock()
	return err
}

// deflateSink takes the compressed bytes of a messageWriter, keeping the
// last four in the buffer, which may be the end of the message.
type deflateSink messageWriter

func (s *deflateSink) Write(p []byte) (int, error) {
	w := (*messageWriter)(s)
	total := len(p)
	buf := *w.bp
	for len(p) > 0 {
		if w.n == writeBufSize {
			if err := w.flush(w.n-len(syncTail), false); err != nil {
				return total - len(p), err
			}
		}
		k := copy(buf[maxHeaderLen+w.n:], p)
		w.n += k
		p = p[k:]
	}
	return total, nil
}
