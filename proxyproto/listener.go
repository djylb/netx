package proxyproto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultHeaderTimeout bounds how long a Conn waits for its header when the
// Listener's HeaderTimeout is not positive.
const DefaultHeaderTimeout = 10 * time.Second

// Policy tells a Listener whether a peer sends a PROXY protocol header.
type Policy uint8

const (
	// Required rejects connections that do not start with a header: their
	// first read returns ErrNoHeader. It is the zero value.
	Required Policy = iota
	// Optional uses a header when the connection starts with one and
	// otherwise passes the stream through unchanged, including when it
	// stops, by the header timeout or its end, after at most the start of a
	// signature, as a peer that waits for the server to speak first does.
	Optional
	// Ignore passes the connection through without looking for a header.
	Ignore
)

// Listener wraps a net.Listener whose peers, such as load balancers, send a
// PROXY protocol header, and reports the addresses from the header as the
// connections' RemoteAddr and LocalAddr.
//
// Only trusted peers should be allowed to send a header, since it lets them
// choose the reported client address; use Policy to restrict them.
type Listener struct {
	net.Listener
	// Policy decides for each accepted connection, by its peer address,
	// whether a header is expected. Nil means Required for every peer.
	Policy func(peer net.Addr) Policy
	// HeaderTimeout bounds the wait for a header; a non-positive value means
	// DefaultHeaderTimeout.
	HeaderTimeout time.Duration
	// Datagram is for listeners whose connections return one datagram per
	// Read, such as netx.PacketListener over a UDP socket. The header is then
	// read from the first datagram of each connection, where it may be
	// followed by the first payload or stand alone; later datagrams are
	// passed through unchanged. Header addresses are reported as
	// *net.UDPAddr, since version 1 has no UDP token and UDP senders use TCP4
	// and TCP6.
	Datagram bool
}

// Accept waits for the next connection. Unless the policy is Ignore it returns
// a *Conn, which reads the header the first time it is used, so a slow peer
// does not hold up Accept.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	policy := Required
	if l.Policy != nil {
		policy = l.Policy(c.RemoteAddr())
	}
	if policy == Ignore {
		return c, nil
	}
	timeout := l.HeaderTimeout
	if timeout <= 0 {
		timeout = DefaultHeaderTimeout
	}
	return &Conn{Conn: c, policy: policy, timeout: timeout, datagram: l.Datagram}, nil
}

// headerReadSize is the initial buffer for a stream header; it grows to the
// length of a larger version 2 header once that is known.
const headerReadSize = 256

// maxDatagram is the largest datagram a datagram Conn reads in full.
const maxDatagram = 65535

var datagramPool = sync.Pool{New: func() any {
	b := make([]byte, maxDatagram)
	return &b
}}

// Conn is a connection accepted by a Listener. It reads the PROXY protocol
// header the first time it is read, its addresses are queried, or Header is
// called. Avoid querying the addresses in the accept loop: that waits for the
// header.
//
// The header must arrive within the Listener's HeaderTimeout. A read deadline
// set by the caller that expires sooner also ends a header read started by
// Read or WriteTo, which then returns the timeout; the next call resumes the
// header. An Optional connection that stops, by the header timeout or the end
// of the stream, while the bytes received are only the start of a signature
// has no header, and those bytes are passed through.
type Conn struct {
	net.Conn
	policy   Policy
	timeout  time.Duration
	datagram bool

	// hmu serializes header reads; header and err are set before done.
	hmu    sync.Mutex
	done   atomic.Bool
	hbuf   []byte // stream bytes received while the header is incomplete
	header *Header
	err    error

	// Bytes read with the header that belong to the stream, or the first
	// datagram's payload.
	pendingMu sync.Mutex
	pending   []byte
	drained   atomic.Bool

	mu           sync.Mutex
	readDeadline time.Time // set by the caller
	expires      time.Time // end of the header timeout, from the first header read
	reading      bool      // a header read is in progress
	callerBound  bool      // and it honors readDeadline
}

// Header returns the connection's PROXY protocol header, reading it first if
// needed. It returns nil without an error when an Optional connection had no
// header.
func (c *Conn) Header() (*Header, error) {
	if err := c.init(false); err != nil {
		return nil, err
	}
	return c.header, c.err
}

// init reads the header unless that is done. With callerBound, the caller's
// read deadline also bounds the read; init returns the timeout when it
// expires first and leaves the header to be read by a later call.
func (c *Conn) init(callerBound bool) error {
	if c.done.Load() {
		return nil
	}
	c.hmu.Lock()
	defer c.hmu.Unlock()
	if c.done.Load() {
		return nil
	}
	if err := c.readHeader(callerBound); err != nil {
		return err
	}
	c.hbuf = nil
	c.drained.Store(len(c.pending) == 0)
	c.done.Store(true)
	return nil
}

func (c *Conn) readHeader(callerBound bool) error {
	c.mu.Lock()
	if c.expires.IsZero() {
		c.expires = time.Now().Add(c.timeout)
	}
	c.reading, c.callerBound = true, callerBound
	_ = c.Conn.SetReadDeadline(c.headerDeadline(c.readDeadline))
	c.mu.Unlock()

	var err error
	if c.datagram {
		err = c.readDatagramHeader()
	} else {
		err = c.readStreamHeader()
	}

	c.mu.Lock()
	c.reading = false
	_ = c.Conn.SetReadDeadline(c.readDeadline)
	c.mu.Unlock()
	return err
}

// headerDeadline returns the read deadline that applies during a header read
// when the caller's is t. c.mu must be held.
func (c *Conn) headerDeadline(t time.Time) time.Time {
	if c.callerBound && !t.IsZero() && t.Before(c.expires) {
		return t
	}
	return c.expires
}

// interrupted reports whether a header read failed because of the caller's
// read deadline rather than the header timeout, so that it can be resumed.
func (c *Conn) interrupted(err error) bool {
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Before(c.expires)
}

// readStreamHeader reads the header into c.hbuf, which a resumed read
// continues.
func (c *Conn) readStreamHeader() error {
	for {
		h, n, need, err := parse(c.hbuf)
		switch {
		case err == nil:
			c.header = h
			if n < len(c.hbuf) {
				c.pending = bytes.Clone(c.hbuf[n:])
			}
			return nil
		case errors.Is(err, ErrNoHeader) && c.policy == Optional:
			c.pending = c.hbuf
			return nil
		case !errors.Is(err, io.ErrUnexpectedEOF):
			c.err = err
			return nil
		}
		if need > cap(c.hbuf) {
			c.hbuf = append(make([]byte, 0, max(need, headerReadSize)), c.hbuf...)
		}
		m, rerr := c.Conn.Read(c.hbuf[len(c.hbuf):cap(c.hbuf)])
		c.hbuf = c.hbuf[:len(c.hbuf)+m]
		if m > 0 || rerr == nil {
			continue
		}
		switch {
		case c.interrupted(rerr):
			return rerr
		case c.policy == Optional && signaturePrefix(c.hbuf):
			c.pending = c.hbuf
		case len(c.hbuf) == 0:
			c.err = rerr
		default:
			c.err = unexpectedEOF(rerr)
		}
		return nil
	}
}

// signaturePrefix reports whether b is no longer than the start of a version
// 1 or 2 signature, so that it may as well not be a header.
func signaturePrefix(b []byte) bool {
	if len(b) > 0 && b[0] == v2Signature[0] {
		return len(b) < len(v2Signature)
	}
	return len(b) < len(v1Prefix)
}

func (c *Conn) readDatagramHeader() error {
	bp := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(bp)
	buf := *bp
	n, err := c.Conn.Read(buf)
	if err != nil {
		switch {
		case c.interrupted(err):
			return err
		case c.policy != Optional:
			c.err = err
		}
		return nil
	}
	h, size, err := Parse(buf[:n])
	switch {
	case err == nil:
		h.Source, h.Destination = h.UDPAddrs()
		c.header = h
		if size < n {
			c.pending = bytes.Clone(buf[size:n])
		}
	case errors.Is(err, ErrMalformed):
		c.err = err
	case c.policy == Optional:
		// No header, or a datagram as short as the start of a signature.
		c.pending = bytes.Clone(buf[:n])
	default:
		c.err = ErrNoHeader
	}
	return nil
}

// takePending returns the bytes read with the header, once.
func (c *Conn) takePending() []byte {
	if c.drained.Load() {
		return nil
	}
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	p := c.pending
	c.pending = nil
	c.drained.Store(true)
	return p
}

// Read reads from the stream after the header. On a datagram connection it
// returns one datagram, truncated to b like a UDP socket.
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.init(true); err != nil {
		return 0, err
	}
	if c.err != nil {
		return 0, c.err
	}
	if !c.drained.Load() {
		c.pendingMu.Lock()
		if len(c.pending) > 0 {
			n := copy(b, c.pending)
			if c.datagram || n == len(c.pending) {
				c.pending = nil
				c.drained.Store(true)
			} else {
				c.pending = c.pending[n:]
			}
			c.pendingMu.Unlock()
			return n, nil
		}
		c.pendingMu.Unlock()
	}
	return c.Conn.Read(b)
}

// WriteTo copies the connection after the header to w. A stream lets a
// *net.TCPConn splice the data; a datagram connection writes each datagram
// with one Write.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if err := c.init(true); err != nil {
		return 0, err
	}
	if c.err != nil {
		return 0, c.err
	}
	if c.datagram {
		bp := datagramPool.Get().(*[]byte)
		defer datagramPool.Put(bp)
		buf := *bp
		var total int64
		for {
			n, err := c.Read(buf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				return total, err
			}
			m, err := w.Write(buf[:n])
			total += int64(m)
			if err != nil {
				return total, err
			}
		}
	}
	var total int64
	if p := c.takePending(); len(p) > 0 {
		n, err := w.Write(p)
		total += int64(n)
		if err == nil && n < len(p) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return total, err
		}
	}
	n, err := io.Copy(w, c.Conn)
	return total + n, err
}

// RemoteAddr returns the source address from the header, or the peer address
// when the header has none.
func (c *Conn) RemoteAddr() net.Addr {
	if c.init(false) == nil && c.header != nil && c.header.Source != nil {
		return c.header.Source
	}
	return c.Conn.RemoteAddr()
}

// LocalAddr returns the destination address from the header, or the local
// address when the header has none.
func (c *Conn) LocalAddr() net.Addr {
	if c.init(false) == nil && c.header != nil && c.header.Destination != nil {
		return c.header.Destination
	}
	return c.Conn.LocalAddr()
}

// SetDeadline sets the read and write deadlines. During a header read the
// read deadline takes effect as described for Conn.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	if !c.reading {
		return c.Conn.SetDeadline(t)
	}
	if err := c.Conn.SetWriteDeadline(t); err != nil { //nolint:staticcheck // QF1008: the wrapped Conn, as around it
		return err
	}
	return c.Conn.SetReadDeadline(c.headerDeadline(t))
}

// SetReadDeadline sets the read deadline. During a header read it takes
// effect as described for Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	if c.reading {
		t = c.headerDeadline(t)
	}
	return c.Conn.SetReadDeadline(t)
}

// CloseWrite shuts down the writing side of the connection when it supports
// that, and otherwise returns an error matching errors.ErrUnsupported.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// RawConn returns the accepted connection, for unwrapping helpers such as
// netx.RawConnOf. Reading it directly bypasses the header handling.
func (c *Conn) RawConn() net.Conn {
	return c.Conn
}
