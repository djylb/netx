package proxyproto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/internal/bufpool"
	"github.com/djylb/netx/internal/netutil"
)

// DefaultHeaderTimeout bounds how long a Conn waits for its header when the
// HeaderTimeout of its Config is 0.
const DefaultHeaderTimeout = 10 * time.Second

// Policy tells a Conn whether its peer sends a PROXY protocol header. In
// DatagramEach and DatagramAuto, the mode determines how Required and
// Optional handle missing headers.
type Policy uint8

const (
	// Required rejects connections that do not start with a header: their
	// first read returns ErrNoHeader, or io.EOF for one that ends before
	// sending anything. It is the zero value.
	Required Policy = iota
	// Optional uses a header when the connection starts with one and
	// otherwise passes the stream through unchanged, including when it
	// stops, by the header timeout or its end, after at most the start of a
	// signature, as a peer that waits for the server to speak first does.
	Optional
	// Ignore passes the connection through without looking for a header.
	Ignore
)

// DatagramMode selects how a Conn reads headers on a connection that returns
// one datagram per Read. Its zero value selects stream framing.
type DatagramMode uint8

const (
	// DatagramFirst reads the header only from the first datagram. A
	// header-only first datagram is consumed. If it has no header,
	// Required rejects the connection and Optional passes all datagrams
	// through unchanged.
	DatagramFirst DatagramMode = iota + 1
	// DatagramEach requires a header on each datagram. Reads skip and count
	// datagrams whose header is missing, truncated or malformed.
	DatagramEach
	// DatagramAuto checks each datagram for a complete v1 or v2 signature.
	// Reads pass datagrams without one through unchanged, and skip and count
	// datagrams with a signature followed by a truncated or malformed header.
	DatagramAuto
)

func (m DatagramMode) perDatagram() bool {
	return m == DatagramEach || m == DatagramAuto
}

// TrustPrefixes returns a function for Listener.PolicyFor under which peers
// whose IP address is in one of the prefixes must send a header and other peers
// are passed through without one, as Required and Ignore do. An IPv4 address
// and its IPv4-mapped IPv6 form (::ffff:a.b.c.d) are the same peer, for
// addresses and prefixes alike, so ::ffff:10.0.0.0/104 is 10.0.0.0/8, and an
// IPv6 prefix that holds the IPv4-mapped form of an IPv4 peer, such as ::/0,
// holds the peer. Zones are ignored. Peers without an IP address, such as those
// of a Unix socket, are passed through.
func TrustPrefixes(p ...netip.Prefix) func(peer net.Addr) Policy {
	prefixes := make([]netip.Prefix, 0, len(p))
	for _, pfx := range p {
		prefixes = append(prefixes, netutil.UnmappedPrefixes(pfx)...)
	}
	return func(peer net.Addr) Policy {
		ip := netutil.PeerAddrPort(peer).Addr()
		if !ip.IsValid() {
			return Ignore
		}
		for _, pfx := range prefixes {
			if pfx.Contains(ip) {
				return Required
			}
		}
		return Ignore
	}
}

// Config configures a Conn.
type Config struct {
	// HeaderTimeout bounds the wait for a stream or DatagramFirst header; 0 means
	// DefaultHeaderTimeout (10s), and a negative value means no timeout,
	// as for http.Server.ReadHeaderTimeout. DatagramEach and DatagramAuto
	// use the connection's read deadline.
	HeaderTimeout time.Duration
	// Policy tells whether the peer sends a header. The zero value is
	// Required. With DatagramEach or DatagramAuto, the mode determines
	// how Required and Optional handle missing headers. Ignore always
	// passes datagrams through unchanged.
	Policy Policy
	// Datagram selects framing for connections that return one datagram per
	// Read. Zero selects a stream. DatagramFirst checks only the first
	// datagram and uses Policy when the header is absent. DatagramEach
	// skips datagrams without a header. DatagramAuto passes them through
	// unchanged. In all three modes, TCP header addresses become *net.UDPAddr
	// because version 1 UDP senders use TCP4 and TCP6.
	Datagram DatagramMode
}

// NewConn wraps c and reads PROXY protocol headers as configured by cfg.
// Headers are read lazily. Closing the Conn closes c. With the Ignore
// policy it passes c through and reports no header. For a nil c, its I/O
// methods return net.ErrClosed, its addresses are nil and Close does nothing.
func NewConn(c net.Conn, cfg Config) *Conn {
	timeout := netutil.Timeout(cfg.HeaderTimeout, DefaultHeaderTimeout)
	if c != nil && netutil.IsNilPointer(c) {
		c = nil
	}
	pc := &Conn{conn: c, policy: cfg.Policy, timeout: timeout, datagram: cfg.Datagram}
	if c == nil {
		pc.err = net.ErrClosed
		pc.drained.Store(true)
		pc.done.Store(true)
	} else if cfg.Policy == Ignore || cfg.Datagram.perDatagram() {
		pc.drained.Store(true)
		pc.done.Store(true)
	}
	return pc
}

// HeaderOf returns the header of the first Conn in the chain of c and the
// connections that NetConn() net.Conn methods, such as *tls.Conn's, return
// beneath it, reading the header first if needed, as Conn.Header does. It
// returns nil and no error in DatagramEach and DatagramAuto, or when there
// is no Conn, such as for a connection a Listener passed through under Ignore.
func HeaderOf(c net.Conn) (*Header, error) {
	// A bound on the depth stops a chain of wrappers that loops.
	for range maxUnwrapDepth {
		if c == nil || netutil.IsNilPointer(c) {
			return nil, nil
		}
		if pc, ok := c.(*Conn); ok {
			return pc.Header()
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return nil, nil
		}
		c = u.NetConn()
	}
	return nil, nil
}

// maxUnwrapDepth bounds the NetConn chain that HeaderOf follows.
const maxUnwrapDepth = 16

// Listener wraps a net.Listener whose peers, such as load balancers, send a
// PROXY protocol header. Connections with a connection-wide header use its
// addresses for RemoteAddr and LocalAddr.
//
// Only trusted peers should be allowed to send a header, since it lets them
// choose the reported client address; restrict them with PolicyFor, such as
// to TrustPrefixes. As described for Conn, writes to an accepted connection
// do not wait for its header to be validated.
type Listener struct {
	net.Listener
	// PolicyFor, when set, decides for each accepted connection, by its peer
	// address, whether a header is expected, in place of Config.Policy.
	PolicyFor func(peer net.Addr) Policy
	// Config configures each accepted Conn. Its Policy applies to every
	// peer unless PolicyFor is set; the zero value is Required.
	Config Config
}

// Accept waits for the next connection. Unless the policy is Ignore it returns
// a *Conn, which reads the header the first time it is used, so a slow peer
// does not hold up Accept. Under Ignore it returns the accepted connection
// itself.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cfg := l.Config
	if l.PolicyFor != nil {
		cfg.Policy = l.PolicyFor(c.RemoteAddr())
	}
	if cfg.Policy == Ignore {
		return c, nil
	}
	return NewConn(c, cfg), nil
}

// headerReadSize is the initial buffer for a stream header; it grows to the
// length of a larger version 2 header once that is known.
const headerReadSize = 256

// Conn is a connection whose peer sends a PROXY protocol header, from
// NewConn or a Listener. For streams and DatagramFirst, it reads the header
// the first time it is read, its addresses are queried, or Header is called.
// Avoid querying those addresses in an accept loop, since that waits for the
// header. In DatagramEach and DatagramAuto, ReadDatagram returns each
// datagram's header with its payload.
//
// Writes do not wait for the header: Write, ReadFrom and CloseWrite go
// straight to the connection beneath. Under Required and Optional, a server
// that speaks first, or one that answers what it cannot use, as an HTTP
// server answers 400, therefore writes to a peer that may have sent no header
// or a malformed one. When that matters, check the header before writing.
//
// For streams and DatagramFirst, the header must arrive within HeaderTimeout.
// The read that reaches it returns the timeout. Later reads return a
// non-timeout error matching ErrNoHeader so that loops retrying timeouts do
// not spin. A connection that cannot set deadlines is closed when the header
// timeout expires. A read deadline set by the caller that expires sooner also
// ends a header read started by Read or WriteTo, or their wait for one
// started by another call, which then returns the timeout; the next call
// resumes the header. On an Optional stream, the header timeout or end of
// stream passes through bytes that are only the start of a signature. In
// DatagramFirst, I/O errors during the header read are returned even under
// Optional.
type Conn struct {
	readDeadline time.Time // set by the caller
	expires      time.Time // end of the header timeout, from the first header read
	conn         net.Conn
	err          error
	timeoutAt    error // the header timeout, returned once before err
	// hsem serializes header reads; header and err are set before done.
	hsem        chan struct{}
	header      *Header
	deadlineSet chan struct{} // closed when readDeadline changes
	hbuf        []byte        // stream bytes received while the header is incomplete
	pending     []byte
	timeout     time.Duration
	// Bytes read with the header that belong to the stream, or the first
	// datagram's payload.
	pendingMu   sync.Mutex
	mu          sync.Mutex
	done        atomic.Bool
	drained     atomic.Bool
	dropped     atomic.Uint64
	policy      Policy
	datagram    DatagramMode
	reading     bool // a header read is in progress
	callerBound bool // and it honors readDeadline
}

// Header returns the connection's PROXY protocol header, reading it first if
// needed. It returns nil without an error when an Optional connection had no
// header, under Ignore, or in DatagramEach and DatagramAuto. Use ReadDatagram
// for per-datagram headers.
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
	sem, err := c.lockHeader(callerBound)
	if err != nil {
		return err
	}
	defer func() { <-sem }()
	if c.done.Load() {
		return nil
	}
	if err := c.readHeader(callerBound); err != nil {
		return err
	}
	c.hbuf = nil
	if c.datagram == 0 && len(c.pending) == 0 {
		c.pending = nil // a stream has no empty pending reads
	}
	c.drained.Store(c.pending == nil)
	c.done.Store(true)
	if err := c.timeoutAt; err != nil {
		c.timeoutAt = nil
		return err
	}
	return nil
}

// lockHeader waits for the right to read the header and returns the
// semaphore to release. With callerBound it gives up, as a blocked Read would,
// when the caller's read deadline passes first.
func (c *Conn) lockHeader(callerBound bool) (chan struct{}, error) {
	c.mu.Lock()
	if c.hsem == nil {
		c.hsem = make(chan struct{}, 1)
	}
	sem := c.hsem
	c.mu.Unlock()
	select {
	case sem <- struct{}{}:
		return sem, nil
	default:
	}
	if !callerBound {
		sem <- struct{}{}
		return sem, nil
	}
	for {
		c.mu.Lock()
		deadline := c.readDeadline
		if c.deadlineSet == nil {
			c.deadlineSet = make(chan struct{})
		}
		changed := c.deadlineSet
		c.mu.Unlock()
		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			expired = timer.C
		}
		select {
		case sem <- struct{}{}:
			stopTimer(timer)
			return sem, nil
		case <-expired:
			return nil, os.ErrDeadlineExceeded
		case <-changed:
			stopTimer(timer)
		}
	}
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// deadlineChangedLocked wakes the calls waiting in lockHeader to look at the
// new read deadline. c.mu must be held.
func (c *Conn) deadlineChangedLocked() {
	if c.deadlineSet != nil {
		close(c.deadlineSet)
		c.deadlineSet = nil
	}
}

// fail records err as the error that ended the header read. A terminal
// timeout is returned once as it is. Later calls can identify the cause
// with errors.Is, but a loop retrying timeouts will stop.
func (c *Conn) fail(err error) {
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		c.timeoutAt = err
		err = &headerTimeoutError{cause: err}
	}
	c.err = err
}

// headerTimeoutError reports a terminal timeout reading the header. It
// matches ErrNoHeader and the original error and is not a timeout.
type headerTimeoutError struct {
	cause error
}

func (e *headerTimeoutError) Error() string {
	return "proxyproto: header read timed out: " + e.cause.Error()
}

func (e *headerTimeoutError) Is(target error) bool { return errors.Is(e.cause, target) }
func (e *headerTimeoutError) Unwrap() error        { return ErrNoHeader }
func (e *headerTimeoutError) Timeout() bool        { return false }
func (e *headerTimeoutError) Temporary() bool      { return false }

func (c *Conn) readHeader(callerBound bool) error {
	c.mu.Lock()
	if c.expires.IsZero() {
		c.expires = time.Now().Add(c.timeout)
	}
	c.reading, c.callerBound = true, callerBound
	var guard *time.Timer
	if c.conn.SetReadDeadline(c.headerDeadline(c.readDeadline)) != nil {
		// Without deadline support, closing the connection is the only way
		// to end a header read that outlasts the header timeout.
		guard = time.AfterFunc(time.Until(c.expires), func() { _ = c.conn.Close() })
	}
	c.mu.Unlock()

	var err error
	if c.datagram != 0 {
		err = c.readDatagramHeader()
	} else {
		err = c.readStreamHeader()
	}
	if guard != nil && !guard.Stop() {
		// The guard closed the connection, so not even an Optional one can
		// pass its bytes on: report the header timeout rather than the use
		// of a closed connection.
		c.header, c.pending, c.err = nil, nil, nil
		c.fail(os.ErrDeadlineExceeded)
	}

	c.mu.Lock()
	c.reading = false
	_ = c.conn.SetReadDeadline(c.readDeadline)
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
	now := time.Now()
	return c.callerBound && !c.readDeadline.IsZero() &&
		!now.Before(c.readDeadline) && now.Before(c.expires)
}

// readStreamHeader reads the header into c.hbuf, which a resumed read
// continues.
func (c *Conn) readStreamHeader() error {
	empty := 0 // reads in a row that returned nothing
	for {
		h, n, need, err := decode(c.hbuf, 0)
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
			// Read headerReadSize bytes at a time, and beyond that grow with
			// the bytes received rather than to the length a version 2
			// header claims, so that a few bytes cannot hold 64 KiB.
			size := max(headerReadSize, min(need, 2*cap(c.hbuf)))
			c.hbuf = append(make([]byte, 0, size), c.hbuf...)
		}
		m, rerr := c.conn.Read(c.hbuf[len(c.hbuf):cap(c.hbuf)])
		c.hbuf = c.hbuf[:len(c.hbuf)+m]
		if m > 0 {
			empty = 0
			continue
		}
		if rerr == nil {
			// Give up on a connection that keeps returning nothing, as
			// bufio does, rather than spin.
			if empty++; empty < 100 {
				continue
			}
			rerr = io.ErrNoProgress
		}
		switch {
		case c.interrupted(rerr):
			return rerr
		case c.policy == Optional && signaturePrefix(c.hbuf):
			c.pending = c.hbuf
		case len(c.hbuf) == 0:
			c.fail(rerr)
		default:
			c.fail(unexpectedEOF(rerr))
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
	bp := bufpool.Large.Get()
	defer bufpool.Large.Put(bp)
	buf := *bp
	n, err := c.conn.Read(buf)
	if err != nil {
		if c.interrupted(err) {
			return err
		}
		c.fail(err)
		return nil
	}
	h, size, err := decodeDatagram(buf[:n], c.datagram)
	switch {
	case err == nil:
		c.header = h
		if size < n {
			c.pending = bytes.Clone(buf[size:n])
		}
	case errors.Is(err, io.ErrUnexpectedEOF):
		// A whole signature, in a datagram too short for its header.
		c.err = malformed("header cut short by the end of a %d-byte datagram", n)
	case errors.Is(err, ErrNoHeader) && c.policy == Optional:
		// No header, or a datagram as short as the start of a signature. It
		// is passed on even when empty: a datagram is a message.
		c.pending = append(make([]byte, 0, n), buf[:n]...)
	default:
		c.err = err
	}
	return nil
}

// decodeDatagram decodes a header confined to one datagram. A partial
// signature is payload, even if it would be incomplete on a stream.
func decodeDatagram(b []byte, mode DatagramMode) (*Header, int, error) {
	h, n, _, err := decode(b, mode)
	if errors.Is(err, io.ErrUnexpectedEOF) && signaturePrefix(b) {
		return nil, 0, ErrNoHeader
	}
	if err == nil {
		h.Source, h.Destination = h.UDPAddrs()
	}
	return h, n, err
}

// ReadDatagram reads one datagram, truncating its payload to fit b, and
// returns its header in DatagramEach and DatagramAuto. A header-only packet
// in these modes returns zero bytes and its header. With DatagramAuto or
// Ignore, a datagram passed through unchanged has a nil header. In
// DatagramFirst, the returned header applies to the entire connection.
// Headers can be retained across reads. For a stream, ReadDatagram returns
// errors.ErrUnsupported.
func (c *Conn) ReadDatagram(b []byte) (n int, h *Header, err error) {
	if c == nil || c.conn == nil {
		return 0, nil, net.ErrClosed
	}
	if c.datagram == 0 {
		return 0, nil, errors.ErrUnsupported
	}
	if c.datagram.perDatagram() && c.policy != Ignore {
		return c.readEachDatagram(b)
	}
	n, err = c.Read(b)
	if err == nil || n > 0 {
		h = c.header
	}
	return n, h, err
}

// DroppedDatagrams returns the cumulative number of packets skipped while
// reading in DatagramEach or DatagramAuto. It is safe to call concurrently
// with reads.
func (c *Conn) DroppedDatagrams() uint64 {
	if c == nil {
		return 0
	}
	return c.dropped.Load()
}

func (c *Conn) readEachDatagram(b []byte) (int, *Header, error) {
	buf := b
	if len(buf) < bufpool.LargeSize {
		bp := bufpool.Large.Get()
		defer bufpool.Large.Put(bp)
		buf = *bp
	}
	for {
		n, err := c.conn.Read(buf[:bufpool.LargeSize])
		if n == 0 && err != nil {
			return 0, nil, err
		}
		h, size, decodeErr := decodeDatagram(buf[:n], c.datagram)
		if decodeErr == nil || (errors.Is(decodeErr, ErrNoHeader) && c.datagram == DatagramAuto) {
			return copy(b, buf[size:n]), h, err
		}
		c.dropped.Add(1)
		if err != nil {
			return 0, nil, err
		}
	}
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
// returns one datagram, truncated to b like a UDP socket. In DatagramEach
// and DatagramAuto it skips rejected datagrams and discards the metadata of
// delivered datagrams. Use ReadDatagram to obtain that metadata.
func (c *Conn) Read(b []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	if c.datagram.perDatagram() && c.policy != Ignore {
		n, _, err := c.readEachDatagram(b)
		return n, err
	}
	if err := c.init(true); err != nil {
		return 0, err
	}
	if c.err != nil {
		return 0, c.err
	}
	if !c.drained.Load() {
		c.pendingMu.Lock()
		// A datagram is pending even when it is empty.
		if p := c.pending; p != nil {
			n := copy(b, p)
			if c.datagram != 0 || n == len(p) {
				c.pending = nil
				c.drained.Store(true)
			} else {
				c.pending = p[n:]
			}
			c.pendingMu.Unlock()
			return n, nil
		}
		c.pendingMu.Unlock()
	}
	return c.conn.Read(b)
}

// WriteTo copies the connection after the header to w. A stream lets a
// *net.TCPConn splice the data; a datagram connection writes each datagram
// with one Write.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	if err := c.init(true); err != nil {
		return 0, err
	}
	if c.err != nil {
		if errors.Is(c.err, io.EOF) {
			// A connection that ended before sending anything.
			return 0, nil
		}
		return 0, c.err
	}
	if c.datagram != 0 {
		bp := bufpool.Large.Get()
		defer bufpool.Large.Put(bp)
		buf := *bp
		var total int64
		for {
			n, h, rerr := c.ReadDatagram(buf)
			if n > 0 || h != nil || rerr == nil {
				m, err := w.Write(buf[:n])
				total += int64(m)
				if err == nil && m < n {
					err = io.ErrShortWrite
				}
				if err != nil {
					return total, err
				}
			}
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			if rerr != nil {
				return total, rerr
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
	if netutil.Splices(w, c.conn) {
		n, err := io.Copy(w, c.conn)
		return total + n, err
	}
	switch rf := w.(type) {
	case *net.TCPConn, *net.UnixConn:
		// Their ReadFrom would copy through a buffer it allocates.
	case io.ReaderFrom:
		n, err := rf.ReadFrom(c.conn)
		return total + n, err
	}
	// Without ReadFrom, io.Copy would allocate a buffer for every call.
	// Through a stream buffer: the writer has no ReadFrom.
	bp := bufpool.Stream.Get()
	defer bufpool.Stream.Put(bp)
	n, err := io.CopyBuffer(writerOnly{w}, readerOnly{c.conn}, *bp)
	return total + n, err
}

// readerOnly hides every method but Read, so that io.CopyBuffer uses the
// buffer it is given.
type readerOnly struct{ io.Reader }

// RemoteAddr returns the source address from the header, or the peer address
// when the header has none. A stream reports a UDP address as a
// *net.TCPAddr, so that it has the address type of its listener; a header
// of AF_UNIX addresses gives a *net.UnixAddr, so check the type rather than
// assert *net.TCPAddr when peers may send them. In DatagramEach and
// DatagramAuto it always returns the peer address without reading.
func (c *Conn) RemoteAddr() net.Addr {
	if c.init(false) == nil && c.header != nil && c.header.Source != nil {
		return c.streamAddr(c.header.Source)
	}
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

// LocalAddr returns the destination address from the header, or the local
// address when the header has none, with the address type of RemoteAddr. In
// DatagramEach and DatagramAuto it always returns the transport's local
// address without reading.
func (c *Conn) LocalAddr() net.Addr {
	if c.init(false) == nil && c.header != nil && c.header.Destination != nil {
		return c.streamAddr(c.header.Destination)
	}
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

// streamAddr returns a header address as a stream connection reports it: a
// *net.UDPAddr, from a UDP4 or UDP6 token or a DGRAM transport, as a
// *net.TCPAddr.
func (c *Conn) streamAddr(a net.Addr) net.Addr {
	if u, ok := a.(*net.UDPAddr); ok && u != nil && c.datagram == 0 {
		return &net.TCPAddr{IP: u.IP, Port: u.Port, Zone: u.Zone}
	}
	return a
}

// ReadFrom copies r to the connection with the ReadFrom of the connection
// beneath, so that a *net.TCPConn can splice the data. Writes do not wait
// for the header.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.conn == nil {
		return 0, net.ErrClosed
	}
	if rf, ok := c.conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(writerOnly{c.conn}, r)
}

// writerOnly hides every method but Write, so that io.Copy does not call
// ReadFrom again.
type writerOnly struct{ io.Writer }

// SetDeadline sets the read and write deadlines. During a header read the
// read deadline takes effect as described for Conn.
func (c *Conn) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.deadlineChangedLocked()
	if !c.reading {
		return c.conn.SetDeadline(t)
	}
	if err := c.conn.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.conn.SetReadDeadline(c.headerDeadline(t))
}

// SetReadDeadline sets the read deadline. During a header read it takes
// effect as described for Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.deadlineChangedLocked()
	if c.reading {
		t = c.headerDeadline(t)
	}
	return c.conn.SetReadDeadline(t)
}

// CloseWrite shuts down the writing side of the connection when it supports
// that, and otherwise returns an error matching errors.ErrUnsupported.
func (c *Conn) CloseWrite() error {
	if c.conn == nil {
		return net.ErrClosed
	}
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// NetConn returns the connection beneath, as *tls.Conn's NetConn does, for
// unwrapping helpers. Reading it directly bypasses the header handling.
func (c *Conn) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.conn
}

// NetxOwned describes the transport closed by Close.
func (c *Conn) NetxOwned() netutil.Owned { return netutil.BuiltinOwned(c, c.NetConn(), nil) }

// Write writes to the connection. Writes do not wait for the header.
func (c *Conn) Write(b []byte) (int, error) {
	if c.conn == nil {
		return 0, net.ErrClosed
	}
	return c.conn.Write(b)
}

// Close closes the connection, ending a header read in progress.
func (c *Conn) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetWriteDeadline(t)
}
