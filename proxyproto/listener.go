package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/djylb/netx"
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
	// otherwise passes the stream through unchanged.
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
	return &Conn{Conn: c, policy: policy, timeout: timeout}, nil
}

// headerReadSize is the read buffer used for the header; larger version 2
// headers are read in full once their length is known.
const headerReadSize = 256

// Conn is a connection accepted by a Listener. It reads the PROXY protocol
// header the first time it is read, its addresses are queried, or Header is
// called. Avoid querying the addresses in the accept loop: that waits for the
// header.
type Conn struct {
	net.Conn
	policy  Policy
	timeout time.Duration

	once   sync.Once
	header *Header
	err    error
	r      net.Conn // the stream after the header

	mu           sync.Mutex
	readDeadline time.Time // set by the caller before the header was read
}

// Header returns the connection's PROXY protocol header, reading it first if
// needed. It returns nil without an error when an Optional connection had no
// header.
func (c *Conn) Header() (*Header, error) {
	c.init()
	return c.header, c.err
}

func (c *Conn) init() {
	c.once.Do(c.readHeader)
}

func (c *Conn) readHeader() {
	c.r = c.Conn
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	br := bufio.NewReaderSize(c.Conn, headerReadSize)
	h, err := Read(br)
	switch {
	case err == nil:
		c.header = h
	case errors.Is(err, ErrNoHeader) && c.policy == Optional:
	default:
		c.err = err
	}
	c.mu.Lock()
	_ = c.Conn.SetReadDeadline(c.readDeadline)
	c.mu.Unlock()
	if n := br.Buffered(); n > 0 {
		rest, _ := br.Peek(n)
		c.r = netx.NewPrefixConn(c.Conn, bytes.Clone(rest))
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	c.init()
	if c.err != nil {
		return 0, c.err
	}
	return c.r.Read(b)
}

// WriteTo copies the stream after the header to w, letting a *net.TCPConn
// splice the data.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	c.init()
	if c.err != nil {
		return 0, c.err
	}
	return io.Copy(w, c.r)
}

// RemoteAddr returns the source address from the header, or the peer address
// when the header has none.
func (c *Conn) RemoteAddr() net.Addr {
	c.init()
	if c.header != nil && c.header.Source != nil {
		return c.header.Source
	}
	return c.Conn.RemoteAddr()
}

// LocalAddr returns the destination address from the header, or the local
// address when the header has none.
func (c *Conn) LocalAddr() net.Addr {
	c.init()
	if c.header != nil && c.header.Destination != nil {
		return c.header.Destination
	}
	return c.Conn.LocalAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return c.Conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
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

// RawConn returns the innermost accepted connection; see netx.RawConnOf.
// Reading it directly bypasses the header handling.
func (c *Conn) RawConn() net.Conn {
	return netx.RawConnOf(c.Conn)
}
