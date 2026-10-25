// Package duplex joins a read half and a write half into a net.Conn, and
// lets either half be replaced while the connection is in use.
//
// Join turns any io.Reader and io.Writer into a connection: the body of an
// HTTP response and the body of its request, two one-way channels, or
// standard input and output. The connection reads the read half and writes
// the write half, and gives them what a net.Conn has and they may lack:
//
//   - CloseRead stops the read half, CloseWrite the write half, and Close
//     both. A half that has CloseRead or CloseWrite is half-closed that way,
//     any other io.Closer is closed. A value that is both halves is closed
//     once: CloseRead and CloseWrite then use its CloseRead and CloseWrite
//     methods, or else leave it open until the other direction is closed
//     too, and Close closes it once.
//   - Deadlines are passed on to halves that have SetReadDeadline,
//     SetWriteDeadline or SetDeadline, the last only for a half that is not
//     also the other half. Setting a deadline for a half without them
//     returns an error matching errors.ErrUnsupported; clearing it succeeds.
//     Deadlines are not emulated: a read that its half cannot interrupt
//     would need a goroutine that outlives it and a copy of what it reads.
//   - LocalAddr and RemoteAddr come from the read half, else the write half,
//     when they have such methods that return a non-nil address, and are
//     otherwise an address whose network and string are "duplex".
//
// A nil read half reads as an empty stream, returning io.EOF, and a nil
// write half fails every Write with an error matching errors.ErrUnsupported.
// After CloseRead, CloseWrite or Close, reads or writes in the closed
// direction return net.ErrClosed.
//
// The halves may be a Reader, which reads one stream after another, and a
// Writer, whose stream can be swapped. A sender that moves its stream to a
// new channel swaps the stream of its Writer, which ends the old channel;
// the receiver appends each channel to its Reader as it arrives, and reads
// on across the change in order:
//
//	// sender
//	up := new(duplex.Writer)
//	err := up.Swap(ctx, firstChannel)
//	c := duplex.Join(downlink, up)
//	err = up.Swap(ctx, nextChannel) // waits for the write in progress
//
//	// receiver, as each channel arrives
//	done, err := in.Append(channel)
//
// WriteTo and ReadFrom hand copies to the halves, so io.Copy and relays
// keep the halves' own fast paths, such as splice and sendfile between
// sockets and files.
//
// Read, Write, the deadline methods and the Close methods may be called
// concurrently, and Read and Write do not allocate. The methods of a nil
// *Conn return net.ErrClosed.
package duplex

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Conn is a net.Conn made of a read half and a write half. A Conn owns its
// halves: its Close methods close them.
type Conn struct {
	r      io.Reader
	w      io.Writer
	shared bool // r and w are the same value

	rClosed, wClosed atomic.Bool

	mu        sync.Mutex
	closed    bool // Close was called
	rReleased bool // r's Close was called
	wReleased bool // w's Close was called
}

// Join returns a connection that reads r and writes w. Either may be nil.
func Join(r io.Reader, w io.Writer) *Conn {
	return &Conn{r: r, w: w, shared: same(r, w)}
}

var (
	_ net.Conn      = (*Conn)(nil)
	_ io.WriterTo   = (*Conn)(nil)
	_ io.ReaderFrom = (*Conn)(nil)
)

// unsupported is an error that matches errors.ErrUnsupported.
type unsupported string

func (e unsupported) Error() string        { return string(e) }
func (e unsupported) Is(target error) bool { return target == errors.ErrUnsupported }

var (
	errNoWriter        = unsupported("duplex: no write half")
	errNoReadDeadline  = unsupported("duplex: read half has no deadline")
	errNoWriteDeadline = unsupported("duplex: write half has no deadline")
)

// Read reads the read half.
func (c *Conn) Read(p []byte) (int, error) {
	if c == nil || c.rClosed.Load() {
		return 0, net.ErrClosed
	}
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}

// Write writes the write half.
func (c *Conn) Write(p []byte) (int, error) {
	if c == nil || c.wClosed.Load() {
		return 0, net.ErrClosed
	}
	if c.w == nil {
		return 0, errNoWriter
	}
	return c.w.Write(p)
}

// reader and writer hide the WriteTo and ReadFrom methods of a Conn.
type reader struct{ c *Conn }
type writer struct{ c *Conn }

func (r reader) Read(p []byte) (int, error)  { return r.c.Read(p) }
func (w writer) Write(p []byte) (int, error) { return w.c.Write(p) }

// WriteTo copies the read half to w until io.EOF, as copyTo does.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.rClosed.Load() {
		return 0, net.ErrClosed
	}
	if c.r == nil {
		return 0, nil
	}
	return copyTo(w, c.r, reader{c})
}

// copyTo copies r to w, through the copy methods that keep their fast
// paths: w's ReadFrom of r when r is a socket, whose own WriteTo copies
// through a buffer to anything but a Unix socket, else r's WriteTo, else
// w's ReadFrom of plain, which reads what r does, else a buffer.
func copyTo(w io.Writer, r io.Reader, plain io.Reader) (int64, error) {
	switch r.(type) {
	case *net.TCPConn, *net.UnixConn:
		if rf, ok := w.(io.ReaderFrom); ok {
			return rf.ReadFrom(r)
		}
	}
	if wt, ok := r.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	return io.Copy(w, plain)
}

// ReadFrom copies src to the write half until io.EOF, through the write
// half's ReadFrom when it has one.
func (c *Conn) ReadFrom(src io.Reader) (int64, error) {
	if c == nil || c.wClosed.Load() {
		return 0, net.ErrClosed
	}
	if rf, ok := c.w.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(writer{c}, src)
}

// CloseRead stops the read half: it calls the half's CloseRead method, or
// else its Close method unless it is also the open write half. Later reads
// return net.ErrClosed. Closing a closed read side does nothing.
func (c *Conn) CloseRead() error {
	if c == nil {
		return net.ErrClosed
	}
	return c.closeSide(true)
}

// CloseWrite stops the write half: it calls the half's CloseWrite method,
// or else its Close method unless it is also the open read half. Later
// writes return net.ErrClosed. Closing a closed write side does nothing.
func (c *Conn) CloseWrite() error {
	if c == nil {
		return net.ErrClosed
	}
	return c.closeSide(false)
}

// closeSide closes the read side, or the write side.
func (c *Conn) closeSide(read bool) error {
	h, this, other := any(c.w), &c.wClosed, &c.rClosed
	if read {
		h, this, other = c.r, &c.rClosed, &c.wClosed
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if this.Swap(true) {
		c.mu.Unlock()
		return nil
	}
	// A value that is both halves is closed whole once both directions are.
	if cl, ok := h.(io.Closer); ok && c.shared && other.Load() && !c.rReleased {
		c.rReleased, c.wReleased = true, true
		c.mu.Unlock()
		return cl.Close()
	}
	cl, closer := h.(io.Closer)
	if closer && halfCloses(h, read) {
		closer = false // stopped by its CloseRead or CloseWrite, closed by Close
	}
	if closer && !c.shared {
		if read {
			c.rReleased = true
		} else {
			c.wReleased = true
		}
	}
	c.mu.Unlock()
	switch {
	case closer && c.shared:
		return nil // the other direction is open
	case closer:
		return cl.Close()
	}
	return halfClose(h, read)
}

// halfCloses reports whether h has CloseRead, when read, or CloseWrite.
func halfCloses(h any, read bool) bool {
	if read {
		_, ok := h.(interface{ CloseRead() error })
		return ok
	}
	_, ok := h.(interface{ CloseWrite() error })
	return ok
}

// Close closes both halves, each value once. A half that is an io.Closer is
// closed with Close, also after CloseRead or CloseWrite stopped it with its
// CloseRead or CloseWrite method; another gets the CloseRead or CloseWrite
// it has not had yet. Closing a closed Conn returns net.ErrClosed.
func (c *Conn) Close() error {
	if c == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closed = true
	rOpen, wOpen := !c.rClosed.Swap(true), !c.wClosed.Swap(true)
	rDone, wDone := c.rReleased || c.r == nil, c.wReleased || c.w == nil
	c.rReleased, c.wReleased = true, true
	c.mu.Unlock()

	if c.shared {
		if rDone {
			return nil
		}
		if cl, ok := c.r.(io.Closer); ok {
			return cl.Close()
		}
		var errs [2]error
		if rOpen {
			errs[0] = halfClose(c.r, true)
		}
		if wOpen {
			errs[1] = halfClose(c.w, false)
		}
		return errors.Join(errs[:]...)
	}
	var errs [2]error
	if !rDone {
		errs[0] = fullClose(c.r, rOpen, true)
	}
	if !wDone {
		errs[1] = fullClose(c.w, wOpen, false)
	}
	return errors.Join(errs[:]...)
}

// fullClose closes h with Close, or else, when its direction is open, with
// CloseRead or CloseWrite.
func fullClose(h any, open, read bool) error {
	if cl, ok := h.(io.Closer); ok {
		return cl.Close()
	}
	if open {
		return halfClose(h, read)
	}
	return nil
}

func halfClose(h any, read bool) error {
	if read {
		if cr, ok := h.(interface{ CloseRead() error }); ok {
			return cr.CloseRead()
		}
		return nil
	}
	if cw, ok := h.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// same reports whether a and b are the same non-nil value. Values of a type
// that is not comparable are never the same.
func same(a, b any) (eq bool) {
	if a == nil || b == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			eq = false
		}
	}()
	return a == b
}

type readDeadliner interface{ SetReadDeadline(time.Time) error }
type writeDeadliner interface{ SetWriteDeadline(time.Time) error }
type deadliner interface{ SetDeadline(time.Time) error }

// SetReadDeadline sets the read deadline of the read half; see the package
// documentation.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return c.setReadDeadline(t)
}

func (c *Conn) setReadDeadline(t time.Time) error {
	if c.r == nil {
		return nil
	}
	if d, ok := c.r.(readDeadliner); ok {
		return d.SetReadDeadline(t)
	}
	if d, ok := c.r.(deadliner); ok && !c.shared {
		return d.SetDeadline(t)
	}
	return noDeadline(t, errNoReadDeadline)
}

// SetWriteDeadline sets the write deadline of the write half; see the
// package documentation.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return c.setWriteDeadline(t)
}

func (c *Conn) setWriteDeadline(t time.Time) error {
	if c.w == nil {
		return nil
	}
	if d, ok := c.w.(writeDeadliner); ok {
		return d.SetWriteDeadline(t)
	}
	if d, ok := c.w.(deadliner); ok && !c.shared {
		return d.SetDeadline(t)
	}
	return noDeadline(t, errNoWriteDeadline)
}

// SetDeadline sets both deadlines. A value that is both halves and has
// SetDeadline but neither SetReadDeadline nor SetWriteDeadline gets one
// SetDeadline call; its deadlines cannot be set one at a time.
func (c *Conn) SetDeadline(t time.Time) error {
	if c == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if c.shared {
		_, r := c.r.(readDeadliner)
		_, w := c.r.(writeDeadliner)
		if d, ok := c.r.(deadliner); ok && !r && !w {
			return d.SetDeadline(t)
		}
	}
	return errors.Join(c.setReadDeadline(t), c.setWriteDeadline(t))
}

// noDeadline returns err, or nil for the zero time, which a half without
// deadlines has already.
func noDeadline(t time.Time, err error) error {
	if t.IsZero() {
		return nil
	}
	return err
}

// LocalAddr returns the local address of the read half, else of the write
// half, else an address whose network and string are "duplex".
func (c *Conn) LocalAddr() net.Addr {
	if c != nil {
		for _, h := range [...]any{c.r, c.w} {
			if a, ok := h.(interface{ LocalAddr() net.Addr }); ok {
				if addr := a.LocalAddr(); addr != nil {
					return addr
				}
			}
		}
	}
	return addr{}
}

// RemoteAddr returns the remote address of the read half, else of the write
// half, else an address whose network and string are "duplex".
func (c *Conn) RemoteAddr() net.Addr {
	if c != nil {
		for _, h := range [...]any{c.r, c.w} {
			if a, ok := h.(interface{ RemoteAddr() net.Addr }); ok {
				if addr := a.RemoteAddr(); addr != nil {
					return addr
				}
			}
		}
	}
	return addr{}
}

// addr is the address of a Conn whose halves have none.
type addr struct{}

func (addr) Network() string { return "duplex" }
func (addr) String() string  { return "duplex" }

// waiter is a broadcast for state guarded by a mutex: wait parks until the
// next broadcast, the deadline or the end of done.
type waiter struct {
	ch chan struct{}
}

func (w *waiter) broadcast() {
	if w.ch != nil {
		close(w.ch)
		w.ch = nil
	}
}

// wait unlocks mu, waits for a broadcast, the deadline, if not zero, or
// done, and locks mu again. It reports os.ErrDeadlineExceeded for a
// deadline that has passed, without waiting.
func (w *waiter) wait(mu *sync.Mutex, deadline time.Time, done <-chan struct{}) error {
	var tc <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		tc = t.C
	}
	if w.ch == nil {
		w.ch = make(chan struct{})
	}
	ch := w.ch
	mu.Unlock()
	defer mu.Lock()
	select {
	case <-ch:
	case <-tc:
	case <-done:
	}
	return nil
}
