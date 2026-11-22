//go:build unix

package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/djylb/netx/internal/netutil"
)

// streamSocket is a source read straight from a TCP or Unix stream socket,
// also beneath this package's pass-through wrappers, which Relay can wait on
// without a buffer. Other sources may hold data the socket does not show, as
// a TLS connection does.
type streamSocket struct {
	src  *relaySource // what Relay reads, around conn
	conn net.Conn
	raw  syscall.RawConn
	err  error
	peek func(fd uintptr) bool
	read func(fd uintptr) bool
	// peekOnce peeks on its first call of a wait and reports readable on
	// the next, once the poller has woken the wait; see waitReadable.
	peekOnce func(fd uintptr) bool
	buf      []byte
	n        int
	// The state of a call, which the callbacks below share, so that they are
	// made once.
	peekBuf [1]byte
	blocked bool
	peeked  bool
}

// socketSource returns the stream socket that s reads, or nil.
func socketSource(s *relaySource) relaySocket {
	var sc syscall.Conn
	conn, ok := s.base.(net.Conn)
	switch c := conn.(type) {
	case *net.TCPConn:
		sc = c
	case *net.UnixConn:
		if !netutil.IsStreamUnix(c) {
			return nil
		}
		sc = c
	}
	if !ok || sc == nil {
		return nil
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	st := &streamSocket{src: s, conn: conn, raw: raw}
	st.peek = func(fd uintptr) bool {
		for {
			n, _, err := syscall.Recvfrom(int(fd), st.peekBuf[:], syscall.MSG_PEEK)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return false
			}
			st.n, st.err = n, err
			return true
		}
	}
	st.peekOnce = func(fd uintptr) bool {
		if st.peeked {
			return true
		}
		st.peeked = true
		return st.peek(fd)
	}
	st.read = func(fd uintptr) bool {
		for {
			n, err := syscall.Read(int(fd), st.buf)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			st.blocked = errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
			st.n, st.err = n, err
			return true
		}
	}
	return st
}

// wait waits until the socket has data, an end or an error to read, and
// reports whether the stream has ended. It returns the socket's pending
// error, such as a reset: peeking at it clears it on Linux, so a read would
// report a clean end instead, and the error of the wait itself, as for a
// closed connection or a passed deadline, as a read would.
func (s *streamSocket) wait(context.Context) (bool, error) {
	if s.src.exhausted() {
		return true, nil // the bound ends the source
	}
	if s.src.prefixPending() {
		return false, nil
	}
	if err := s.src.timeouts.refresh(); err != nil {
		return false, err
	}
	s.n, s.err = 0, nil
	if err := s.raw.Read(s.peek); err != nil {
		return false, netutil.RawOpError(err, "read")
	}
	if s.err != nil {
		return false, sockOpError(s.conn, "read", "recvfrom", s.err)
	}
	return s.n == 0, nil
}

// waitReadable waits until the socket is readable, as wait does, for a read
// that follows at once: it peeks only before it parks and trusts the
// poller's wake-up after, leaving the end and an error that comes later to
// that read, which saves a system call per wake-up.
func (s *streamSocket) waitReadable() error {
	if s.src.exhausted() || s.src.prefixPending() {
		return nil
	}
	if err := s.src.timeouts.refresh(); err != nil {
		return err
	}
	s.n, s.err, s.peeked = 0, nil, false
	if err := s.raw.Read(s.peekOnce); err != nil {
		return netutil.RawOpError(err, "read")
	}
	if s.err != nil {
		return sockOpError(s.conn, "read", "recvfrom", s.err)
	}
	return nil
}

// readNow reads into b what the socket holds, without waiting: it reports
// blocked when there is nothing yet. Bytes a PrefixConn holds are read
// through it.
func (s *streamSocket) readNow(b []byte) (int, bool, error) {
	if s.src.prefixPending() {
		n, err := s.src.r.Read(b)
		return n, false, err
	}
	if s.src.exhausted() {
		return 0, false, io.EOF
	}
	b = b[:s.src.limited(int64(len(b)))]
	if err := s.src.timeouts.refresh(); err != nil {
		return 0, false, err
	}
	s.buf, s.n, s.err, s.blocked = b, 0, nil, false
	err := s.raw.Read(s.read)
	s.buf = nil
	switch {
	case err != nil, s.blocked:
		// wait reports a failure as a read would.
		return 0, true, nil //nolint:nilerr // the error is left for wait to report
	case s.err != nil:
		return 0, false, sockOpError(s.conn, "read", "read", s.err)
	case s.n == 0 && len(b) > 0:
		return 0, false, io.EOF
	}
	s.src.consumed(s.n)
	return s.n, false, nil
}

// sockOpError reports the error of a system call on c as c's own I/O errors
// are reported.
func sockOpError(c net.Conn, op, syscallName string, err error) error {
	return &net.OpError{Op: op, Net: c.LocalAddr().Network(), Source: c.LocalAddr(),
		Addr: c.RemoteAddr(), Err: os.NewSyscallError(syscallName, err)}
}

// socketReader reads a stream socket without waiting, failing with
// ErrWouldBlock when it holds nothing.
type socketReader struct{ s *streamSocket }

func (r socketReader) Read(p []byte) (int, error) {
	n, blocked, err := r.s.readNow(p)
	if blocked {
		return 0, ErrWouldBlock
	}
	return n, err
}

// readFromReady copies a stream socket into the destination's ReadFrom
// only while the socket has data: ReadFrom reads until the socket would
// block and then returns, and the copy waits for more without calling it,
// so that a buffer or write space ReadFrom takes, which a blocked read would
// keep, is not held while the direction is idle. ReadFrom must return a
// read error, as io.ReaderFrom does, and stay usable after it.
func (s *streamSocket) readFromReady(_ context.Context, rf io.ReaderFrom, idle *relayIdle) (int64, error) {
	r := idle.reader(socketReader{s})
	var written int64
	for {
		if err := s.waitReadable(); err != nil {
			return written, err
		}
		n, err := rf.ReadFrom(r)
		written += n
		if !IsWouldBlock(err) {
			return written, err
		}
	}
}
