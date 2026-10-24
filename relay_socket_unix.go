//go:build unix

package netx

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
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
	buf  []byte
	n    int
	// The state of a call, which the callbacks below share, so that they are
	// made once.
	peekBuf [1]byte
	blocked bool
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
func (s *streamSocket) wait() (bool, error) {
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
		return false, rawOpError(err, "read")
	}
	if s.err != nil {
		return false, sockOpError(s.conn, "read", "recvfrom", s.err)
	}
	return s.n == 0, nil
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
		return 0, true, nil
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

// rawOpError reports an error of syscall.RawConn's Read or Write, whose
// operation is "raw-read" or "raw-write", as one of Read or Write, op.
func rawOpError(err error, op string) error {
	if err == nil {
		return nil
	}
	if oe, ok := errors.AsType[*net.OpError](err); ok {
		if rawOp, raw := strings.CutPrefix(oe.Op, "raw-"); !raw || rawOp != op {
			return err
		}
		e := *oe
		e.Op = op
		return &e
	}
	return err
}
