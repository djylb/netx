//go:build unix

package netx

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
)

// streamSocket is a source read straight from a TCP or Unix stream socket,
// also beneath this package's pass-through wrappers, which Relay can wait on
// without a buffer. Other sources may hold data the socket does not show, as
// a TLS connection does.
type streamSocket struct {
	src  io.Reader // what Relay reads, around conn
	conn net.Conn
	// timeouts are the TimeoutConns around conn, refreshed before each
	// wait or read of the socket.
	timeouts relayTimeouts
	raw      syscall.RawConn
	err      error
	peek     func(fd uintptr) bool
	read     func(fd uintptr) bool
	buf      []byte
	n        int
	// The state of a call, which the callbacks below share, so that they are
	// made once.
	peekBuf [1]byte
	blocked bool
}

// socketSource returns the stream socket that src reads, or nil.
func socketSource(src io.Reader) relaySocket {
	var sc syscall.Conn
	conn, ok := unwrapPrefix(src).(net.Conn)
	switch c := conn.(type) {
	case *net.TCPConn:
		sc = c
	case *net.UnixConn:
		if !isStreamUnix(c) {
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
	s := &streamSocket{src: src, conn: conn, raw: raw, timeouts: timeoutsOf(src)}
	s.peek = func(fd uintptr) bool {
		for {
			n, _, err := syscall.Recvfrom(int(fd), s.peekBuf[:], syscall.MSG_PEEK)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return false
			}
			s.n, s.err = n, err
			return true
		}
	}
	s.read = func(fd uintptr) bool {
		for {
			n, err := syscall.Read(int(fd), s.buf)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			s.blocked = errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
			s.n, s.err = n, err
			return true
		}
	}
	return s
}

// wait waits until the socket has data, an end or an error to read, and
// reports whether the stream has ended. It returns the socket's pending
// error, such as a reset: peeking at it clears it on Linux, so a read would
// report a clean end instead, and the error of the wait itself, as for a
// closed connection or a passed deadline, as a read would.
func (s *streamSocket) wait() (bool, error) {
	if prefixPending(s.src) {
		return false, nil
	}
	if err := s.timeouts.refresh(); err != nil {
		return false, err
	}
	s.n, s.err = 0, nil
	if err := s.raw.Read(s.peek); err != nil {
		return false, asReadError(err)
	}
	if s.err != nil {
		return false, s.opError("recvfrom", s.err)
	}
	return s.n == 0, nil
}

// readNow reads into b what the socket holds, without waiting: it reports
// blocked when there is nothing yet. Bytes a PrefixConn holds are read
// through it.
func (s *streamSocket) readNow(b []byte) (int, bool, error) {
	if prefixPending(s.src) {
		n, err := s.src.Read(b)
		return n, false, err
	}
	if err := s.timeouts.refresh(); err != nil {
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
		return 0, false, s.opError("read", s.err)
	case s.n == 0 && len(b) > 0:
		return 0, false, io.EOF
	}
	return s.n, false, nil
}

func (s *streamSocket) opError(syscallName string, err error) error {
	return &net.OpError{Op: "read", Net: s.conn.LocalAddr().Network(), Source: s.conn.LocalAddr(),
		Addr: s.conn.RemoteAddr(), Err: os.NewSyscallError(syscallName, err)}
}

// asReadError reports an error of RawConn.Read, whose operation is
// "raw-read", as one of Read.
func asReadError(err error) error {
	if err == nil {
		return nil
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "raw-read" {
		e := *oe
		e.Op = "read"
		return &e
	}
	return err
}
