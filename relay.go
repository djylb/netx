package netx

import (
	"io"
	"net"
	"runtime"
	"sync"
)

const (
	relayBufSize = 32 << 10
	// relayDatagramBufSize holds the largest UDP datagram, so that a source
	// returning one datagram per Read is not truncated.
	relayDatagramBufSize = 64 << 10
)

var (
	relayBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, relayBufSize)
			return &buf
		},
	}
	relayDatagramBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, relayDatagramBufSize)
			return &buf
		},
	}
)

type relayOptions struct {
	halfClose bool
}

// RelayOption configures Relay.
type RelayOption func(*relayOptions)

// WithHalfClose makes Relay pass EOF on instead of ending the relay: when one
// direction reaches EOF, Relay shuts down the writing side of the other end
// with CloseWrite and keeps copying the opposite direction until it ends too.
// An end without CloseWrite support, such as a net.Pipe, is closed as without
// this option. Pair it with an idle timeout, for example TimeoutConn, so a peer
// that never finishes cannot hold the relay open.
func WithHalfClose() RelayOption {
	return func(o *relayOptions) {
		o.halfClose = true
	}
}

// Relay copies data between a and b in both directions and closes both when it
// returns. By default it stops as soon as either direction stops, at EOF or on
// an error, closing both ends to end the other direction; see WithHalfClose.
//
// It returns the bytes copied from a to b and from b to a, and the error that
// stopped the relay, or nil if it stopped at EOF. Errors caused by Relay
// closing the connections are not reported.
//
// On Linux, a direction between a *net.TCPConn and another *net.TCPConn or a
// *net.UnixConn, also beneath a PrefixConn on the reading side, is left to the
// kernel with splice. Otherwise a direction is copied with the reading end's
// WriteTo or else the writing end's ReadFrom, as io.Copy would, so a datagram
// connection can keep each datagram whole; the WriteTo and ReadFrom of
// *net.TCPConn and *net.UnixConn are skipped, also beneath a PrefixConn, and
// the data goes through a pooled 32 KiB buffer instead of one they allocate.
// A source that returns one datagram per Read, such as a *net.UDPConn, a
// PacketListener connection or a FramedConn with WithDatagramReads, gets a
// 64 KiB buffer instead, so that no datagram is cut short.
func Relay(a, b io.ReadWriteCloser, opts ...RelayOption) (aToB, bToA int64, err error) {
	var cfg relayOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	var (
		mu      sync.Mutex
		stopped bool
	)
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	// finish handles the end of the copy into dst.
	finish := func(dst io.ReadWriteCloser, copyErr error) {
		if copyErr == nil && cfg.halfClose && closeWrite(dst) == nil {
			return
		}
		mu.Lock()
		first := !stopped
		stopped = true
		if first {
			err = copyErr
		}
		mu.Unlock()
		if first {
			closeBoth()
		}
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		n, copyErr := relayCopy(b, a)
		aToB = n
		finish(b, copyErr)
	})
	n, copyErr := relayCopy(a, b)
	bToA = n
	finish(a, copyErr)
	wg.Wait()

	mu.Lock()
	first := !stopped
	stopped = true
	mu.Unlock()
	if first {
		// Both directions ended with EOF after half-closing.
		closeBoth()
	}
	return aToB, bToA, err
}

func relayCopy(dst io.Writer, src io.Reader) (int64, error) {
	if canSplice(dst, src) {
		return io.Copy(dst, src)
	}
	if wt, ok := ownWriterTo(src); ok {
		return wt.WriteTo(dst)
	}
	if rf, ok := dst.(io.ReaderFrom); ok && !isStdConn(dst) {
		return rf.ReadFrom(src)
	}
	pool := &relayBufPool
	if datagramReader(src) {
		pool = &relayDatagramBufPool
	}
	buf := pool.Get().(*[]byte)
	defer pool.Put(buf)
	// Hide ReadFrom and WriteTo, or a *net.TCPConn that cannot splice copies
	// through a buffer of its own instead of the pooled one.
	return io.CopyBuffer(writerOnly{dst}, readerOnly{src}, *buf)
}

// ownWriterTo returns src's WriteTo unless it only falls back to a buffer of
// its own: that of a *net.TCPConn or *net.UnixConn, or of a PrefixConn over
// one or over a connection without WriteTo.
func ownWriterTo(src io.Reader) (io.WriterTo, bool) {
	wt, ok := src.(io.WriterTo)
	if !ok {
		return nil, false
	}
	inner := unwrapPrefix(src)
	if _, ok := inner.(io.WriterTo); !ok {
		return nil, false
	}
	return wt, !isStdConn(inner)
}

// datagramReader reports whether each Read of r returns one datagram, which a
// buffer shorter than the datagram would truncate: a FramedConn with
// WithDatagramReads, or a connection over a PacketListener peer or a UDP, IP
// or Unix datagram socket.
func datagramReader(r io.Reader) bool {
	if fc, ok := r.(*FramedConn); ok && fc != nil && fc.datagram {
		return true
	}
	switch c := rawConnOf(r).(type) {
	case *packetConn, *net.UDPConn, *net.IPConn:
		return true
	case *net.UnixConn:
		return !isStreamUnix(c)
	}
	return false
}

// isStdConn reports whether c is a *net.TCPConn or a *net.UnixConn.
func isStdConn(c any) bool {
	switch c.(type) {
	case *net.TCPConn, *net.UnixConn:
		return true
	}
	return false
}

// unwrapPrefix returns the connection beneath any PrefixConns around r.
func unwrapPrefix(r io.Reader) io.Reader {
	for {
		pc, ok := r.(*PrefixConn)
		if !ok || pc == nil || pc.Conn == nil {
			return r
		}
		r = pc.Conn
	}
}

// spliceOS reports whether *net.TCPConn moves data with splice(2).
const spliceOS = runtime.GOOS == "linux" || runtime.GOOS == "android"

// canSplice reports whether io.Copy(dst, src) moves the data with splice:
// from a TCP or Unix stream connection into a TCP connection, or from a TCP
// connection into a Unix stream connection. PrefixConn.WriteTo passes its wrapped
// connection on to io.Copy, so src is looked at beneath it.
func canSplice(dst io.Writer, src io.Reader) bool {
	if !spliceOS {
		return false
	}
	src = unwrapPrefix(src)
	switch d := dst.(type) {
	case *net.TCPConn:
		switch s := src.(type) {
		case *net.TCPConn:
			return true
		case *net.UnixConn:
			return isStreamUnix(s)
		}
	case *net.UnixConn:
		_, ok := src.(*net.TCPConn)
		return ok && isStreamUnix(d)
	}
	return false
}

// isStreamUnix reports whether c is a "unix" stream socket, the only kind of
// Unix connection that splice is used for.
func isStreamUnix(c *net.UnixConn) bool {
	addr := c.LocalAddr()
	return addr != nil && addr.Network() == "unix"
}

// readerOnly and writerOnly hide every method but Read or Write.
type readerOnly struct{ io.Reader }

type writerOnly struct{ io.Writer }
