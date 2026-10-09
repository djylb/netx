package netx

import (
	"io"
	"sync"
)

const relayBufSize = 32 << 10

var relayBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, relayBufSize)
		return &buf
	},
}

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
// closing the connections are not reported. The copies use io.CopyBuffer with
// pooled 32 KiB buffers, so a ReaderFrom or WriterTo such as *net.TCPConn can
// move the data without a user-space copy.
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
	buf := relayBufPool.Get().(*[]byte)
	defer relayBufPool.Put(buf)
	return io.CopyBuffer(dst, src, *buf)
}
