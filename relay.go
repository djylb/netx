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

// Relay copies data between a and b in both directions. When either
// direction stops, at EOF or on an error, Relay closes both a and b, which
// ends the other direction, and returns once both copies have finished.
//
// It returns the bytes copied from a to b and from b to a, and the error that
// stopped the first direction, or nil if that direction reached EOF. Errors
// caused by Relay closing the connections are not reported. The copies use
// io.CopyBuffer, so a ReaderFrom or WriterTo such as *net.TCPConn can move
// the data without a user-space buffer.
func Relay(a, b io.ReadWriteCloser) (aToB, bToA int64, err error) {
	var (
		once     sync.Once
		firstErr error
	)
	stop := func(err error) {
		once.Do(func() {
			firstErr = err
			_ = a.Close()
			_ = b.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		var err error
		aToB, err = relayCopy(b, a)
		stop(err)
	})
	var copyErr error
	bToA, copyErr = relayCopy(a, b)
	stop(copyErr)
	wg.Wait()
	return aToB, bToA, firstErr
}

func relayCopy(dst io.Writer, src io.Reader) (int64, error) {
	buf := relayBufPool.Get().(*[]byte)
	defer relayBufPool.Put(buf)
	return io.CopyBuffer(dst, src, *buf)
}
