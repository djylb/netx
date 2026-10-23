package netx

import "github.com/djylb/netx/internal/dgram"

// The pooled buffer sizes. A buffer is pooled at its full length.
const (
	// smallBufSize fits common datagrams, such as those of a PacketListener
	// queue, and small frames.
	smallBufSize = dgram.SmallSize
	// relayBufSize is the buffer a stream is copied through.
	relayBufSize = dgram.StreamSize
	// largeBufSize fits the largest UDP datagram and the largest frame with
	// its header.
	largeBufSize = dgram.LargeSize
	// datagramWaitSize is what a datagram's RelayFlow.Wait is asked for:
	// 64 KiB, the size of the largest UDP datagram rounded up.
	datagramWaitSize = 64 << 10
)

// The pools are shared with the other packages of this module, whose
// datagram queues hand their buffers to Relay.
var (
	smallBufs = dgram.Small
	relayBufs = dgram.Stream
	largeBufs = dgram.Large
)

// largeBufSize holds a frame with its header.
var _ [largeBufSize - 2 - MaxFramePayload]struct{}
var _ [2 + MaxFramePayload - largeBufSize]struct{}

// poolFor returns the pool of the smallest buffers that hold n bytes, or nil
// if none do.
func poolFor(n int) *dgram.Pool {
	switch {
	case n <= smallBufSize:
		return smallBufs
	case n <= relayBufSize:
		return relayBufs
	case n <= largeBufSize:
		return largeBufs
	}
	return nil
}

// putBuf gives back a buffer of a pool or of a datagram queue, whatever its
// length now; one whose capacity is not a pool's size is dropped.
func putBuf(bp *[]byte) { dgram.Release(bp) }
