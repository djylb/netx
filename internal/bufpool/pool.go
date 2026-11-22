// Package bufpool holds buffers shared by networking helpers.
package bufpool

import "sync"

const (
	// SmallSize fits common datagrams, such as the queued datagrams of a
	// connection, which take the room of several when larger.
	SmallSize = 2 << 10
	// StreamSize is the buffer a stream is copied through.
	StreamSize = 32 << 10
	// MaxDatagram is the largest UDP datagram.
	MaxDatagram = 65535
	// LargeSize fits the largest UDP datagram with room for a 2-byte length
	// ahead of it, as a frame header takes.
	LargeSize = 2 + MaxDatagram
)

// Pool pools buffers of one size, each at its full length. Its methods are
// small enough to be inlined.
type Pool struct {
	pool sync.Pool
	size int
}

// The shared pools, initialised statically, so that a program that links
// this package without using them runs no initialisation for them.
var (
	Small  = &Pool{pool: sync.Pool{New: func() any { return NewBuf(SmallSize) }}, size: SmallSize}
	Stream = &Pool{pool: sync.Pool{New: func() any { return NewBuf(StreamSize) }}, size: StreamSize}
	Large  = &Pool{pool: sync.Pool{New: func() any { return NewBuf(LargeSize) }}, size: LargeSize}
)

// NewBuf returns a new buffer of n bytes.
func NewBuf(n int) *[]byte {
	b := make([]byte, n)
	return &b
}

// Size returns the size of p's buffers.
func (p *Pool) Size() int { return p.size }

// Get returns a buffer of p.Size() bytes.
func (p *Pool) Get() *[]byte {
	return p.pool.Get().(*[]byte)
}

// Put gives back a buffer of Get, whatever its length now.
func (p *Pool) Put(bp *[]byte) {
	if len(*bp) != p.size {
		*bp = (*bp)[:p.size]
	}
	p.pool.Put(bp)
}

// Release gives back a buffer of one of the shared pools or of a Queue,
// whatever its length now; one of another capacity is dropped.
func Release(bp *[]byte) {
	switch cap(*bp) {
	case SmallSize:
		Small.Put(bp)
	case StreamSize:
		Stream.Put(bp)
	case LargeSize:
		Large.Put(bp)
	}
}
