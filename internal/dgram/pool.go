// Package dgram holds the machinery of the listeners that demultiplex one
// datagram socket into connections, one per peer or flow: pooled datagram
// buffers, a per-connection queue with a read deadline, the table of
// connections with its accept backlog, limit and idle sweep, the backoff
// of a read loop, and the lookups of the host names that datagrams are sent
// to, which hold the datagrams meanwhile. It depends on the standard library alone, so that the leaf
// packages can use it, and has no package initialisation beyond its pools.
package dgram

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
