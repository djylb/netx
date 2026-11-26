// Package dnslookup resolves names and queues datagrams pending resolution.
package dnslookup

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/djylb/netx/internal/bufpool"
)

// The bounds of Lookups.
const (
	// LookupTTL is how long a name's lookup is reused, from its end.
	LookupTTL = time.Minute
	// LookupFailureTTL is how long a failed lookup is reused, so that
	// datagrams to a name that does not resolve do not each wait for DNS.
	LookupFailureTTL = 5 * time.Second
	// MaxCachedNames is how many lookups are cached; the cache is cleared
	// when it is full.
	MaxCachedNames = 1024
	// MaxLookups is how many names are looked up at once.
	MaxLookups = 64
	// MaxLookupQueue is how many datagrams are held for one name.
	MaxLookupQueue = 16
	// MaxLookupHeld is how many bytes of datagrams are held in all.
	MaxLookupHeld = 256 << 10
)

// Lookups resolves the host names that datagrams are sent to without making
// the sender wait: Route returns a name's cached result, or holds a copy of
// the datagram while the name is looked up in a goroutine of its own and
// then hands it to the send function, in order with the later datagrams to
// the name, or drops it when the lookup fails. Results and failures are
// cached. V is what a lookup yields, such as an address. Lookups are
// bounded by MaxLookups, MaxLookupQueue and MaxLookupHeld, and Close
// cancels them. Its methods are safe for concurrent use.
type Lookups[V any] struct {
	// resolve looks a name up; send sends a held datagram to name once it
	// has resolved to v, outside the lock.
	resolve func(ctx context.Context, name string) (V, error)
	send    func(p []byte, name string, v V, port uint16)
	busy    error           // returned for a datagram beyond the bounds
	ctx     context.Context //nolint:containedctx // owned by the Lookups, canceled by Close, ending lookups
	cancel  context.CancelFunc
	names   map[string]lookupEntry[V]
	queues  map[string]*lookupQueue // by name, while it is looked up
	timeout time.Duration
	mu      sync.Mutex
	held    int // bytes of the datagrams in queues
}

type lookupEntry[V any] struct {
	expires time.Time
	err     error
	v       V
}

type lookupQueue struct {
	packets []heldDatagram
	count   int // includes packets in the send callback
}

// heldDatagram is a copy of a datagram to a name being looked up.
type heldDatagram struct {
	bp   *[]byte
	port uint16
}

// NewLookups returns Lookups that resolve names with resolve, each lookup
// bounded by timeout, send held datagrams with send, and fail datagrams
// beyond the bounds with busy.
func NewLookups[V any](timeout time.Duration, busy error, resolve func(ctx context.Context, name string) (V, error), send func(p []byte, name string, v V, port uint16)) *Lookups[V] {
	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // cancel is kept in the struct and called by Close
	return &Lookups[V]{
		resolve: resolve, send: send, busy: busy, ctx: ctx, cancel: cancel,
		names:   make(map[string]lookupEntry[V]),
		queues:  make(map[string]*lookupQueue),
		timeout: timeout,
	}
}

// Route returns the cached result of name, or its cached failure, or holds a
// copy of p, a datagram to name and port, until name resolves, starting a
// lookup if none runs, and reports whether it did. It fails with
// net.ErrClosed once Close has been called, and with the busy error beyond
// the bounds. It does not allocate for a cached name.
func (l *Lookups[V]) Route(p []byte, name string, port uint16) (v V, held bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// A running lookup takes the datagram even if the name has a fresh
	// entry, so that it is not sent before the datagrams held.
	if l.ctx.Err() != nil {
		return v, false, net.ErrClosed
	}
	queue, running := l.queues[name]
	if !running {
		if entry, ok := l.names[name]; ok && time.Now().Before(entry.expires) {
			return entry.v, false, entry.err
		}
	}
	if len(p) > MaxLookupHeld-l.held || running && queue.count >= MaxLookupQueue || !running && len(l.queues) >= MaxLookups {
		return v, false, l.busy
	}
	if !running {
		queue = new(lookupQueue)
		l.queues[name] = queue
		go l.lookupAndSend(name)
	}
	var bp *[]byte
	if len(p) <= bufpool.SmallSize {
		bp = bufpool.Small.Get()
		*bp = (*bp)[:len(p)]
	} else {
		bp = bufpool.NewBuf(len(p))
	}
	copy(*bp, p)
	queue.count++
	queue.packets = append(queue.packets, heldDatagram{bp: bp, port: port})
	l.held += len(p)
	return v, true, nil
}

// Resolve returns the cached result of name, or looks it up and caches the
// result. It fails with net.ErrClosed when Close ends the lookup.
func (l *Lookups[V]) Resolve(name string) (V, error) {
	l.mu.Lock()
	entry, ok := l.names[name]
	l.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.v, entry.err
	}
	ctx, cancel := context.WithTimeout(l.ctx, l.timeout)
	v, err := l.resolve(ctx, name)
	cancel()
	if l.ctx.Err() != nil {
		var zero V
		return zero, net.ErrClosed
	}
	ttl := LookupTTL
	if err != nil {
		ttl = LookupFailureTTL
	}
	l.mu.Lock()
	if len(l.names) >= MaxCachedNames {
		clear(l.names)
	}
	// The lookup may have taken seconds; the entry lasts from its end.
	l.names[name] = lookupEntry[V]{expires: time.Now().Add(ttl), err: err, v: v}
	l.mu.Unlock()
	return v, err
}

// lookupAndSend resolves name and then sends the datagrams held for it,
// also those held while it sends, or drops them when the lookup failed or
// l is closed.
func (l *Lookups[V]) lookupAndSend(name string) {
	v, err := l.Resolve(name)
	var batch []heldDatagram
	for {
		l.mu.Lock()
		queue := l.queues[name]
		batch, queue.packets = queue.packets, batch[:0]
		if len(batch) == 0 {
			delete(l.queues, name)
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
		for i, d := range batch {
			if err == nil && l.ctx.Err() == nil {
				l.send(*d.bp, name, v, d.port)
			}
			size := len(*d.bp)
			bufpool.Release(d.bp)
			l.mu.Lock()
			l.held -= size
			queue.count--
			l.mu.Unlock()
			batch[i] = heldDatagram{}
		}
	}
}

// Close cancels the lookups, which then drop their datagrams; Route fails
// from now on for every name.
func (l *Lookups[V]) Close() { l.cancel() }

// Running returns how many lookups run.
func (l *Lookups[V]) Running() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.queues)
}

// Held includes queued payloads and payloads still in the send callback.
func (l *Lookups[V]) Held() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held
}
