package httpproxy

import (
	"bufio"
	"errors"
	"net"
	"slices"
	"sync"
	"time"
)

// upConn is a connection to a target, with the reader of its responses.
type upConn struct {
	c   net.Conn
	br  *bufio.Reader
	key string
	// reused tells that it served a request before, so that a request
	// that fails on it before any response may be retried on a new one.
	reused bool

	// While idle in a pool, a goroutine waits on it for data, an end or its
	// idle timeout; taken and peekErr are guarded by the pool's lock.
	taken     bool
	peekErr   error
	watchDone chan struct{}
	idleSince time.Time
}

// close closes the connection and gives its reader back.
func (u *upConn) close() {
	_ = u.c.Close()
	if u.br != nil {
		putReader(u.br)
		u.br = nil
	}
}

// pool keeps idle connections to targets by key, for later requests to the
// same target, as reuse keys tell (see Server.ReuseKey). Each idle
// connection is watched by a goroutine that ends it when the target closes
// it, sends anything unasked, or when it has been idle for the idle
// timeout, so that a connection taken from the pool is not one that the
// target already closed, as far as it can be known.
type pool struct {
	mu      sync.Mutex
	idle    map[string][]*upConn
	n       int
	closed  bool
	perKey  int // most idle connections of a key; no reuse when not positive
	total   int // most idle connections; no bound when not positive
	timeout time.Duration
}

// get returns an idle connection for key, or nil.
func (p *pool) get(key string) *upConn {
	for {
		p.mu.Lock()
		list := p.idle[key]
		if len(list) == 0 {
			p.mu.Unlock()
			return nil
		}
		u := list[len(list)-1]
		list[len(list)-1] = nil
		if len(list) == 1 {
			delete(p.idle, key)
		} else {
			p.idle[key] = list[:len(list)-1]
		}
		p.n--
		u.taken = true
		p.mu.Unlock()
		// Stop the watcher: its Peek returns at once, and what it returned
		// tells whether the connection is still good.
		_ = u.c.SetReadDeadline(time.Unix(1, 0))
		<-u.watchDone
		// A timeout is the wake-up above, unless the idle timeout passed
		// just before it.
		if ne, ok := errors.AsType[net.Error](u.peekErr); !ok || !ne.Timeout() || u.br.Buffered() > 0 || time.Since(u.idleSince) >= p.timeout {
			u.close() // closed, failed, sent something unasked or idle too long
			continue
		}
		if u.c.SetReadDeadline(time.Time{}) != nil {
			u.close()
			continue
		}
		u.reused = true
		return u
	}
}

// put keeps u for a later request to its key, or closes it when the pool
// has no room, is closed, or u has no deadlines to watch it with.
func (p *pool) put(u *upConn) {
	u.idleSince = time.Now()
	if u.c.SetReadDeadline(u.idleSince.Add(p.timeout)) != nil {
		u.close()
		return
	}
	p.mu.Lock()
	if p.closed || p.perKey <= 0 || len(p.idle[u.key]) >= p.perKey || p.total > 0 && p.n >= p.total {
		p.mu.Unlock()
		u.close()
		return
	}
	if p.idle == nil {
		p.idle = make(map[string][]*upConn)
	}
	u.taken, u.peekErr, u.watchDone = false, nil, make(chan struct{})
	p.idle[u.key] = append(p.idle[u.key], u)
	p.n++
	p.mu.Unlock()
	go p.watch(u)
}

// watch waits on an idle connection until it is taken, or ends it when it
// gets data, an end or an error, or times out idle.
func (p *pool) watch(u *upConn) {
	_, err := u.br.Peek(1)
	p.mu.Lock()
	if u.taken {
		u.peekErr = err
		p.mu.Unlock()
		close(u.watchDone)
		return
	}
	if list := p.idle[u.key]; len(list) > 0 {
		if i := slices.Index(list, u); i >= 0 {
			list = slices.Delete(list, i, i+1)
			p.n--
			if len(list) == 0 {
				delete(p.idle, u.key)
			} else {
				p.idle[u.key] = list
			}
		}
	}
	p.mu.Unlock()
	close(u.watchDone)
	u.close()
}

// close closes the idle connections, whose watchers then end, and makes
// put close the connections given to it.
func (p *pool) close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle, p.n = nil, 0
	p.mu.Unlock()
	for _, list := range idle {
		for _, u := range list {
			_ = u.c.Close() // the watcher gives the reader back
		}
	}
}

// idleConns returns the number of idle connections.
func (p *pool) idleConns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}
