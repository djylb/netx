// Package serve holds the lifecycle that the servers of this module share:
// the listeners and connections they serve, a context that Close cancels,
// Shutdown and Close. It depends on the standard library alone.
package serve

import (
	"context"
	"errors"
	"maps"
	"net"
	"slices"
	"sync"
)

// Tracker tracks the listeners and connections of a server. The zero value
// is ready to use; it must not be copied after first use.
type Tracker struct {
	draining  bool // Shutdown was called
	closed    bool // Close was called
	mu        sync.Mutex
	ctx       context.Context // canceled by Close
	cancel    context.CancelFunc
	drain     context.Context // canceled by Shutdown and Close
	stopDrain context.CancelFunc
	// Tracked by pointer, as in net/http, since the dynamic types of a
	// net.Listener or a net.Conn need not be comparable.
	listeners map[*net.Listener]struct{}
	conns     map[*net.Conn]struct{}
	drained   chan struct{} // closed when conns empties during Shutdown
	closeDone chan struct{} // closed when the first Close has returned
}

// Serve accepts connections on l with accept and serves each with serve, in
// its own goroutine, under the context that Close cancels, passing the
// errors that end them to onError. It returns closedErr after Shutdown or
// Close, which close l, or the error that ended accepting.
func (t *Tracker) Serve(l net.Listener, closedErr error,
	accept func(context.Context, net.Listener) (net.Conn, error),
	serve func(context.Context, net.Conn) error,
	onError func(net.Conn, error)) error {
	if !t.track(&l, true) {
		_ = l.Close()
		return closedErr
	}
	defer t.track(&l, false)
	ctx := t.Context()
	for {
		c, err := accept(ctx, l)
		if err != nil {
			if t.Stopping() {
				return closedErr
			}
			return err
		}
		// Tracked before the goroutine starts, so that Shutdown, once it
		// sees no connections, cannot miss one being started. One accepted
		// just before Shutdown or Close closed the listener is refused,
		// which is no failure.
		if !t.TrackConn(&c, true) {
			_ = c.Close()
			continue
		}
		go func() {
			defer t.TrackConn(&c, false)
			if err := serve(ctx, c); err != nil {
				onError(c, err)
			}
		}()
	}
}

// Context returns the context that Close cancels.
func (t *Tracker) Context() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ctx == nil {
		t.ctx, t.cancel = context.WithCancel(context.Background())
		if t.closed {
			t.cancel()
		}
	}
	return t.ctx
}

// DrainContext returns a context that Shutdown and Close cancel, for
// connections to end once they are idle.
func (t *Tracker) DrainContext() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.drain == nil {
		t.drain, t.stopDrain = context.WithCancel(context.Background())
		if t.closed || t.draining {
			t.stopDrain()
		}
	}
	return t.drain
}

// Bind returns a context derived from ctx that also ends with Close, or
// false after Close.
func (t *Tracker) Bind(ctx context.Context) (context.Context, context.CancelFunc, bool) {
	if t.IsClosed() {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(t.Context(), cancel)
	return ctx, func() { stop(); cancel() }, true
}

// TrackConn adds c, refusing it after Shutdown or Close, or removes it.
func (t *Tracker) TrackConn(c *net.Conn, add bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if add {
		if t.closed || t.draining {
			return false
		}
		if t.conns == nil {
			t.conns = make(map[*net.Conn]struct{})
		}
		t.conns[c] = struct{}{}
		return true
	}
	delete(t.conns, c)
	if len(t.conns) == 0 && t.drained != nil {
		close(t.drained)
		t.drained = nil
	}
	return true
}

func (t *Tracker) track(l *net.Listener, add bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if add {
		if t.closed || t.draining {
			return false
		}
		if t.listeners == nil {
			t.listeners = make(map[*net.Listener]struct{})
		}
		t.listeners[l] = struct{}{}
		return true
	}
	delete(t.listeners, l)
	return true
}

// IsClosed reports whether Close was called.
func (t *Tracker) IsClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// Stopping reports whether Shutdown or Close was called.
func (t *Tracker) Stopping() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed || t.draining
}

// Locked calls fn with the tracker's lock held, telling whether Close was
// called, so that state of the server that Close ends can be set up without
// racing it.
func (t *Tracker) Locked(fn func(closed bool)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fn(t.closed)
}

// ActiveConns returns the number of tracked connections.
func (t *Tracker) ActiveConns() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// Shutdown closes the listeners, refuses new connections, waits until the
// tracked connections end or ctx ends, and then calls closeFn, the server's
// Close.
func (t *Tracker) Shutdown(ctx context.Context, closeFn func() error) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return closeFn() // waits for the Close in progress
	}
	t.draining = true
	if t.stopDrain != nil {
		t.stopDrain()
	}
	// Taken out, so that Close does not close them again.
	listeners := slices.Collect(maps.Keys(t.listeners))
	clear(t.listeners)
	var drained chan struct{}
	if len(t.conns) > 0 {
		if t.drained == nil {
			t.drained = make(chan struct{})
		}
		drained = t.drained
	}
	t.mu.Unlock()
	var errs []error
	for _, l := range listeners {
		errs = append(errs, (*l).Close())
	}
	if drained != nil {
		select {
		case <-drained:
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		}
	}
	return errors.Join(append(errs, closeFn())...)
}

// Close cancels the context, closes the listeners and the tracked
// connections and then calls extra, if not nil, for what else the server
// closes. Later calls wait until the first has finished and return nil.
func (t *Tracker) Close(extra func() error) error {
	t.mu.Lock()
	if t.closeDone == nil {
		t.closeDone = make(chan struct{})
	}
	done := t.closeDone
	if t.closed {
		t.mu.Unlock()
		<-done // the first Close finishes its work before any call returns
		return nil
	}
	t.closed = true
	defer close(done)
	if t.cancel != nil {
		t.cancel()
	}
	if t.stopDrain != nil {
		t.stopDrain()
	}
	// Close outside the lock: closing a *tls.Conn can block for seconds while
	// it sends close_notify, and serving goroutines need the lock to finish.
	listeners := slices.Collect(maps.Keys(t.listeners))
	conns := slices.Collect(maps.Keys(t.conns))
	t.mu.Unlock()
	var errs []error
	for _, l := range listeners {
		errs = append(errs, (*l).Close())
	}
	for _, c := range conns {
		_ = (*c).Close()
	}
	if extra != nil {
		errs = append(errs, extra())
	}
	return errors.Join(errs...)
}
