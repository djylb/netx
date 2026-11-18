package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/timeshim"

	"github.com/djylb/netx/internal/dgram"
)

type relayOptions struct {
	flows     [2]RelayFlow // a to b, b to a
	clock     timeshim.Clock
	groups    []*ConnGroup
	idle      time.Duration
	halfClose bool
}

// RelayOption configures Relay.
type RelayOption func(*relayOptions)

// WithRelayHalfClose makes Relay pass EOF on instead of ending the relay: when one
// direction reaches EOF, Relay shuts down the writing side of the other end
// with CloseWrite and keeps copying the opposite direction until it ends too.
// An end without CloseWrite support, such as a net.Pipe, is closed as without
// this option. Pair it with an idle timeout, for example TimeoutConn, so a peer
// that never finishes cannot hold the relay open.
func WithRelayHalfClose() RelayOption {
	return func(o *relayOptions) {
		o.halfClose = true
	}
}

// WithRelayIdleTimeout ends the relay once no data has passed in either
// direction for d, and Relay then returns ErrRelayIdle. Relay watches the
// data it copies, also where it splices, and leaves the ends' deadlines
// alone, so it works on ends without deadlines too; time spent in a
// RelayFlow.Wait does not count as idle. The idle timeout keeps the fast
// paths of a direction without RelayFlow hooks: splice, in pieces, and the
// ends' own WriteTo and ReadFrom, through a writer or reader that records
// the data. A non-positive d sets none.
func WithRelayIdleTimeout(d time.Duration) RelayOption {
	return func(o *relayOptions) {
		o.idle = d
	}
}

// WithRelayClock makes the idle timeout of WithRelayIdleTimeout tell the time
// by c instead of the system clock, such as a timeshim.Fake in tests.
func WithRelayClock(c timeshim.Clock) RelayOption {
	return func(o *relayOptions) {
		o.clock = c
	}
}

// ErrRelayIdle is returned by a Relay that WithRelayIdleTimeout ended.
var ErrRelayIdle = errors.New("netx: relay idle")

// WithRelayGroup adds the relay to each group while it runs: the group's
// CloseMembers and Close end it as the end of Relay's context would, also
// while a RelayFlow.Wait blocks, which closing the relay's ends cannot do,
// and Relay returns ErrRelayGroupClosed, which also matches the cause given
// to CloseMembers. A relay started on a closed group ends at once.
func WithRelayGroup(groups ...*ConnGroup) RelayOption {
	return func(o *relayOptions) {
		o.groups = append(o.groups, groups...)
	}
}

// ErrRelayGroupClosed is returned by a Relay that a ConnGroup closed; see
// WithRelayGroup.
var ErrRelayGroupClosed = errors.New("netx: relay closed by its group")

// relayCloser is the member of a ConnGroup that stops a relay.
type relayCloser func(error)

func (stop relayCloser) Close() error {
	stop(ErrRelayGroupClosed)
	return nil
}

// stopFor stops the relay for a group closed with cause, if not nil.
func (stop relayCloser) stopFor(cause error) {
	if cause == nil {
		stop(ErrRelayGroupClosed)
	} else {
		stop(&groupClosedError{cause: cause})
	}
}

// groupClosedError ends a relay that a group closed with a cause; it matches
// both ErrRelayGroupClosed and the cause.
type groupClosedError struct{ cause error }

func (e *groupClosedError) Error() string {
	return ErrRelayGroupClosed.Error() + ": " + e.cause.Error()
}
func (e *groupClosedError) Unwrap() []error { return []error{ErrRelayGroupClosed, e.cause} }

// WithRelayFlows paces and counts the two directions of a Relay, from a to b
// and from b to a; see RelayFlow. A nil flow does neither, and the flows are
// copied, so that changing them later does not affect the relay. A
// direction whose flow has Wait, Done or
// First is copied with splice where Relay would splice it, in pieces, so that
// Done sees the bytes as they pass, and otherwise through Relay's buffer: the
// reading end's WriteTo and the writing end's ReadFrom are not used, so only
// the sources that Relay knows to return one datagram per Read are read a
// datagram at a time.
func WithRelayFlows(aToB, bToA *RelayFlow) RelayOption {
	var flows [2]RelayFlow
	for i, f := range [...]*RelayFlow{aToB, bToA} {
		if f != nil {
			flows[i] = *f
		}
	}
	return func(o *relayOptions) {
		o.flows = flows
	}
}

// Relay copies data between a and b in both directions and closes both when it
// returns. By default it stops as soon as either direction stops, at EOF or on
// an error, closing both ends to end the other direction; see WithRelayHalfClose.
//
// The end of ctx stops the relay too, closing both ends, and Relay then
// returns context.Cause(ctx), unless it had stopped already: cancel a context
// that many relays share, with a cause, to end them all, for example when an
// allowance runs out or a service is disabled; relays blocked in a read end
// too, which an error from RelayFlow.Done cannot do. A ctx that is done
// already passes no byte.
//
// It returns the bytes copied from a to b and from b to a, and the error that
// stopped the relay, or nil if it stopped at EOF. Errors caused by Relay
// closing the connections are not reported.
//
// On Linux and Android, a direction between a *net.TCPConn and another
// *net.TCPConn or a *net.UnixConn is left to the kernel with splice, through
// a pipe that it holds only while data moves. Relay looks through
// PrefixConns, AddrOverrideConns, TimeoutConns, whose idle deadlines it then
// refreshes itself, and the connections of ConnGroup.Track and
// NewSingleConnListener, for splice and its other fast paths, but not
// through other wrappers. Otherwise a direction is copied with the reading
// end's WriteTo or else the writing end's ReadFrom, as io.Copy would, except
// those of *net.TCPConn, whose data goes through a pooled 32 KiB buffer
// instead. A stream read straight from a socket takes that buffer only once
// the socket is readable, on Unix systems, so that an idle relay holds none,
// and is fed to the writing end's ReadFrom only while it has data: once the
// socket would block, ReadFrom's read fails, ReadFrom returns, and it is
// called again when the socket is readable, so that what it takes for a
// read is not held while the direction is idle. ReadFrom must return the
// read error, as io.ReaderFrom does, and stay usable after it.
//
// A direction from a ReadNotifier, such as a stream of a multiplexed
// connection, also beneath the wrappers above, is copied without a
// goroutine of its own: each notification starts a task that copies
// through the pooled buffer until TryRead would block, so that an idle
// relay between such a stream and a TCP connection keeps only the
// goroutine that called Relay, waiting for the TCP side. The rest of the
// prefix of a PrefixConn above the stream is readable at once: it is
// copied without waiting for the stream. A task blocked on
// a write holds the stream back, as a blocked copy would.
//
// A source that returns one datagram per Read, such as a *net.UDPConn, a
// PacketListener connection, a FramedConn with WithFramedDatagrams, or a
// connection of another package whose LocalAddr is on a datagram network
// (udp, ip, unixgram), has each datagram written whole with one Write, empty
// ones included. A PacketListener connection hands its queued datagrams over
// and a FramedConn
// reads each frame into a buffer that fits it, so that an idle relay holds no
// buffer and each datagram is copied once, and RelayFlow.Done may see more
// than Wait's n for one; other sources get a 64 KiB buffer, the largest UDP
// datagram.
func Relay(ctx context.Context, a, b io.ReadWriteCloser, opts ...RelayOption) (aToB, bToA int64, err error) {
	var cfg relayOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	var idle *relayIdle
	if cfg.idle > 0 {
		idle = newRelayIdle(cfg.idle, cfg.clock)
		// An active flow reports to idle itself; the others keep their
		// fast paths, around which the copy reports to idle.
		for i := range cfg.flows {
			if cfg.flows[i].active() {
				cfg.flows[i] = idle.watch(cfg.flows[i])
			}
		}
	}
	// flowCtx, for the flows, ends with the relay.
	parent := ctx
	flowCtx, cancel := parent, context.CancelFunc(func() {})
	if len(cfg.groups) > 0 || cfg.flows[0].active() || cfg.flows[1].active() {
		flowCtx, cancel = context.WithCancel(parent)
	}
	// stop ends the relay with stopErr unless it has stopped already; a
	// concurrent call returns only once the ends are closed.
	var (
		once     sync.Once
		stopping atomic.Bool
	)
	stop := func(stopErr error) {
		once.Do(func() {
			stopping.Store(true)
			err = stopErr
			cancel()
			_ = a.Close()
			_ = b.Close()
		})
	}
	if parent.Done() != nil {
		if parent.Err() != nil {
			// Not a byte passes once the context is done.
			stop(context.Cause(parent))
			return 0, 0, err
		}
		defer context.AfterFunc(parent, func() { stop(context.Cause(parent)) })()
	}
	if idle != nil {
		defer idle.start(func() { stop(ErrRelayIdle) })()
	}
	// A group that an end's Close closes, while stop runs, calls the
	// relay's member again, which then must not wait for itself.
	member := relayCloser(func(e error) {
		if !stopping.Load() {
			stop(e)
		}
	})
	var removes []func()
	defer func() {
		for _, remove := range removes {
			remove()
		}
	}()
	for i, g := range cfg.groups {
		if g == nil || slices.Contains(cfg.groups[:i], g) {
			continue
		}
		remove, addErr := g.Add(member)
		removes = append(removes, remove)
		if addErr != nil {
			// A closed group: the relay ends before it starts, also when
			// another group stops it meanwhile, which this waits for.
			stop(ErrRelayGroupClosed)
			return 0, 0, err
		}
	}
	// ended handles the end of the copy into dst.
	ended := func(dst io.ReadWriteCloser, f *RelayFlow, n int64, copyErr error) {
		endErr := copyErr
		if endErr != nil && stopping.Load() {
			endErr = net.ErrClosed // the relay's own Close ended it
		}
		f.end(n, endErr)
		if copyErr == nil && cfg.halfClose && closeWrite(dst) == nil {
			return
		}
		stop(copyErr)
	}
	dirIdle := func(f *RelayFlow) *relayIdle {
		if f.active() {
			return nil // reports to idle itself
		}
		return idle
	}
	var wg sync.WaitGroup
	// notified starts the copy of src to dst without a goroutine of its own
	// if src is a ReadNotifier, and reports whether it did.
	notified := func(dst, src io.ReadWriteCloser, f *RelayFlow, out *int64) bool {
		c := newNotifyCopy(flowCtx, dst, src, f, dirIdle(f), func(n int64, copyErr error) {
			*out = n
			ended(dst, f, n, copyErr)
			wg.Done()
		})
		if c == nil {
			return false
		}
		wg.Add(1)
		c.start()
		return true
	}
	// direction copies src to dst and handles its end.
	direction := func(dst, src io.ReadWriteCloser, f *RelayFlow) int64 {
		n, copyErr := relayDirection(flowCtx, dst, src, f, dirIdle(f))
		ended(dst, f, n, copyErr)
		return n
	}
	aNotified := notified(b, a, &cfg.flows[0], &aToB)
	bNotified := notified(a, b, &cfg.flows[1], &bToA)
	switch {
	case aNotified && bNotified:
	case aNotified:
		bToA = direction(a, b, &cfg.flows[1])
	case bNotified:
		aToB = direction(b, a, &cfg.flows[0])
	default:
		wg.Go(func() { aToB = direction(b, a, &cfg.flows[0]) })
		bToA = direction(a, b, &cfg.flows[1])
	}
	wg.Wait()

	// Both directions ended with EOF after half-closing, unless the relay
	// stopped already.
	stop(nil)
	return aToB, bToA, err
}

// Copy copies src to dst until src's EOF or an error, as one direction of a
// Relay does, with the same splicing, waiting without a buffer and handling
// of datagrams, paced and counted by f, which may be nil for neither. It
// closes neither end and returns the bytes copied and nil at EOF, or the
// error that stopped it; f.End is called before it returns.
//
// ctx ends a blocked f.Wait, and, since Copy does not close the ends, once
// ctx is done Copy sets an expired read deadline on src and an expired write
// deadline on dst, those that have SetReadDeadline and SetWriteDeadline, to
// interrupt a blocked read or write, and returns context.Cause(ctx); the
// deadlines stay set for the caller to reset. A source or destination without
// deadlines must be closed to end a Copy blocked on it.
func Copy(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, error) {
	if ctx.Err() != nil {
		err := context.Cause(ctx)
		f.end(0, err)
		return 0, err
	}
	interrupt := afterFuncSync(ctx, func() {
		if r, ok := src.(interface{ SetReadDeadline(t time.Time) error }); ok {
			_ = r.SetReadDeadline(dgram.Past)
		}
		if w, ok := dst.(interface{ SetWriteDeadline(t time.Time) error }); ok {
			_ = w.SetWriteDeadline(dgram.Past)
		}
	})
	n, err := relayDirection(ctx, dst, src, f, nil)
	// A ctx that ended interrupted the copy: Stop then waits until the
	// deadlines are set, so that they cannot undo deadlines the caller sets
	// after Copy returns.
	if !interrupt.Stop() && err != nil {
		err = context.Cause(ctx)
	}
	f.end(n, err)
	return n, err
}
