package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	idle      time.Duration
	halfClose bool
	groups    []*ConnGroup
	flows     [2]RelayFlow // a to b, b to a
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
// RelayFlow.Wait does not count as idle. As with RelayFlow hooks, the ends'
// own WriteTo and ReadFrom are then not used. A non-positive d sets none.
func WithRelayIdleTimeout(d time.Duration) RelayOption {
	return func(o *relayOptions) {
		o.idle = d
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

func (stop relayCloser) closeMember(cause error, _ bool) error {
	if cause == nil {
		stop(ErrRelayGroupClosed)
	} else {
		stop(&groupClosedError{cause: cause})
	}
	return nil
}

// groupClosedError ends a relay that a group closed with a cause; it matches
// both ErrRelayGroupClosed and the cause.
type groupClosedError struct{ cause error }

func (e *groupClosedError) Error() string {
	return ErrRelayGroupClosed.Error() + ": " + e.cause.Error()
}
func (e *groupClosedError) Unwrap() []error { return []error{ErrRelayGroupClosed, e.cause} }

// RelayFlow paces and counts one direction of a Relay or a Copy. Any of its
// functions may be nil. They are called from the goroutine copying that
// direction, one call at a time; functions shared by both directions, or by
// several relays, as a limiter of one user is, must be safe for concurrent
// use.
type RelayFlow struct {
	// Wait is called before each read from the direction's source with the
	// most bytes Relay can take at once, and blocks until bytes may pass. It
	// returns how many may pass now, from 1 to n: a stream is read for at
	// most that many, and a datagram is read whole, as it cannot be split.
	// On Unix systems, a source read straight from a socket is waited on
	// until it has data first, and its end is passed on without Wait; for
	// other sources Wait runs while they may still be idle, and before the
	// read that finds their end. A blocked Wait holds none of Relay's
	// buffers or pipes. A Wait that may block for long must return when ctx
	// is done: closing the relay's ends does not wake it, so end such relays
	// with Relay's context or WithRelayGroup.
	// Wait need not charge them, since Done reports what passed: a limiter
	// can charge that, going into debt that a later Wait waits out, so that
	// a relay idle in a read holds none of an allowance it shares. ctx is
	// done once the relay stops. An error ends the relay and is returned.
	Wait func(ctx context.Context, n int64) (int64, error)
	// Done is called with the bytes written to the direction's destination
	// after each write. An error, such as for a used up allowance, ends the
	// relay and is returned.
	Done func(n int64) error
	// First is called once with the first bytes read from the direction's
	// source, a stream's first non-empty read or the first datagram, before
	// they are written, so that a relay can tell the protocol of a
	// connection or log the start of it. b is valid only during the call.
	// A stream's first read goes through Relay's buffer, also where Relay
	// splices the rest.
	First func(b []byte)
	// End is called once when the direction stops, with the bytes it
	// copied and the error that stopped it: nil at the source's EOF, or
	// net.ErrClosed when the relay stopped it for another reason, such as
	// the other direction ending. Relay calls it before it passes the end on
	// with CloseWrite or stops the relay, so that the other direction can
	// be given a shorter idle timeout once one has ended, and Copy before it
	// returns. Unlike the other hooks, End alone does not make a direction
	// go through Relay's buffer.
	End func(n int64, err error)
}

func (f *RelayFlow) active() bool {
	return f.Wait != nil || f.Done != nil || f.First != nil
}

// firstHook returns First, which a copy calls on its first read.
func (f *RelayFlow) firstHook() func([]byte) {
	if f == nil {
		return nil
	}
	return f.First
}

// wait returns how many bytes may pass of at most limit, limit without Wait.
func (f *RelayFlow) wait(ctx context.Context, limit int64) (int64, error) {
	if f == nil || f.Wait == nil {
		return limit, nil
	}
	n, err := f.Wait(ctx, limit)
	if err != nil {
		if ctx.Err() != nil {
			// Ended by the relay or its context; the cause, not the
			// hook's view of it.
			return 0, context.Cause(ctx)
		}
		return 0, err
	}
	return min(max(n, 1), limit), nil
}

func (f *RelayFlow) done(n int64) error {
	if f == nil || f.Done == nil || n <= 0 {
		return nil
	}
	return f.Done(n)
}

// WithRelayFlows paces and counts the two directions of a Relay, from a to b
// and from b to a; see RelayFlow. A direction whose flow has Wait, Done or
// First is copied with splice where Relay would splice it, in pieces, so that
// Done sees the bytes as they pass, and otherwise through Relay's buffer: the
// reading end's WriteTo and the writing end's ReadFrom are not used, so only
// the sources that Relay knows to return one datagram per Read are read a
// datagram at a time.
func WithRelayFlows(aToB, bToA RelayFlow) RelayOption {
	return func(o *relayOptions) {
		o.flows = [2]RelayFlow{aToB, bToA}
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
// PrefixConns, AddrOverrideConns and TimeoutConns, whose idle deadlines it
// then refreshes itself, for splice and its other fast paths, but not
// through other wrappers. Otherwise a direction is copied with the reading
// end's WriteTo or else the writing end's ReadFrom, as io.Copy would, except
// those of *net.TCPConn, whose data goes through a pooled 32 KiB buffer
// instead. A stream read straight from a socket takes that buffer only once
// the socket is readable, on Unix systems, so that an idle relay holds none.
//
// A source that returns one datagram per Read, such as a *net.UDPConn, a
// PacketListener connection, a FramedConn with WithFramedDatagrams, or a
// connection of another package whose LocalAddr is on a datagram network
// (udp, ip, unixgram), has each datagram written whole with one Write, empty
// ones included. A
// PacketListener connection hands its queued datagrams over and a FramedConn
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
		idle = newRelayIdle(cfg.idle)
		cfg.flows[0] = idle.watch(cfg.flows[0])
		cfg.flows[1] = idle.watch(cfg.flows[1])
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
	// finish handles the end of the copy into dst.
	finish := func(dst io.ReadWriteCloser, copyErr error) {
		if copyErr == nil && cfg.halfClose && closeWrite(dst) == nil {
			return
		}
		stop(copyErr)
	}

	// direction copies src to dst and handles its end.
	direction := func(dst, src io.ReadWriteCloser, f *RelayFlow) int64 {
		n, copyErr := relayDirection(flowCtx, dst, src, f)
		endErr := copyErr
		if endErr != nil && stopping.Load() {
			endErr = net.ErrClosed // the relay's own Close ended it
		}
		f.end(n, endErr)
		finish(dst, copyErr)
		return n
	}
	var wg sync.WaitGroup
	wg.Go(func() { aToB = direction(b, a, &cfg.flows[0]) })
	bToA = direction(a, b, &cfg.flows[1])
	wg.Wait()

	// Both directions ended with EOF after half-closing, unless the relay
	// stopped already.
	stop(nil)
	return aToB, bToA, err
}

// Copy copies src to dst until src's EOF or an error, as one direction of a
// Relay does, with the same splicing, waiting without a buffer and handling
// of datagrams, paced and counted by f, whose zero value does neither. It
// closes neither end and returns the bytes copied and nil at EOF, or the
// error that stopped it; f.End is called before it returns.
//
// ctx ends a blocked f.Wait, and, since Copy does not close the ends, once
// ctx is done Copy sets an expired read deadline on src and an expired write
// deadline on dst, those that have SetReadDeadline and SetWriteDeadline, to
// interrupt a blocked read or write, and returns context.Cause(ctx); the
// deadlines stay set for the caller to reset. A source or destination without
// deadlines must be closed to end a Copy blocked on it.
func Copy(ctx context.Context, dst io.Writer, src io.Reader, f RelayFlow) (int64, error) {
	if ctx.Err() != nil {
		err := context.Cause(ctx)
		f.end(0, err)
		return 0, err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		past := time.Unix(1, 0)
		if r, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = r.SetReadDeadline(past)
		}
		if w, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = w.SetWriteDeadline(past)
		}
	})
	n, err := relayDirection(ctx, dst, src, &f)
	if !stop() {
		// ctx ended: wait until the deadlines are set, so that they cannot
		// undo deadlines the caller sets after Copy returns.
		<-interrupted
		if err != nil {
			err = context.Cause(ctx)
		}
	}
	f.end(n, err)
	return n, err
}

func (f *RelayFlow) end(n int64, err error) {
	if f.End != nil {
		f.End(n, err)
	}
}

// relayIdle is the idle timeout of a relay: the flows of both directions
// record when data passes, and a timer stops the relay once none has for d.
type relayIdle struct {
	timer    *time.Timer
	d        time.Duration
	activity atomic.Int64 // clockOffset of the last data
	waiting  atomic.Int32 // flows blocked in Wait, which is not idleness
	mu       sync.Mutex   // orders the timer with start and its stop
	stopped  bool
}

func newRelayIdle(d time.Duration) *relayIdle {
	i := &relayIdle{d: d}
	i.touch()
	return i
}

func (i *relayIdle) touch() { i.activity.Store(clockOffset(time.Now())) }

// watch returns f recording the data that passes, and its waits.
func (i *relayIdle) watch(f RelayFlow) RelayFlow {
	done := f.Done
	f.Done = func(n int64) error {
		i.touch()
		if done != nil {
			return done(n)
		}
		return nil
	}
	if wait := f.Wait; wait != nil {
		f.Wait = func(ctx context.Context, n int64) (int64, error) {
			i.waiting.Add(1)
			defer func() {
				i.touch()
				i.waiting.Add(-1)
			}()
			return wait(ctx, n)
		}
	}
	return f
}

// start starts the timer, which calls stop once the relay is idle, and
// returns a function that ends it.
func (i *relayIdle) start(stop func()) func() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.timer = time.AfterFunc(i.d, func() { i.check(stop) })
	return func() {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.stopped = true
		i.timer.Stop()
	}
}

func (i *relayIdle) check(stop func()) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return
	}
	left := time.Duration(i.activity.Load() + int64(i.d) - clockOffset(time.Now()))
	if i.waiting.Load() > 0 {
		left = i.d // a Wait that blocks counts as activity
	}
	if left > 0 {
		i.timer.Reset(left)
		return
	}
	i.stopped = true
	stop()
}

// relayDirection copies src to dst for Relay, through f when it is active.
func relayDirection(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, error) {
	if !f.active() {
		return relayCopy(dst, src)
	}
	dst = unwrapPrefixWriter(dst)
	var prefix int64
	if f.First != nil && !datagramReader(src) {
		// A stream's first read goes through the buffer, for First, which
		// the copy of the rest, however it goes, then never sees.
		n, over, err := copyFirstPiece(ctx, dst, src, f)
		if over {
			return n, err
		}
		prefix = n
		rest := *f
		rest.First = nil
		f = &rest
	}
	if canSplice(dst, src) {
		n, ok, err := spliceCopy(ctx, dst, src, f)
		if ok {
			return prefix + n, err
		}
		prefix += n
	}
	if datagramReader(src) {
		n, err := copyDatagrams(ctx, dst, src, f)
		return prefix + n, err
	}
	n, err := copyStream(ctx, dst, src, f)
	return prefix + n, err
}

// copyFirstPiece copies the first non-empty read of src to dst through
// Relay's buffer, giving it to f.First first, and reports whether the copy
// is over, at the end of src or on an error.
func copyFirstPiece(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, bool, error) {
	sock := socketSource(src)
	for {
		end := false
		if sock != nil {
			var err error
			if end, err = sock.wait(); err != nil {
				return 0, true, err
			}
		}
		n := int64(relayBufSize)
		if !end {
			var err error
			if n, err = f.wait(ctx, relayBufSize); err != nil {
				return 0, true, err
			}
		}
		bp := relayBufPool.Get().(*[]byte)
		r, rerr := src.Read((*bp)[:n])
		var written int64
		if r > 0 {
			f.First((*bp)[:r])
			m, werr := dst.Write((*bp)[:r])
			written = int64(m)
			if werr == nil && m != r {
				werr = io.ErrShortWrite
			}
			if derr := f.done(written); werr == nil {
				werr = derr
			}
			if werr != nil {
				relayBufPool.Put(bp)
				return written, true, werr
			}
		}
		relayBufPool.Put(bp)
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, true, rerr
		}
		if r > 0 {
			return written, false, nil
		}
	}
}

func relayCopy(dst io.Writer, src io.Reader) (int64, error) {
	// A PrefixConn writes straight to the connection it wraps.
	dst = unwrapPrefixWriter(dst)
	if canSplice(dst, src) {
		n, ok, err := spliceCopy(context.Background(), dst, src, nil)
		if !ok {
			var m int64
			m, err = io.Copy(dst, src)
			n += m
		}
		return n, err
	}
	if wt, ok := ownWriterTo(src); ok {
		return wt.WriteTo(dst)
	}
	// Before the writing end's ReadFrom, which would copy datagrams through
	// a buffer of its own, perhaps cutting them, and drop empty ones.
	if datagramReader(src) {
		return copyDatagrams(context.Background(), dst, src, nil)
	}
	if rf, ok := dst.(io.ReaderFrom); ok && !isStdConn(dst) {
		return rf.ReadFrom(src)
	}
	return copyStream(context.Background(), dst, src, nil)
}

// relaySocket is a source that Relay can wait on without a buffer; see
// socketSource.
type relaySocket interface {
	// wait waits until the source has data, an end or an error, reports
	// an end, and returns the error of a failed wait as a read would.
	wait() (end bool, err error)
	// readNow reads what the source holds without waiting, or reports
	// blocked.
	readNow(b []byte) (n int, blocked bool, err error)
}

// copyStream copies src to dst through a pooled buffer. A source read
// straight from a socket is waited on until it is readable without the
// buffer; without Wait, a read after one that filled the buffer takes only
// what is already there instead, waiting only when there is nothing. A
// blocked Wait holds no buffer either. Other sources keep the buffer, as
// their reads hold it anyway.
func copyStream(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, error) {
	sock := socketSource(src)
	paced := f != nil && f.Wait != nil
	var (
		written int64
		bp      *[]byte
		full    bool
	)
	release := func() {
		if bp != nil {
			relayBufPool.Put(bp)
			bp = nil
		}
	}
	defer release()
	for {
		end := false
		// With Wait, always: Wait then paces what is there, and the end
		// passes without it.
		if sock != nil && (!full || paced) {
			release()
			var err error
			if end, err = sock.wait(); err != nil {
				return written, err
			}
		}
		n := int64(relayBufSize)
		if !end {
			// At the end there is nothing for Wait to pace.
			if paced {
				release()
			}
			var err error
			if n, err = f.wait(ctx, relayBufSize); err != nil {
				return written, err
			}
		}
		if bp == nil {
			bp = relayBufPool.Get().(*[]byte)
		}
		buf := (*bp)[:n]
		var (
			r    int
			rerr error
		)
		if sock != nil && full && !paced {
			var blocked bool
			if r, blocked, rerr = sock.readNow(buf); blocked {
				full = false // wait for it without the buffer
				continue
			}
		} else {
			r, rerr = src.Read(buf)
		}
		full = r == len(buf)
		if r > 0 {
			m, werr := dst.Write(buf[:r])
			written += int64(m)
			if werr == nil && m != r {
				werr = io.ErrShortWrite
			}
			if derr := f.done(int64(m)); werr == nil {
				werr = derr
			}
			if werr != nil {
				return written, werr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

// datagramSource is a source of this package that hands its datagrams over
// in pooled buffers, which the caller gives back with putDatagramBuf: a
// PacketListener connection, whose queue holds them so, or a FramedConn with
// WithFramedDatagrams, which waits for a frame's header before it takes a
// buffer that fits the frame. A relay from one holds no buffer while idle and
// copies each datagram once.
type datagramSource interface {
	nextDatagram() (*[]byte, error)
}

// datagramSourceOf returns the datagramSource that src reads, also beneath
// this package's pass-through wrappers, or nil.
func datagramSourceOf(src io.Reader) datagramSource {
	if prefixPending(src) {
		return nil
	}
	switch c := unwrapPrefix(src).(type) {
	case *packetConn:
		if c != nil {
			return c
		}
	case *FramedConn:
		if c != nil && c.datagram {
			return c
		}
	}
	return nil
}

// getDatagramBuf returns a pooled buffer of n bytes, n at most
// relayDatagramBufSize.
func getDatagramBuf(n int) *[]byte {
	if n <= packetBufSize {
		bp := packetBufPool.Get().(*[]byte)
		*bp = (*bp)[:n]
		return bp
	}
	bp := relayDatagramBufPool.Get().(*[]byte)
	*bp = (*bp)[:n]
	return bp
}

// putDatagramBuf gives back a buffer of getDatagramBuf or of a
// PacketListener connection's queue; others are dropped.
func putDatagramBuf(bp *[]byte) {
	switch cap(*bp) {
	case packetBufSize:
		putPacketBuf(bp)
	case relayDatagramBufSize:
		*bp = (*bp)[:relayDatagramBufSize]
		relayDatagramBufPool.Put(bp)
	}
}

// copySourceDatagrams copies the datagrams of src to dst with one Write
// each, in the buffers that src hands over, refreshing the deadlines of the
// TimeoutConns ts around src before each.
func copySourceDatagrams(ctx context.Context, dst io.Writer, src datagramSource, ts relayTimeouts, f *RelayFlow) (int64, error) {
	first := f.firstHook()
	var written int64
	for {
		if _, err := f.wait(ctx, relayDatagramBufSize); err != nil {
			return written, err
		}
		if err := ts.refresh(); err != nil {
			return written, err
		}
		bp, err := src.nextDatagram()
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return written, err
		}
		n := len(*bp)
		if first != nil {
			first(*bp)
			first = nil
		}
		m, werr := dst.Write(*bp)
		putDatagramBuf(bp)
		written += int64(m)
		if werr == nil && m != n {
			werr = io.ErrShortWrite
		}
		if derr := f.done(int64(m)); werr == nil {
			werr = derr
		}
		if werr != nil {
			return written, werr
		}
	}
}

// copyDatagrams copies each datagram that a Read of src returns to dst with
// one Write, empty datagrams included, which io.Copy would drop.
func copyDatagrams(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, error) {
	if ds := datagramSourceOf(src); ds != nil {
		return copySourceDatagrams(ctx, dst, ds, timeoutsOf(src), f)
	}
	paced := f != nil && f.Wait != nil
	first := f.firstHook()
	var bp *[]byte
	defer func() {
		if bp != nil {
			relayDatagramBufPool.Put(bp)
		}
	}()
	var written int64
	for {
		if paced && bp != nil {
			// A blocked Wait holds no buffer.
			relayDatagramBufPool.Put(bp)
			bp = nil
		}
		if _, err := f.wait(ctx, relayDatagramBufSize); err != nil {
			return written, err
		}
		if bp == nil {
			bp = relayDatagramBufPool.Get().(*[]byte)
		}
		buf := *bp
		n, err := src.Read(buf)
		if n > 0 || err == nil {
			if first != nil {
				first(buf[:n])
				first = nil
			}
			m, werr := dst.Write(buf[:n])
			written += int64(m)
			if werr == nil && m != n {
				werr = io.ErrShortWrite
			}
			if derr := f.done(int64(m)); werr == nil {
				werr = derr
			}
			if werr != nil {
				return written, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return written, err
		}
	}
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

// innerReader is implemented by the wrappers of this package, whose Reads
// read the reader it returns, so that Relay can look through each layer.
type innerReader interface {
	innerReader() io.Reader
}

// datagramReader reports whether each Read of r returns one datagram, which a
// buffer shorter than the datagram would truncate: a FramedConn with
// WithFramedDatagrams, or a connection over a PacketListener peer or a UDP, IP
// or Unix datagram socket, also beneath wrappers.
func datagramReader(r io.Reader) bool {
	for range maxUnwrapDepth {
		next, ok := r.(innerReader)
		if !ok || isDatagramConn(r) {
			break
		}
		if r = next.innerReader(); r == nil {
			return false
		}
	}
	if isDatagramConn(r) {
		return true
	}
	// Wrappers of other packages may expose the connection beneath them,
	// which is only looked at here, not owned.
	//noinspection GoResourceLeak
	if isDatagramConn(rawConnOf(r)) {
		return true
	}
	return datagramNetwork(r)
}

// datagramNetwork reports whether r is a connection of another package whose
// local address is on a datagram network, such as a connection per UDP peer
// or flow, whose Reads then return one datagram each. A stream over UDP that
// reports a UDP address is copied as datagrams too, which keeps its bytes.
func datagramNetwork(r io.Reader) bool {
	c, ok := r.(interface{ LocalAddr() net.Addr })
	if !ok || isNilPointer(c) {
		return false
	}
	addr := c.LocalAddr()
	if addr == nil {
		return false
	}
	network := addr.Network()
	if base, _, ok := strings.Cut(network, ":"); ok {
		network = base // "ip4:icmp" and the like
	}
	switch network {
	case "udp", "udp4", "udp6", "ip", "ip4", "ip6", "unixgram", "unixpacket":
		return true
	}
	return false
}

func isDatagramConn(r any) bool {
	switch c := r.(type) {
	case *FramedConn:
		return c != nil && c.datagram
	case *packetConn, *net.UDPConn, *net.IPConn:
		return true
	case *net.UnixConn:
		return c != nil && !isStreamUnix(c)
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

// unwrapPrefixWriter returns the connection beneath any PrefixConns and
// AddrOverrideConns around w, whose writes go straight to it. It stops at a
// TimeoutConn, whose writes refresh its deadline.
func unwrapPrefixWriter(w io.Writer) io.Writer {
	for range maxUnwrapDepth {
		next := plainPassThrough(w)
		if next == nil {
			break
		}
		w = next
	}
	return w
}

// unwrapPrefix returns the connection beneath the pass-through wrappers
// around r; see passThrough.
func unwrapPrefix(r io.Reader) io.Reader {
	for range maxUnwrapDepth {
		next := passThrough(r)
		if next == nil {
			break
		}
		r = next
	}
	return r
}

// unwrapConn is unwrapPrefix for either end.
func unwrapConn(v any) any {
	for range maxUnwrapDepth {
		next := passThrough(v)
		if next == nil {
			break
		}
		v = next
	}
	return v
}

// passThrough returns the connection that v passes its data to unchanged, or
// nil: that of a PrefixConn, after its prefix, of an AddrOverrideConn or a
// ConnGroup's tracked connection, or of a TimeoutConn, whose deadlines a relay that reads or writes the connection
// beneath refreshes with relayTimeouts.
func passThrough(v any) net.Conn {
	if c, ok := v.(*TimeoutConn); ok {
		if c != nil {
			return c.conn
		}
		return nil
	}
	return plainPassThrough(v)
}

// plainPassThrough is passThrough without TimeoutConn.
func plainPassThrough(v any) net.Conn {
	switch c := v.(type) {
	case *PrefixConn:
		if c != nil {
			return c.conn
		}
	case *AddrOverrideConn:
		if c != nil {
			return c.conn
		}
	case *trackedConn:
		if c != nil {
			return c.conn
		}
	}
	return nil
}

// relayTimeouts are the TimeoutConns around a connection that a relay reads
// or writes beneath them, whose idle deadlines it then refreshes, as their
// own Read and Write do, before each wait, read or write.
type relayTimeouts []*TimeoutConn

// timeoutsOf returns the TimeoutConns among the pass-through wrappers
// around v.
func timeoutsOf(v any) relayTimeouts {
	var ts relayTimeouts
	for range maxUnwrapDepth {
		if c, ok := v.(*TimeoutConn); ok && c != nil && c.conn != nil {
			ts = append(ts, c)
		}
		// The connection beneath is only looked at, not owned.
		//noinspection GoResourceLeak
		next := passThrough(v)
		if next == nil {
			break
		}
		v = next
	}
	return ts
}

// refresh moves the idle deadline of each TimeoutConn on.
func (ts relayTimeouts) refresh() error {
	for _, c := range ts {
		if err := c.refreshDeadline(); err != nil {
			return err
		}
	}
	return nil
}

// spliceOS reports whether *net.TCPConn moves data with splice(2).
const spliceOS = runtime.GOOS == "linux" || runtime.GOOS == "android"

// canSplice reports whether io.Copy(dst, src) moves the data with splice:
// from a TCP or Unix stream connection into a TCP connection, or from a TCP
// connection into a Unix stream connection, also beneath the pass-through
// wrappers of either end.
func canSplice(dst io.Writer, src io.Reader) bool {
	if !spliceOS {
		return false
	}
	src = unwrapPrefix(src)
	switch d := unwrapConn(dst).(type) {
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

// prefixPending reports whether a PrefixConn around r, beneath this
// package's pass-through wrappers, still holds prefix bytes.
func prefixPending(r io.Reader) bool {
	for range maxUnwrapDepth {
		if c, ok := r.(*PrefixConn); ok && c != nil && !c.drained.Load() {
			return true
		}
		// The connection beneath is only looked at, not owned.
		//noinspection GoResourceLeak
		next := passThrough(r)
		if next == nil {
			return false
		}
		r = next
	}
	return false
}
