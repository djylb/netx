package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/dgram"

	"github.com/djylb/timeshim"
)

// DatagramRelay relays the datagrams of a UDP association between a stream
// that carries them with their RFC 1928 headers, one per message, and a
// PacketConn that sends them to their destinations; see Relay. Every field
// is optional. The zero DatagramRelay, and a nil one, relay every datagram.
// A DatagramRelay may serve many relays at once and must not be changed
// while any runs; its functions are called from the relays' goroutines and
// must then be safe for concurrent use.
type DatagramRelay struct {
	// Allow, if set, drops the datagrams to destinations it rejects. As with
	// Server.AllowPacket, IP addresses come as IP and other names
	// unresolved, so a policy on IP addresses must also check the addresses
	// that names resolve to, in a PacketConn that resolves them.
	Allow func(dst netx.Addr) bool
	// Sent, if set, is called with the destination and payload length of
	// each datagram that the PacketConn took.
	Sent func(dst netx.Addr, n int)
	// Received, if set, is called with the source and payload length of
	// each reply written to the stream.
	Received func(src netx.Addr, n int)
	// OnError, if set, receives the errors that drop a datagram: a
	// malformed one, a fragment (ErrFragmented), one that does not fit
	// (ErrDatagramTooLarge), a failed send, an ICMP error that a send
	// caused, or a reply that the stream did not take. The peer at the
	// stream's other end can cause these at the rate it sends, so a
	// handler that logs them should rate-limit. The error that ends the
	// relay is returned by Relay instead.
	OnError func(err error)
	// IdleTimeout, if positive, ends a relay that no datagram passed in
	// either direction for this long, with netx.ErrRelayIdle. Datagrams
	// dropped as invalid or by Allow do not count.
	IdleTimeout time.Duration
	// Clock tells the time of IdleTimeout; the system clock if nil.
	Clock timeshim.Clock
}

// ErrDatagramTooLarge drops a datagram that fills the relay's whole buffer,
// which may have cut it short: it is longer than the largest UDP datagram.
var ErrDatagramTooLarge = errors.New("socks5: UDP datagram too large")

// Relay relays datagrams between stream and out until one of them ends, and
// closes both when it returns.
//
// Each Read of stream must return one datagram with its RFC 1928 header,
// and each Write sends one, as with a netx.FramedConn made with
// netx.WithFramedDatagrams, a UDP socket connected to the client, or a
// netx.PacketListener connection. Relay sends the payload of each datagram
// to its destination through out, and writes each reply that out receives
// to stream, headed by the reply's source. Datagrams whose fragment number
// is not 0 are dropped, as RFC 1928 lets a relay that does not reassemble
// fragments do, and so are truncated ones and ones longer than any UDP
// datagram; see OnError.
//
// With out from NewPacketConn, the relay is a full-cone NAT: one socket
// sends every datagram, so all destinations see the same source address and
// port, and replies from any address and port are delivered, also from ones
// never sent to. Datagrams to a name are held while it is looked up, as
// NewPacketConn describes, and the others pass meanwhile; a reply always
// comes from an IP address. Another PacketConn, such as one that forwards
// the datagrams through a tunnel, must not block in WriteTo for long, which
// holds up the datagrams behind.
//
// Relay holds two buffers of the largest datagram, which it reuses for every
// datagram without copying it or allocating. It returns once both
// directions have stopped: when ctx ends, returning context.Cause(ctx); when
// stream reaches EOF or either side is closed, returning nil; when either
// side fails, returning the error; or with netx.ErrRelayIdle after
// IdleTimeout. Errors caused by Relay closing the two sides are not
// reported. A receive error ends the relay, except one that a UDP socket
// reports for an ICMP error caused by an earlier datagram, such as a closed
// port, of which as many are skipped as datagrams were sent.
//
// Lookups of names that NewPacketConn started may outlive Relay: closing out
// cancels them, and each ends within the lookup's timeout,
// DefaultDialTimeout, also with a resolver that does not see the
// cancellation at once; there are at most as many as NewPacketConn runs at
// once.
func (r *DatagramRelay) Relay(ctx context.Context, stream io.ReadWriteCloser, out PacketConn) error {
	var cfg DatagramRelay
	if r != nil {
		cfg = *r
	}
	var (
		once    sync.Once
		stopErr error
	)
	// stop ends the relay with err unless it has stopped already; a
	// concurrent call returns only once the sides are closed.
	stop := func(err error) {
		once.Do(func() {
			stopErr = err
			_ = stream.Close()
			_ = out.Close()
		})
	}
	if ctx.Done() != nil {
		if ctx.Err() != nil {
			stop(context.Cause(ctx))
			return stopErr
		}
		defer context.AfterFunc(ctx, func() { stop(context.Cause(ctx)) })()
	}
	d := &datagramRelay{
		stream:        stream,
		out:           out,
		allow:         cfg.Allow,
		sent:          cfg.Sent,
		received:      cfg.Received,
		onError:       cfg.OnError,
		reportInvalid: true,
	}
	if cfg.IdleTimeout > 0 {
		d.idle = startDatagramIdle(cfg.IdleTimeout, cfg.Clock, func() { stop(netx.ErrRelayIdle) })
		defer d.idle.end()
	}
	var wg sync.WaitGroup
	wg.Go(func() { stop(d.replies()) })
	stop(d.requests())
	wg.Wait()
	return stopErr
}

// datagramRelay is one relay of a DatagramRelay or of a Server association.
type datagramRelay struct {
	stream   io.ReadWriter
	out      PacketConn
	allow    func(dst netx.Addr) bool
	sent     func(dst netx.Addr, n int)
	received func(src netx.Addr, n int)
	onError  func(err error)
	idle     *datagramIdle // nil without an idle timeout
	// icmpCredit counts the datagrams sent, up to maxICMPCredit, that a
	// reported ICMP error can stand for; see replies.
	icmpCredit atomic.Int32
	// reportInvalid passes the datagrams dropped as invalid to onError,
	// which a Server does not.
	reportInvalid bool
}

// maxICMPCredit bounds the ICMP errors that replies skips without a datagram
// sent in between.
const maxICMPCredit = 64

// udpBufPool holds the buffers of the relay goroutines, which fit the
// largest datagram with its header, so that short relays do not each
// allocate them.
var udpBufPool = sync.Pool{New: func() any {
	b := make([]byte, MaxDatagramHeaderLen+dgram.MaxDatagram)
	return &b
}}

// requests sends the datagrams of the stream to their destinations until the
// stream or out ends, and returns the error that ended it, nil for an EOF or
// a close.
func (d *datagramRelay) requests() error {
	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	buf := *bp
	for {
		n, err := d.stream.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || netx.IsClosed(err) {
				return nil
			}
			return err
		}
		if n == len(buf) {
			// Valid datagrams, header included, are shorter: this one may
			// have been cut short.
			if d.reportInvalid {
				d.report(ErrDatagramTooLarge)
			}
			continue
		}
		dst, h, err := DecodeDatagram(buf[:n])
		if err != nil {
			if d.reportInvalid && d.onError != nil {
				d.onError(fmt.Errorf("socks5: udp datagram dropped: %w", err))
			}
			continue
		}
		if d.allow != nil && !d.allow(dst) {
			continue
		}
		// Only datagrams that are relayed count as activity, so that
		// invalid or refused ones do not keep an idle relay going.
		d.touch()
		m, err := d.out.WriteTo(buf[h:n], dst)
		if err != nil {
			if netx.IsClosed(err) {
				return nil
			}
			if d.onError != nil {
				d.onError(fmt.Errorf("socks5: udp send to %v: %w", dst, err))
			}
			continue
		}
		if c := d.icmpCredit.Load(); c < maxICMPCredit {
			d.icmpCredit.Store(c + 1) // only requests adds
		}
		if d.sent != nil {
			d.sent(dst, m)
		}
	}
}

// replies writes the replies that out receives, from any source, to the
// stream until either ends, and returns the error that ended it, nil for an
// EOF or a close.
func (d *datagramRelay) replies() error {
	// Replies are read in place after room for the longest header, which is
	// then written just before the payload, so they are not copied.
	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	packet := *bp
	payload := packet[MaxDatagramHeaderLen:]
	var hdr [MaxDatagramHeaderLen]byte
	for {
		n, src, err := d.out.ReadFrom(payload)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF) || netx.IsClosed(err):
				return nil
			case isICMPError(err) && d.takeICMPCredit():
				// An ICMP error for an earlier datagram, which some
				// systems report on unconnected sockets too, ends only
				// that datagram's flow, not the relay.
				if d.onError != nil {
					d.onError(fmt.Errorf("socks5: udp receive: %w", err))
				}
				continue
			}
			return fmt.Errorf("socks5: udp receive: %w", err)
		}
		d.touch()
		h, err := AppendDatagram(hdr[:0], src, nil)
		if err != nil {
			d.report(err)
			continue
		}
		start := MaxDatagramHeaderLen - len(h)
		copy(packet[start:], h)
		if _, err := d.stream.Write(packet[start : MaxDatagramHeaderLen+n]); err != nil {
			if netx.IsClosed(err) {
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, netx.ErrFrameDesync) {
				return err
			}
			// One undeliverable reply, such as one too large once wrapped,
			// does not end the relay.
			if d.onError != nil {
				d.onError(fmt.Errorf("socks5: udp reply from %v: %w", src, err))
			}
			continue
		}
		if d.received != nil {
			d.received(src, n)
		}
	}
}

// takeICMPCredit reports whether a datagram was sent that an ICMP error may
// stand for, and uses it up: each error that a socket reports stands for
// one, so a PacketConn that returns the same error again is not read in a
// loop.
func (d *datagramRelay) takeICMPCredit() bool {
	for {
		c := d.icmpCredit.Load()
		if c <= 0 {
			return false
		}
		if d.icmpCredit.CompareAndSwap(c, c-1) {
			return true
		}
	}
}

// isICMPError reports whether err is a UDP socket's report of an ICMP port
// unreachable or reset: a *net.OpError on a udp network with the
// ECONNREFUSED or ECONNRESET errno, not an error that only reads like one.
func isICMPError(err error) bool {
	var op *net.OpError
	if !errors.As(err, &op) || !strings.HasPrefix(op.Net, "udp") {
		return false
	}
	switch netx.ErrnoName(err) {
	case "ECONNREFUSED", "ECONNRESET":
		return true
	}
	return false
}

func (d *datagramRelay) report(err error) {
	if d.onError != nil {
		d.onError(err)
	}
}

func (d *datagramRelay) touch() {
	if d.idle != nil {
		d.idle.activity.Store(d.idle.epoch.Now())
	}
}

// datagramIdle ends a relay that no datagram passed for d.
type datagramIdle struct {
	d        time.Duration
	epoch    *dgram.Epoch
	activity atomic.Int64 // epoch time of the last datagram
	mu       sync.Mutex   // orders the timer with end
	timer    timeshim.Timer
	ended    bool
}

func startDatagramIdle(d time.Duration, c timeshim.Clock, stop func()) *datagramIdle {
	i := &datagramIdle{d: d, epoch: dgram.NewEpoch(c)}
	i.activity.Store(i.epoch.Now())
	i.mu.Lock()
	defer i.mu.Unlock()
	i.timer = i.epoch.Clock().AfterFunc(d, func() { i.check(stop) })
	return i
}

func (i *datagramIdle) check(stop func()) {
	i.mu.Lock()
	if i.ended {
		i.mu.Unlock()
		return
	}
	left := time.Duration(i.activity.Load() + int64(i.d) - i.epoch.Now())
	if left > 0 {
		i.timer.Reset(left)
		i.mu.Unlock()
		return
	}
	i.ended = true
	i.mu.Unlock()
	stop()
}

func (i *datagramIdle) end() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.ended = true
	i.timer.Stop()
}
