package netx

import (
	"io"
	"net"
	"strings"

	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/netx/internal/netutil"
)

// relaySource is the source of one direction of a Relay or a Copy as the
// copy sees it, found once when the direction starts by looking through the
// connections of this package around it.
type relaySource struct {
	r io.Reader // the source as given, which the copy reads
	// base is the connection beneath the wrappers that pass reads on
	// unchanged, which splice and a wait for data look at.
	base any
	// timeouts are the TimeoutConns among those wrappers, whose idle
	// deadlines a read beneath them refreshes.
	timeouts relayTimeouts
	// prefixes are the PrefixConns among them, which are read through until
	// their prefixes are gone.
	prefixes []*PrefixConn
	// datagrams hands base's datagrams over, or is nil.
	datagrams datagramSource
	// bottom is where the look through this package's connections ended,
	// which datagram looks at further.
	bottom      any
	sock        relaySocket // see socket
	datagram    bool        // see readsDatagrams
	datagramSet bool
	sockSet     bool
	// Room for the usual few timeouts and prefixes.
	timeoutsBuf [2]*TimeoutConn
	prefixesBuf [2]*PrefixConn
}

// datagramSource is a connection that hands its datagrams over in pooled
// buffers, which the caller gives back with putBuf: a PacketListener
// connection or a connection of another package of this module, such as a
// transparent.FlowConn, whose queue holds them so, or a FramedConn with
// WithFramedDatagrams, which waits for a frame's header before it takes a
// buffer that fits the frame. A relay from one holds no buffer while idle
// and copies each datagram once.
type datagramSource interface {
	nextDatagram() (*[]byte, error)
}

// queueSource is the datagramSource of a connection of another package of
// this module whose datagrams are in a dgram.Queue.
type queueSource struct{ q *dgram.Queue }

func (s queueSource) nextDatagram() (*[]byte, error) { return s.q.Next() }

// queueOf returns the datagram queue of v, a connection of another package
// of this module, or nil; see dgram.QueueOf.
func queueOf(v any) *dgram.Queue { return dgram.QueueOf(v) }

// relayTimeouts are the TimeoutConns around a connection that a relay reads
// or writes beneath them, whose idle deadlines it then refreshes, as their
// own Read and Write do, before each wait, read or write.
type relayTimeouts []*TimeoutConn

// refresh moves the idle deadline of each TimeoutConn on.
func (ts relayTimeouts) refresh() error {
	for _, c := range ts {
		if err := c.refreshDeadline(); err != nil {
			return err
		}
	}
	return nil
}

// relayEnds are the ends of one direction of a Relay or a Copy, which it
// looks at once when it starts.
type relayEnds struct {
	src relaySource
	dst relaySink
}

func newRelayEnds(dst io.Writer, src io.Reader) *relayEnds {
	e := new(relayEnds)
	e.src.init(src)
	e.dst.init(dst)
	return e
}

func newRelaySource(r io.Reader) *relaySource {
	s := new(relaySource)
	s.init(r)
	return s
}

// init sets s up for r.
func (s *relaySource) init(r io.Reader) {
	s.r, s.base = r, r
	s.timeouts, s.prefixes = s.timeoutsBuf[:0], s.prefixesBuf[:0]
	var v any = r
	passing := true
	for range maxUnwrapDepth {
		info, ok := layerOf(v)
		if !ok {
			if q := queueOf(v); q != nil {
				s.datagram, s.datagramSet = true, true
				if passing {
					s.datagrams = queueSource{q}
				}
				return
			}
			break
		}
		if info.datagrams != nil {
			s.datagram, s.datagramSet = true, true
			if passing {
				s.datagrams = info.datagrams
			}
			return
		}
		if passing {
			if info.kind&layerPassesThrough == 0 || info.conn == nil {
				passing = false
			} else {
				switch {
				case info.kind&layerPrefix != 0:
					s.prefixes = append(s.prefixes, v.(*PrefixConn))
				case info.kind&layerRefresh != 0:
					s.timeouts = append(s.timeouts, v.(*TimeoutConn))
				}
				s.base = info.conn
			}
		}
		if info.kind&layerReads == 0 {
			break
		}
		if v = info.reader(); v == nil {
			s.datagramSet = true // reads nothing
			return
		}
	}
	s.bottom = v
}

// readsDatagrams reports whether each Read of the source returns one
// datagram, which a buffer shorter than the datagram would truncate: a
// FramedConn with WithFramedDatagrams, or a connection over a PacketListener
// peer or a UDP, IP or Unix datagram socket, also beneath wrappers.
func (s *relaySource) readsDatagrams() bool {
	if !s.datagramSet {
		// Wrappers of other packages may expose the connection beneath
		// them, which is only looked at here, not owned.
		//noinspection GoResourceLeak
		s.datagram = isDatagramConn(s.bottom) || isDatagramConn(InnermostConn(s.bottom)) || datagramNetwork(s.bottom)
		s.datagramSet = true
	}
	return s.datagram
}

// readsDatagrams reports whether each Read of r returns one datagram; see
// relaySource.readsDatagrams.
func readsDatagrams(r io.Reader) bool {
	return newRelaySource(r).readsDatagrams()
}

// prefixPending reports whether a PrefixConn around base still holds prefix
// bytes.
func (s *relaySource) prefixPending() bool {
	for _, c := range s.prefixes {
		if c.pending() {
			return true
		}
	}
	return false
}

// socket returns the stream socket that the source reads straight from, or
// nil; see socketSource.
func (s *relaySource) socket() relaySocket {
	if !s.sockSet {
		s.sock, s.sockSet = socketSource(s), true
	}
	return s.sock
}

// ownWriterTo returns the source's WriteTo unless it only falls back to a
// buffer of its own: that of a *net.TCPConn or *net.UnixConn, or of a
// wrapper over one or over a connection without WriteTo.
func (s *relaySource) ownWriterTo() (io.WriterTo, bool) {
	wt, ok := s.r.(io.WriterTo)
	if !ok {
		return nil, false
	}
	if _, ok := s.base.(io.WriterTo); !ok {
		return nil, false
	}
	return wt, !isStdConn(s.base)
}

// relaySink is the destination of one direction as the copy sees it; see
// relaySource.
type relaySink struct {
	// w is the destination beneath the wrappers that pass writes on
	// unchanged, which the copy writes.
	w io.Writer
	// base is beneath TimeoutConns too, which splice writes to.
	base any
	// timeouts are the TimeoutConns above base, whose idle deadlines a
	// write to base refreshes.
	timeouts    relayTimeouts
	timeoutsBuf [2]*TimeoutConn
}

// init sets d up for w.
func (d *relaySink) init(w io.Writer) {
	d.w, d.base, d.timeouts = w, w, d.timeoutsBuf[:0]
	writing := true
	for range maxUnwrapDepth {
		info, ok := layerOf(d.base)
		if !ok || info.kind&layerPassesThrough == 0 || info.conn == nil {
			break
		}
		if info.kind&layerRefresh != 0 {
			// Its own writes refresh its deadline; writes beneath it would
			// have to.
			d.timeouts = append(d.timeouts, d.base.(*TimeoutConn))
			writing = false
		}
		d.base = info.conn
		if writing {
			d.w = info.conn
		}
	}
}

// isDatagramConn reports whether v is a connection whose Reads return one
// datagram each.
func isDatagramConn(v any) bool {
	switch c := v.(type) {
	case *net.UDPConn, *net.IPConn:
		return true
	case *net.UnixConn:
		return c != nil && !netutil.IsStreamUnix(c)
	}
	if info, ok := layerOf(v); ok {
		return info.datagrams != nil
	}
	return queueOf(v) != nil
}

// datagramNetwork reports whether v is a connection of another package whose
// local address is on a datagram network, such as a connection per UDP peer
// or flow, whose Reads then return one datagram each. A stream over UDP that
// reports a UDP address is copied as datagrams too, which keeps its bytes.
func datagramNetwork(v any) bool {
	c, ok := v.(interface{ LocalAddr() net.Addr })
	if !ok || netutil.IsNilPointer(c) {
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

// isStdConn reports whether c is a *net.TCPConn or a *net.UnixConn.
func isStdConn(c any) bool {
	switch c.(type) {
	case *net.TCPConn, *net.UnixConn:
		return true
	}
	return false
}

// canSplice reports whether io.Copy(d.base, s.base) moves the data with
// splice: from a TCP or Unix stream connection into a TCP connection, or
// from a TCP connection into a Unix stream connection.
func canSplice(d *relaySink, s *relaySource) bool {
	return netutil.Splices(d.base, s.base)
}
