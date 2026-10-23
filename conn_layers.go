package netx

import (
	"io"
	"net"
	"reflect"
	"slices"

	"github.com/djylb/netx/internal/netutil"
)

// layer is implemented by the connections of this package, each in its own
// file, to describe themselves to InnermostConn, ConnAs and Relay.
type layer interface {
	netxLayer() layerInfo
}

// layerInfo describes a connection of this package; see layer.
type layerInfo struct {
	// self is the connection itself, which tells it apart from a type of
	// another package that embeds it: that type has netxLayer too, but may
	// read, write and unwrap otherwise.
	self any
	// conn is the connection beneath, which unwrapping follows first.
	conn net.Conn
	// rwc is what Read and Write go to when that is not conn, as in
	// WrapConn.
	rwc  io.ReadWriteCloser
	kind layerKind
	// datagrams, when not nil, hands over the datagrams that each Read
	// returns one of.
	datagrams datagramSource
}

// layerKind tells how a connection of this package passes data on.
type layerKind uint8

const (
	// layerWraps: InnermostConn and ConnAs follow conn and rwc rather than
	// a NetConn method.
	layerWraps layerKind = 1 << iota
	// layerReads: each Read reads what is beneath once, so that datagrams
	// keep their bounds.
	layerReads
	// layerPasses: reads and writes go to conn unchanged.
	layerPasses
	// layerPrefix: as layerPasses once the prefix of a PrefixConn is read.
	layerPrefix
	// layerRefresh: as layerPasses, where a TimeoutConn's idle deadline is
	// refreshed as its own Read and Write do.
	layerRefresh

	// layerPassesThrough are the layers that a Relay reads and writes
	// beneath; it refreshes the idle deadlines of the TimeoutConns it skips.
	layerPassesThrough = layerPasses | layerPrefix | layerRefresh
)

// layerOf returns the description of v if it is a connection of this
// package.
func layerOf(v any) (layerInfo, bool) {
	l, ok := v.(layer)
	if !ok {
		return layerInfo{}, false
	}
	info := l.netxLayer()
	return info, info.self == v
}

// reader returns what the connection's Reads read.
func (info *layerInfo) reader() io.Reader {
	if info.rwc != nil {
		return info.rwc
	}
	if info.conn != nil {
		return info.conn
	}
	return nil
}

// InnermostConn returns the innermost connection beneath v: it follows the
// wrappers of this package and the NetConn() net.Conn methods of others,
// such as *tls.Conn's, which return the connection one layer down. It
// returns v itself when v wraps nothing, and nil for a nil connection, also
// a nil pointer such as a nil *net.TCPConn, and for a value that is not a
// connection. The connection is borrowed: v's owner still closes it.
func InnermostConn(v any) net.Conn {
	var seen [8]any
	return innermost(v, 0, seen[:0])
}

// ConnAs returns the first connection of type T in the chain beneath v, v
// included, as errors.As does for errors: through the wrappers of this
// package and NetConn methods, such as to find the *tls.Conn or
// *TimeoutConn beneath other wrappers.
func ConnAs[T any](v any) (T, bool) {
	var seen [8]any
	return connAs[T](v, 0, seen[:0])
}

// maxUnwrapDepth bounds NetConn chains so cyclic wrappers cannot loop forever.
const maxUnwrapDepth = 16

// wrapped returns what a wrapper of this package wraps, one layer down and
// in the order unwrapping looks at it, without its NetConn method, so that
// a cycle through the wrappers is seen and both sides of a WrapConn are
// looked at. A nil wrapper wraps nothing.
func wrapped(v any) (first, second any, ok bool) {
	info, ok := layerOf(v)
	if !ok || info.kind&layerWraps == 0 {
		return nil, nil, false
	}
	if info.conn != nil {
		first = info.conn
	}
	if info.rwc != nil {
		second = info.rwc
	}
	return first, second, true
}

func connAs[T any](v any, depth int, seen []any) (T, bool) {
	var zero T
	if v == nil || netutil.IsNilPointer(v) {
		return zero, false
	}
	if t, ok := v.(T); ok {
		return t, true
	}
	if first, second, ok := wrapped(v); ok {
		if slices.Contains(seen, v) {
			return zero, false
		}
		seen = append(seen, v)
		for _, inner := range [...]any{first, second} {
			if t, ok := connAs[T](inner, depth, seen); ok {
				return t, true
			}
		}
		return zero, false
	}
	// Only looked at, not owned.
	//noinspection GoResourceLeak
	next, ok := nextConn(v)
	if !ok || next == nil || depth >= maxUnwrapDepth {
		return zero, false
	}
	if conn, isConn := v.(net.Conn); isConn && sameNetConn(next, conn) {
		return zero, false
	}
	return connAs[T](next, depth+1, seen)
}

// innermost unwraps v. depth counts the NetConn calls of other packages'
// wrappers, which may return a new wrapper each time, and seen holds this
// package's wrappers on the way, whose fields a caller may have pointed back
// at them; either way a cycle stops.
func innermost(v any, depth int, seen []any) net.Conn {
	if v == nil {
		return nil
	}
	if first, second, ok := wrapped(v); ok {
		if slices.Contains(seen, v) {
			c, _ := v.(net.Conn)
			return c
		}
		seen = append(seen, v)
		for _, inner := range [...]any{first, second} {
			if raw := innermost(inner, depth, seen); raw != nil {
				return raw
			}
		}
		return nil
	}
	// Unwrapping only borrows connections; their owner remains responsible for closing them.
	//noinspection GoResourceLeak
	if raw, ok := nextConn(v); ok {
		if raw == nil || netutil.IsNilPointer(raw) {
			return nil
		}
		if conn, ok := v.(net.Conn); ok && sameNetConn(raw, conn) {
			return raw
		}
		if depth >= maxUnwrapDepth {
			return raw
		}
		if unwrapped := innermost(raw, depth+1, seen); unwrapped != nil {
			return unwrapped
		}
		return raw
	}
	if conn, ok := v.(net.Conn); ok && !netutil.IsNilPointer(conn) {
		return conn
	}
	return nil
}

// nextConn returns the connection that v wraps, if v exposes one.
// The returned connection is borrowed; inspecting it does not transfer ownership.
func nextConn(v any) (net.Conn, bool) {
	getter, ok := v.(interface{ NetConn() net.Conn })
	if !ok {
		return nil, false
	}
	// *tls.Conn.NetConn does not accept a nil receiver.
	if netutil.IsNilPointer(getter) {
		return nil, true
	}
	return getter.NetConn(), true
}

func sameNetConn(a, b net.Conn) bool {
	if a == nil || b == nil {
		return false
	}
	av := reflect.ValueOf(a)
	bv := reflect.ValueOf(b)
	// Value.Comparable also looks at the values in interface fields, which
	// Type.Comparable does not and on which Equal would panic.
	if av.Type() != bv.Type() || !av.Comparable() || !bv.Comparable() {
		return false
	}
	return av.Equal(bv)
}
