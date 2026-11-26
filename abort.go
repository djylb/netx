package netx

import (
	"io"

	"github.com/djylb/netx/internal/netutil"
)

// Aborter is a connection that can end abnormally, so that its peer sees a
// cut instead of an end of data: a stream of a multiplexed connection
// resets itself, a WebSocket connection drops its transport without a
// closing handshake. Abort ends both directions at once, ends the reads
// and writes that block on the connection and releases it as Close does;
// a Close afterwards must be harmless. cause tells why, for the
// connection's own reporting, and may be nil.
//
// Abort and Relay use it, also beneath the wrappers of this package, TLS, and
// wrappers declaring OwnedLayers; a *net.TCPConn needs none, as it is reset with
// SO_LINGER 0.
type Aborter interface {
	Abort(cause error)
}

// Abort ends c abnormally, so that its peer reads an error, not an end of
// data: an Aborter, c itself or the first one beneath its wrappers, as
// reached through owned connections, is aborted with cause; otherwise a *net.TCPConn beneath
// c gets SO_LINGER 0, so that closing it sends RST instead of FIN. Then c
// is closed, unless it is an Aborter itself. A connection with neither is
// just closed, as a *net.UnixConn or a datagram connection, whose peers
// cannot tell the two apart.
func Abort(c io.Closer, cause error) {
	if c == nil || netutil.IsNilPointer(c) {
		return
	}
	if a, ok := c.(Aborter); ok {
		a.Abort(cause)
		return
	}
	abortBeneath(c, cause)
	_ = c.Close()
}

// abortBeneath aborts the Aborter beneath v, or makes the close of the
// *net.TCPConn beneath it send RST, without closing v.
func abortBeneath(v any, cause error) {
	if lr, ok := v.(*io.LimitedReader); ok && lr != nil {
		v = lr.R
	}
	netutil.AbortBeneath(v, cause)
}
