package netx

import (
	"context"
	"net"

	"github.com/djylb/netx/internal/netutil"
)

// DoWithContext runs fn, which does I/O on c, such as reading a request,
// bounded by ctx: ctx's deadline becomes c's deadline, and once ctx is done
// c's deadline is set in the past to interrupt the I/O. For a cancelable ctx,
// a connection that rejects a deadline returns an error before fn starts. When fn returns, c's deadline is cleared. It returns
// ctx's error when ctx ended fn, also context.DeadlineExceeded when c's
// deadline, which is ctx's, expired just before ctx reported it, and
// otherwise fn's error.
//
// As an I/O helper it leaves c open on failure, as Peek does, since a
// failure need not end the connection, such as a sniffing read that times
// out before a client that waits for the server to speak first. For an
// exchange that c is no use without, such as a protocol handshake, use
// DoHandshake, which closes c on failure as the handshakes of this module
// do.
func DoWithContext(ctx context.Context, c net.Conn, fn func() error) error {
	return netutil.DoWithContext(ctx, c, fn, false)
}

// DoHandshake runs fn, an exchange on c that c is no use without, such as a
// proxy handshake, bounded by ctx as with DoWithContext, and closes c when
// it fails: c belongs to the caller after a success and is closed after a
// failure, the rule that every handshake of this module follows. When ctx
// ended the exchange or its I/O timed out, a write may have been cut short,
// so the connection beneath a TLS c is closed first, as by CloseBeneathTLS,
// and closing c sends no close_notify that the peer cannot authenticate.
func DoHandshake(ctx context.Context, c net.Conn, fn func() error) error {
	err := netutil.DoWithContext(ctx, c, fn, true)
	if err != nil {
		if ctx.Err() != nil || IsTimeout(err) {
			CloseBeneathTLS(c)
		}
		_ = c.Close()
	}
	return err
}

// CloseBeneathTLS closes the connection beneath c when c is a TLS
// connection. Call it before closing c after an exchange over c timed out or
// was canceled, as DoHandshake does: a TLS connection whose write was cut
// short would still send close_notify on Close, under a record number that
// the peer cannot authenticate, so the peer would see a TLS failure instead
// of the end of the connection. With the connection beneath closed, c's
// Close sends nothing.
//
// A TLS connection is one with the NetConn and HandshakeContext methods of
// *tls.Conn, so that this package does not link crypto/tls and the
// connections of other TLS implementations can declare their transport with
// NetxOwned. Only the transport owned by c is closed.
func CloseBeneathTLS(c net.Conn) {
	if tc, ok := c.(interface {
		NetConn() net.Conn
		HandshakeContext(ctx context.Context) error
	}); ok && !netutil.IsNilPointer(tc) {
		if raw := tc.NetConn(); raw != nil && !netutil.IsNilPointer(raw) && !netutil.Same(raw, c) && sameWrappedParent(c, raw) {
			_ = raw.Close()
		}
	}
}
