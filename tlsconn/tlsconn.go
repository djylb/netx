// Package tlsconn runs TLS handshakes over existing connections with a bound
// on how long they take, and provides a Dialer that layers TLS on any dialer,
// such as a proxy dialer. Its certificate helpers generate self-signed
// certificates or issue them from a private CA (NewSelfSigned, NewCA, Issue,
// EncodePEM), trust peers by fingerprint (Fingerprint, PinSet), cache
// certificates loaded from files, kept in sync as the files change, or from
// PEM data (CertFiles), and hold certificates by ID to pick one for each
// handshake, named by the caller or ranked by server name, or loaded on
// demand (CertStore). Added certificates are named by an ID of the caller's
// choosing, else by their file's path (AddFiles) or fingerprint (CertID);
// give certificates that get renewed a stable ID, such as their domain.
//
// It is separate from the netx root package because importing crypto/tls
// adds a large amount of code to a binary even when no handshake runs.
package tlsconn

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// DefaultHandshakeTimeout bounds a handshake whose context has no deadline,
// so that a peer that never answers cannot hold it forever. It leaves room
// for a slow link and a large certificate chain, as the other handshake
// bounds of this module do.
const DefaultHandshakeTimeout = 10 * time.Second

// Client runs a TLS client handshake over raw and returns the connection with
// no deadline set.
//
// The handshake stops when ctx is done; a ctx without a deadline gets one
// DefaultHandshakeTimeout ahead. The deadline is applied both on raw and
// through the context, so it also holds when raw ignores deadlines or fails to
// set them. On failure raw is closed and the returned connection is nil.
// netx.InnermostConn unwraps the result through its NetConn method.
func Client(ctx context.Context, raw net.Conn, cfg *tls.Config) (*tls.Conn, error) {
	return handshake(ctx, raw, cfg, tls.Client)
}

// Server is Client for the server side of the handshake, whose cfg must not
// be nil.
func Server(ctx context.Context, raw net.Conn, cfg *tls.Config) (*tls.Conn, error) {
	if cfg == nil && raw != nil {
		_ = raw.Close()
		return nil, errNoServerConfig
	}
	return handshake(ctx, raw, cfg, tls.Server)
}

var errNoServerConfig = errors.New("tlsconn: Server needs a TLS config")

func handshake(ctx context.Context, raw net.Conn, cfg *tls.Config, newConn func(net.Conn, *tls.Config) *tls.Conn) (*tls.Conn, error) {
	if raw == nil {
		return nil, net.ErrClosed
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultHandshakeTimeout)
		defer cancel()
		deadline, _ = ctx.Deadline()
	}
	// A connection without deadline support, which may say so with an error
	// such as errors.ErrUnsupported, is bounded by the context instead.
	_ = raw.SetDeadline(deadline)
	tc := newConn(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		// Before a completed handshake this only closes raw.
		_ = tc.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return tc, nil
}
