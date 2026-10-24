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
// For certificates that users upload, it parses chains and private keys and
// checks that they match (ParseKeyPair), verifies chains with typed errors
// (VerifyChain), tells which names a certificate covers by the rules of
// RFC 9525 (Covers, CertNames, VerifyDomain), has a user prove that they hold
// a certificate's private key (Challenger, SignPossession) and describes
// certificates for display (Summarize).
//
// It is separate from the netx root package because importing crypto/tls
// adds a large amount of code to a binary even when no handshake runs.
package tlsconn

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
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
// set them. A handshake that ctx ends, or whose deadline passes, returns
// ctx's error, such as context.DeadlineExceeded. On failure raw is closed
// and the returned connection is nil. The result's NetConn method returns
// raw, which unwrappers such as netx.InnermostConn follow.
func Client(ctx context.Context, raw net.Conn, cfg *tls.Config) (*tls.Conn, error) {
	return handshake(ctx, raw, cfg, tls.Client, DefaultHandshakeTimeout)
}

// Server is Client for the server side of the handshake, whose cfg must not
// be nil.
func Server(ctx context.Context, raw net.Conn, cfg *tls.Config) (*tls.Conn, error) {
	if cfg == nil && raw != nil {
		_ = raw.Close()
		return nil, errNoServerConfig
	}
	return handshake(ctx, raw, cfg, tls.Server, DefaultHandshakeTimeout)
}

var errNoServerConfig = errors.New("tlsconn: Server needs a TLS config")

// handshake runs the handshake of newConn(raw, cfg) under ctx, which gets a
// deadline limit ahead when it has none and limit is positive.
func handshake(ctx context.Context, raw net.Conn, cfg *tls.Config, newConn func(net.Conn, *tls.Config) *tls.Conn, limit time.Duration) (*tls.Conn, error) {
	if raw == nil {
		return nil, net.ErrClosed
	}
	deadline, ok := ctx.Deadline()
	if !ok && limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
		deadline, ok = ctx.Deadline()
	}
	if ok {
		// A connection without deadline support, which may say so with an
		// error such as errors.ErrUnsupported, is bounded by the context
		// instead.
		_ = raw.SetDeadline(deadline)
	}
	tc := newConn(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		// Before a completed handshake this only closes raw.
		_ = tc.Close()
		// raw's deadline can fire just before ctx reports that it ended.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if ok && errors.Is(err, os.ErrDeadlineExceeded) && !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	if ok {
		_ = raw.SetDeadline(time.Time{})
	}
	return tc, nil
}
