// Package tlsconn runs TLS handshakes over existing connections with a bound
// on how long they take, and provides a Dialer that layers TLS on any dialer,
// such as a proxy dialer. Its certificate helpers generate self-signed
// certificates (NewSelfSigned, EncodePEM), trust peers by fingerprint
// (Fingerprint, PinSet) and cache certificates loaded from files or PEM data
// (CertCache).
//
// It is separate from the netx root package because importing crypto/tls
// adds about 800 KB to a binary even when no handshake runs.
package tlsconn

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// DefaultTimeout bounds a handshake whose timeout is not positive.
const DefaultTimeout = 5 * time.Second

// Client runs a TLS client handshake over raw and returns the connection with
// no deadline set.
//
// The handshake stops when ctx is done or after timeout, DefaultTimeout if
// non-positive. The timeout is applied both as a deadline on raw and as a
// context deadline, so it also holds when raw ignores deadlines. On failure raw
// is closed and the returned connection is nil. netx.RawConnOf unwraps the
// result through its NetConn method.
func Client(ctx context.Context, raw net.Conn, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	return handshake(ctx, raw, cfg, timeout, tls.Client)
}

// Server is Client for the server side of the handshake.
func Server(ctx context.Context, raw net.Conn, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	return handshake(ctx, raw, cfg, timeout, tls.Server)
}

func handshake(ctx context.Context, raw net.Conn, cfg *tls.Config, timeout time.Duration, newConn func(net.Conn, *tls.Config) *tls.Conn) (*tls.Conn, error) {
	if raw == nil {
		return nil, net.ErrClosed
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = raw.Close()
		return nil, err
	}
	tc := newConn(raw, cfg)
	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := tc.HandshakeContext(hsCtx)
	if err == nil {
		err = raw.SetDeadline(time.Time{})
	}
	if err != nil {
		// Before a completed handshake this only closes raw.
		_ = tc.Close()
		return nil, err
	}
	return tc, nil
}
