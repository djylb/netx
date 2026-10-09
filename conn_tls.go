package netx

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// TLSClient runs a TLS client handshake over raw and returns the connection
// with no deadline set.
//
// The handshake stops when ctx is done or after timeout, DefaultTimeout if
// non-positive. The timeout is applied both as a deadline on raw and as a
// context deadline, so it also holds when raw ignores deadlines. On failure raw
// is closed and the returned connection is nil. RawConnOf unwraps the result
// through its NetConn method.
func TLSClient(ctx context.Context, raw net.Conn, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	if raw == nil {
		return nil, net.ErrClosed
	}
	return tlsHandshake(ctx, raw, cfg, timeout, tls.Client)
}

// TLSServer is TLSClient for the server side of the handshake.
func TLSServer(ctx context.Context, raw net.Conn, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	if raw == nil {
		return nil, net.ErrClosed
	}
	return tlsHandshake(ctx, raw, cfg, timeout, tls.Server)
}

func tlsHandshake(ctx context.Context, raw net.Conn, cfg *tls.Config, timeout time.Duration, newConn func(net.Conn, *tls.Config) *tls.Conn) (*tls.Conn, error) {
	timeout = normalizeLinkTimeout(timeout)
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
