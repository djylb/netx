package tlsconn

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/djylb/netx/internal/netutil"
)

// ContextDialer dials connections with a DialContext(ctx, network, address)
// (net.Conn, error) method. *net.Dialer implements it. It is the same type as
// netx.ContextDialer.
type ContextDialer = netutil.ContextDialer

// Dialer dials connections with Forward and runs a TLS client handshake on
// them. Unlike tls.Dialer, Forward can be any ContextDialer, such as a proxy
// dialer, so TLS can be layered on a proxied connection, or a proxy dialer
// can use a Dialer as its Forward to reach the proxy over TLS.
type Dialer struct {
	// Config is the TLS configuration; nil means the zero configuration.
	// Without a ServerName, the host of the dialed address is used, as
	// tls.Dialer does, or the whole address when it has no port.
	Config *tls.Config
	// HandshakeTimeout, if positive, also bounds the handshake, after the
	// dial and within the context's deadline. If zero, a handshake whose
	// context has no deadline is bounded by DefaultHandshakeTimeout, as with
	// Client. If negative, the context alone bounds it, as for a dialer
	// whose callers bound a whole dial through a proxy with the context.
	HandshakeTimeout time.Duration
	// Forward dials the underlying connection; nil means a zero net.Dialer.
	Forward ContextDialer
}

// Dial is DialContext with a background context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext dials address and returns the *tls.Conn after a successful
// handshake. ctx bounds both the dial and the handshake.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	cfg := d.Config
	if cfg == nil || cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address // no port, as for a Forward dialer of Unix sockets
		}
		if cfg == nil {
			cfg = &tls.Config{}
		} else {
			cfg = cfg.Clone()
		}
		cfg.ServerName = host
	}
	var forward ContextDialer = &net.Dialer{}
	if d.Forward != nil {
		forward = d.Forward
	}
	raw, err := forward.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	limit := DefaultHandshakeTimeout
	switch {
	case d.HandshakeTimeout > 0:
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.HandshakeTimeout)
		defer cancel()
	case d.HandshakeTimeout < 0:
		limit = 0
	}
	tc, err := handshake(ctx, raw, cfg, tls.Client, limit)
	if err != nil {
		return nil, err
	}
	return tc, nil
}
