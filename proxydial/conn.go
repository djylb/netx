package proxydial

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/djylb/netx"
)

// handshake runs fn on c under ctx with netx.DoWithContext and closes c when
// it fails.
func handshake(ctx context.Context, c net.Conn, fn func() error) error {
	err := netx.DoWithContext(ctx, c, fn)
	if err != nil {
		closeBeneathTLS(ctx, c, err)
		_ = c.Close()
	}
	return err
}

// closeBeneathTLS closes the connection beneath c, if c is a *tls.Conn, when
// err is a timeout or ctx has ended. Such a *tls.Conn may have failed in the
// middle of a write, and its Close would still send close_notify under a
// record number that the proxy cannot authenticate; closing the connection
// beneath it makes its Close send nothing.
func closeBeneathTLS(ctx context.Context, c net.Conn, err error) {
	if ctx.Err() == nil && !netx.IsTimeout(err) {
		return
	}
	if tc, ok := c.(*tls.Conn); ok {
		_ = tc.NetConn().Close()
	}
}

// tlsDialer dials with forward and runs a TLS client handshake bounded by
// ctx alone, as the rest of a proxy dial is.
type tlsDialer struct {
	config  *tls.Config
	forward netx.ContextDialer
}

func (d *tlsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := forwardOf(d.forward).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, d.config)
	if err := handshake(ctx, c, func() error { return tc.HandshakeContext(ctx) }); err != nil {
		return nil, err
	}
	return tc, nil
}

// tlsConfigFor returns cfg for a TLS proxy at host: a config verifying host
// when cfg is nil, cfg itself when it names a server, and otherwise a clone
// of cfg with ServerName set to host.
func tlsConfigFor(cfg *tls.Config, host string) *tls.Config {
	switch {
	case cfg == nil:
		return &tls.Config{ServerName: host}
	case cfg.ServerName != "":
		return cfg
	}
	cfg = cfg.Clone()
	cfg.ServerName = host
	return cfg
}
