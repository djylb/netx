package netx

import (
	"context"
	"errors"
	"net"
)

// ErrTransparentListenUnsupported is returned when transparent listening is unavailable.
var ErrTransparentListenUnsupported = errors.New("transparent tcp listener is not supported on this platform")

type listenOptions struct {
	transparent bool
}

// ListenOption configures ListenTCP.
type ListenOption func(*listenOptions)

// WithTransparent enables transparent TCP listener socket options when supported.
func WithTransparent() ListenOption {
	return func(o *listenOptions) {
		o.transparent = true
	}
}

func newListenOptions(opts []ListenOption) listenOptions {
	var cfg listenOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// ListenTCP listens on a TCP address.
func ListenTCP(address string, opts ...ListenOption) (net.Listener, error) {
	return ListenTCPContext(context.Background(), address, opts...)
}

// ListenTCPContext listens on a TCP address using ctx for listener creation.
func ListenTCPContext(ctx context.Context, address string, opts ...ListenOption) (net.Listener, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return listenTCPContext(ctx, address, opts...)
}
