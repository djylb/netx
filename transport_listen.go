package netx

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
