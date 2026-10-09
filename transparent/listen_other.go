//go:build !linux && !freebsd && !darwin

package transparent

import (
	"context"
	"net"
)

func listen(context.Context, string) (net.Listener, error) {
	return nil, ErrListenUnsupported
}
