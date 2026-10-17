//go:build linux || freebsd

package transparent

import (
	"errors"
	"syscall"
)

type sockopt struct {
	level int
	name  int
}

// setOptions enables boolean socket options, skipping those the socket's
// family does not have, and returns the first other failure. It fails when
// none could be set, as in a sandbox without them, rather than leaving the
// socket without what the caller needs.
func setOptions(fd int, opts []sockopt) error {
	var firstErr, skipped error
	set := false
	for _, opt := range opts {
		switch err := syscall.SetsockoptInt(fd, opt.level, opt.name, 1); {
		case err == nil:
			set = true
		case isIgnorableSockopt(err):
			if skipped == nil {
				skipped = err
			}
		case firstErr == nil:
			firstErr = err
		}
	}
	if firstErr == nil && !set {
		return skipped
	}
	return firstErr
}

func isIgnorableSockopt(err error) bool {
	return errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EAFNOSUPPORT)
}

// controlFD runs fn on the descriptor of c and returns the first failure.
func controlFD(c syscall.RawConn, fn func(fd int) error) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = fn(int(fd))
	}); err != nil {
		return err
	}
	return sockErr
}
