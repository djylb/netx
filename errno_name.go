//go:build !plan9

package netx

import (
	"errors"
	"math/bits"
	"syscall"
)

// errnoOf returns the errno in err's chain, 0 for none, and its POSIX name
// for the errnos that the classifiers know.
func errnoOf(err error) (int, string) {
	errno, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return 0, ""
	}
	return int(errno), errnoName(errno)
}

// errnoName maps the platform errnos that the classifiers know to their
// POSIX names (WSAECONNRESET becomes ECONNRESET, for example) and returns ""
// for other errnos.
func errnoName(errno syscall.Errno) string {
	set := errnoSetOf(errno)
	if set == 0 {
		return ""
	}
	return errnoNames[bits.TrailingZeros16(uint16(set))]
}

// errnoValueSet returns the errnos of the table that err is, if it is an
// errno. It looks at err alone, not at what it wraps: errnosOf walks the
// chain itself, so that, as errors.Is does, every errno of a joined chain
// counts, where errors.As would find only the first.
//
//goland:noinspection GoTypeAssertionOnErrors
func errnoValueSet(err error) (errnoSet, bool) {
	errno, ok := err.(syscall.Errno)
	if !ok {
		return 0, false
	}
	return errnoSetOf(errno), true
}

// errnoSetOf returns the errnos of the table that errno is.
func errnoSetOf(errno syscall.Errno) errnoSet {
	var set errnoSet
	for id, targets := range platformErrnos {
		for _, target := range targets {
			if uintptr(target) == uintptr(errno) {
				set |= 1 << id
				break
			}
		}
	}
	return set
}
