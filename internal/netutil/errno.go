//go:build !plan9

package netutil

import "errors"

func isAddrNotAvailableValue(err error) bool {
	for _, errno := range AddrNotAvailableErrnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
