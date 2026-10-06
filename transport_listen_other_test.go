//go:build !linux && !freebsd && !darwin && !windows

package netx

import (
	"errors"
	"testing"
)

func TestListenTCPRejectsTransparentMode(t *testing.T) {
	if _, err := ListenTCP("127.0.0.1:0", WithTransparent()); !errors.Is(err, ErrTransparentListenUnsupported) {
		t.Fatalf("ListenTCP(WithTransparent) error = %v, want %v", err, ErrTransparentListenUnsupported)
	}
}
