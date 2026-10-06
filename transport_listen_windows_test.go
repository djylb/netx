//go:build windows

package netx

import (
	"errors"
	"testing"
)

func TestListenTCPRejectsTransparentModeOnWindows(t *testing.T) {
	if _, err := ListenTCP("127.0.0.1:0", WithTransparent()); !errors.Is(err, ErrTransparentListenUnsupported) {
		t.Fatalf("ListenTCP(WithTransparent) error = %v, want %v", err, ErrTransparentListenUnsupported)
	}
}

func TestListenTCPAllowsRegularModeOnWindows(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected regular listen to succeed, got error: %v", err)
	}
	_ = ln.Close()
}
