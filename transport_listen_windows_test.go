//go:build windows

package netx

import "testing"

func TestListenTCPRejectsTransparentModeOnWindows(t *testing.T) {
	if _, err := ListenTCP("127.0.0.1:0", WithTransparent()); err == nil {
		t.Fatal("expected transparent listen to fail on Windows")
	}
}

func TestListenTCPAllowsRegularModeOnWindows(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected regular listen to succeed, got error: %v", err)
	}
	_ = ln.Close()
}
