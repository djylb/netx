//go:build darwin

package netx

import "testing"

func TestListenTCPAcceptsTransparentModeOnDarwin(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0", WithTransparent())
	if err != nil {
		t.Fatalf("ListenTCP(WithTransparent) error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	_, server := dialAccepted(t, ln)
	if server.LocalAddr().String() != ln.Addr().String() {
		t.Fatalf("server LocalAddr() = %v, want %v", server.LocalAddr(), ln.Addr())
	}
}
