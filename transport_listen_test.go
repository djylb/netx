package netx

import "testing"

func TestListenTCPContextAllowsNilContext(t *testing.T) {
	ln, err := ListenTCPContext(nil, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCPContext(nil) error = %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
