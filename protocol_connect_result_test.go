package netx

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestDialConnectResultClassifiesCommonFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ConnectResultStatus
	}{
		{name: "nil", err: nil, want: ConnectResultOK},
		{name: "timeout", err: fakeNetError{msg: "dial timeout", timeout: true}, want: ConnectResultNetworkUnreachable},
		{name: "dns", err: &net.DNSError{Err: "no such host", Name: "missing.example"}, want: ConnectResultHostUnreachable},
		{name: "connection refused syscall", err: syscall.ECONNREFUSED, want: ConnectResultConnectionRefused},
		{name: "host unreachable syscall", err: syscall.EHOSTUNREACH, want: ConnectResultHostUnreachable},
		{name: "network unreachable syscall", err: syscall.ENETUNREACH, want: ConnectResultNetworkUnreachable},
		{name: "not allowed syscall", err: syscall.EACCES, want: ConnectResultNotAllowed},
		{name: "connection refused text", err: errors.New("connectex: No connection could be made because the target machine actively refused it"), want: ConnectResultConnectionRefused},
		{name: "permission denied text", err: errors.New("permission denied"), want: ConnectResultNotAllowed},
		{name: "unknown", err: errors.New("unexpected failure"), want: ConnectResultServerFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DialConnectResult(tt.err); got != tt.want {
				t.Fatalf("DialConnectResult(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
