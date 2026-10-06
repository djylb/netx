//go:build windows

package netx

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestWindowsErrnoConstantsMatchSyscall(t *testing.T) {
	for _, tt := range []struct {
		name      string
		got, want syscall.Errno
	}{
		{name: "ERROR_ACCESS_DENIED", got: errorAccessDenied, want: syscall.ERROR_ACCESS_DENIED},
		{name: "ERROR_NETNAME_DELETED", got: errorNetnameDeleted, want: syscall.ERROR_NETNAME_DELETED},
		{name: "WSAEACCES", got: wsaEACCES, want: syscall.WSAEACCES},
		{name: "WSAECONNABORTED", got: wsaECONNABORTED, want: syscall.WSAECONNABORTED},
		{name: "WSAECONNRESET", got: wsaECONNRESET, want: syscall.WSAECONNRESET},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestWindowsWinsockErrnosAreClassified(t *testing.T) {
	tests := []struct {
		errno syscall.Errno
		kind  string
		name  string
	}{
		{errno: 10054, kind: "rst", name: "ECONNRESET"},                  // WSAECONNRESET
		{errno: 64, kind: "rst", name: "ECONNRESET"},                     // ERROR_NETNAME_DELETED
		{errno: 10053, kind: "aborted", name: "ECONNABORTED"},            // WSAECONNABORTED
		{errno: 10058, kind: "broken_pipe", name: "EPIPE"},               // WSAESHUTDOWN
		{errno: 10061, kind: "refused", name: "ECONNREFUSED"},            // WSAECONNREFUSED
		{errno: 10065, kind: "host_unreachable", name: "EHOSTUNREACH"},   // WSAEHOSTUNREACH
		{errno: 10051, kind: "network_unreachable", name: "ENETUNREACH"}, // WSAENETUNREACH
		{errno: 10013, kind: "permission_denied", name: "EACCES"},        // WSAEACCES
		{errno: 5, kind: "permission_denied", name: "EACCES"},            // ERROR_ACCESS_DENIED
		{errno: 10060, kind: "timeout", name: "ETIMEDOUT"},               // WSAETIMEDOUT
		// Invented syscall.E* values built by portable code keep working.
		{errno: syscall.ECONNRESET, kind: "rst", name: "ECONNRESET"},
		{errno: syscall.ECONNREFUSED, kind: "refused", name: "ECONNREFUSED"},
		{errno: syscall.EPERM, kind: "permission_denied", name: "EPERM"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%d", tt.kind, tt.errno), func(t *testing.T) {
			err := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("wsarecv", tt.errno)}
			assertNetErrorKind(t, err, tt.kind)
			got := DescribeNetError(err, nil)
			if !strings.HasSuffix(got, " errno_name="+tt.name) {
				t.Fatalf("DescribeNetError() = %q, want errno_name=%s", got, tt.name)
			}
			if wantTimeout := tt.kind == "timeout"; strings.Contains(got, "timeout=true") != wantTimeout {
				t.Fatalf("DescribeNetError() = %q, want timeout=%t", got, wantTimeout)
			}
		})
	}
}
