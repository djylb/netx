//go:build !plan9

package netx

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestDescribeNetErrorOmitsErrnoNameForUnclassifiedErrno(t *testing.T) {
	// ENOBUFS is in no classifier table, so only its number is reported; its
	// system message is already part of err.
	err := &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.ENOBUFS)}
	got := DescribeNetError(err, nil)
	if want := fmt.Sprintf(" errno=%d", syscall.ENOBUFS); !strings.HasSuffix(got, want) {
		t.Fatalf("DescribeNetError() = %q, want suffix %q", got, want)
	}
	if strings.Contains(got, "errno_name=") {
		t.Fatalf("DescribeNetError() = %q, want no errno_name", got)
	}
}
