package netx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

type netErrorClassifier struct {
	name string
	fn   func(error) bool
}

var netErrorClassifiers = []netErrorClassifier{
	{"IsConnReset", IsConnReset},
	{"IsConnAborted", IsConnAborted},
	{"IsBrokenPipe", IsBrokenPipe},
	{"IsConnRefused", IsConnRefused},
	{"IsHostUnreachable", IsHostUnreachable},
	{"IsNetworkUnreachable", IsNetworkUnreachable},
	{"IsPermissionDenied", IsPermissionDenied},
	{"IsTimeout", IsTimeout},
}

// classifierForKind maps a NetErrorKind result to the classifier that produces it.
var classifierForKind = map[string]string{
	"rst":                 "IsConnReset",
	"aborted":             "IsConnAborted",
	"broken_pipe":         "IsBrokenPipe",
	"refused":             "IsConnRefused",
	"host_unreachable":    "IsHostUnreachable",
	"network_unreachable": "IsNetworkUnreachable",
	"permission_denied":   "IsPermissionDenied",
	"timeout":             "IsTimeout",
}

// assertNetErrorKind checks NetErrorKind and that exactly the matching classifier reports err.
func assertNetErrorKind(t *testing.T, err error, want string) {
	t.Helper()
	if got := NetErrorKind(err); got != want {
		t.Fatalf("NetErrorKind(%v) = %q, want %q", err, got, want)
	}
	for _, c := range netErrorClassifiers {
		if got, wantMatch := c.fn(err), classifierForKind[want] == c.name; got != wantMatch {
			t.Fatalf("%s(%v) = %t, want %t", c.name, err, got, wantMatch)
		}
	}
}

// localizedError hides the English errno text, as Windows does on a non-English system.
type localizedError struct {
	err error
}

func (e localizedError) Error() string { return "本地化的错误消息" }
func (e localizedError) Unwrap() error { return e.err }

func TestNetErrorClassifiersMatchText(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{msg: "read tcp 127.0.0.1:1->127.0.0.1:2: read: connection reset by peer", want: "rst"},
		{msg: "wsarecv: An existing connection was forcibly closed by the remote host.", want: "rst"},
		{msg: "wsarecv: The specified network name is no longer available.", want: "rst"},
		{msg: "accept: software caused connection abort", want: "aborted"},
		{msg: "wsasend: An established connection was aborted by the software in your host machine.", want: "aborted"},
		{msg: "write tcp 127.0.0.1:1->127.0.0.1:2: write: broken pipe", want: "broken_pipe"},
		{msg: "wsasend: A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call.", want: "broken_pipe"},
		{msg: "dial tcp 127.0.0.1:1: connect: connection refused", want: "refused"},
		{msg: "dial tcp 127.0.0.1:1: connectex: No connection could be made because the target machine actively refused it.", want: "refused"},
		{msg: "dial tcp 192.0.2.1:80: connect: no route to host", want: "host_unreachable"},
		{msg: "dial tcp 192.0.2.1:80: connect: host is unreachable", want: "host_unreachable"},
		{msg: "dial tcp 192.0.2.1:80: connectex: A socket operation was attempted to an unreachable host.", want: "host_unreachable"},
		{msg: "dial tcp 192.0.2.1:80: connect: network is unreachable", want: "network_unreachable"},
		{msg: "dial tcp 192.0.2.1:80: connectex: A socket operation was attempted to an unreachable network.", want: "network_unreachable"},
		{msg: "dial tcp 192.0.2.1:80: connect: permission denied", want: "permission_denied"},
		{msg: "dial tcp 192.0.2.1:80: connect: operation not permitted", want: "permission_denied"},
		{msg: "dial tcp 192.0.2.1:80: connectex: An attempt was made to access a socket in a way forbidden by its access permissions.", want: "permission_denied"},
		{msg: "Access is denied.", want: "permission_denied"},
		{msg: "dial tcp 192.0.2.1:80: i/o timeout", want: "timeout"},
		{msg: "dial tcp 192.0.2.1:80: connect: connection timed out", want: "timeout"},
		{msg: "dial tcp 192.0.2.1:80: connectex: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.", want: "timeout"},
		{msg: "dial tcp 192.0.2.1:80: connect: operation timed out", want: "timeout"},
		{msg: "unexpected failure", want: "other"},
		{msg: "parse error: datetime outside the allowed range", want: "other"},
		{msg: "runtime output was truncated", want: "other"},
	}
	for _, tt := range tests {
		t.Run(tt.want+"/"+tt.msg, func(t *testing.T) {
			assertNetErrorKind(t, errors.New(tt.msg), tt.want)
		})
	}
}

func TestNetErrorClassifiersMatchErrnoTables(t *testing.T) {
	tables := []struct {
		kind   string
		name   string
		errnos []error
	}{
		{kind: "rst", name: "ECONNRESET", errnos: connResetErrnos},
		{kind: "aborted", name: "ECONNABORTED", errnos: connAbortedErrnos},
		{kind: "broken_pipe", name: "EPIPE", errnos: brokenPipeErrnos},
		{kind: "refused", name: "ECONNREFUSED", errnos: connRefusedErrnos},
		{kind: "host_unreachable", name: "EHOSTUNREACH", errnos: hostUnreachErrnos},
		{kind: "network_unreachable", name: "ENETUNREACH", errnos: netUnreachErrnos},
		{kind: "permission_denied", name: "EACCES", errnos: accessErrnos},
		{kind: "permission_denied", name: "EPERM", errnos: permErrnos},
		{kind: "timeout", name: "ETIMEDOUT", errnos: timedOutErrnos},
	}
	for _, table := range tables {
		for _, errno := range table.errnos {
			t.Run(fmt.Sprintf("%s/%v", table.name, errno), func(t *testing.T) {
				err := &net.OpError{Op: "dial", Net: "tcp", Err: localizedError{err: errno}}
				assertNetErrorKind(t, err, table.kind)
				if runtime.GOOS == "plan9" {
					return // plan9 errors carry no errno
				}
				if got := DescribeNetError(err, nil); !strings.HasSuffix(got, " errno_name="+table.name) {
					t.Fatalf("DescribeNetError() = %q, want errno_name=%s", got, table.name)
				}
			})
		}
	}
}

func TestNetErrorKindGenericErrors(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{err: nil, want: "none"},
		{err: fakeNetError{msg: "deadline", timeout: true}, want: "timeout"},
		{err: fmt.Errorf("read frame: %w", io.ErrUnexpectedEOF), want: "unexpected_eof"},
		{err: io.EOF, want: "eof"},
		{err: &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}, want: "closed"},
		{err: &net.DNSError{Err: "no such host", Name: "missing.example"}, want: "other"},
	}
	for _, tt := range tests {
		if got := NetErrorKind(tt.err); got != tt.want {
			t.Fatalf("NetErrorKind(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
	for _, c := range netErrorClassifiers {
		if c.fn(nil) {
			t.Fatalf("%s(nil) = true, want false", c.name)
		}
	}
	if got := DescribeNetError(nil, nil); got != "kind=none" {
		t.Fatalf("DescribeNetError(nil) = %q, want kind=none", got)
	}
}

func TestDescribeNetErrorIncludesConnAndTimeout(t *testing.T) {
	c, peer := net.Pipe()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close pipe connection: %v", err)
		}
	})
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Errorf("close pipe peer: %v", err)
		}
	})
	err := &net.OpError{Op: "read", Net: "tcp", Err: fakeNetError{msg: "i/o timeout", timeout: true}}
	got := DescribeNetError(err, c)
	for _, want := range []string{"kind=timeout", "timeout=true", "local=pipe", "remote=pipe", "op=read", "net=tcp"} {
		if !strings.Contains(got, want) {
			t.Fatalf("DescribeNetError() = %q, want %s", got, want)
		}
	}
}

func TestNetErrorClassifiersOnLoopback(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()

		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err == nil {
			_ = c.Close()
			t.Skipf("port %s was reused before dialing", addr)
		}
		assertNetErrorKind(t, err, "refused")
		switch runtime.GOOS {
		case "plan9", "js", "wasip1":
			return // plan9 errors carry no errno; js and wasip1 flatten dial errors to text
		}
		if got := DescribeNetError(err, nil); !strings.Contains(got, "errno_name=ECONNREFUSED") {
			t.Fatalf("DescribeNetError() = %q, want errno_name=ECONNREFUSED", got)
		}
	})

	t.Run("reset", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() {
			if err := ln.Close(); err != nil {
				t.Errorf("close listener: %v", err)
			}
		})
		accepted := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}()
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("close client: %v", err)
			}
		})
		server, ok := <-accepted
		if !ok {
			t.Fatal("accept failed")
		}
		// A zero linger turns Close into an abortive close that sends RST.
		if err := server.(*net.TCPConn).SetLinger(0); err != nil {
			_ = server.Close()
			t.Skipf("SetLinger(0): %v", err) // plan9 has no SO_LINGER
		}
		_ = server.Close()

		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = client.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("Read() error = nil, want connection reset")
		}
		assertNetErrorKind(t, err, "rst")
		if got := DescribeNetError(err, client); !strings.Contains(got, "errno_name=ECONNRESET") {
			t.Fatalf("DescribeNetError() = %q, want errno_name=ECONNRESET", got)
		}
	})
}
