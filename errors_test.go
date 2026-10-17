package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
	{"IsAddrInUse", IsAddrInUse},
	{"IsAddrNotAvailable", IsAddrNotAvailable},
	{"IsMessageTooLarge", IsMessageTooLarge},
	{"IsDNSError", IsDNSError},
	{"IsCanceled", IsCanceled},
	{"IsTimeout", IsTimeout},
}

// classifierForKind maps a NetErrorKind result to the classifier that produces it.
var classifierForKind = map[ErrorKind]string{
	"conn_reset":          "IsConnReset",
	"conn_aborted":        "IsConnAborted",
	"broken_pipe":         "IsBrokenPipe",
	"conn_refused":        "IsConnRefused",
	"host_unreachable":    "IsHostUnreachable",
	"network_unreachable": "IsNetworkUnreachable",
	"permission_denied":   "IsPermissionDenied",
	"addr_in_use":         "IsAddrInUse",
	"addr_not_available":  "IsAddrNotAvailable",
	"message_too_large":   "IsMessageTooLarge",
	"dns":                 "IsDNSError",
	"canceled":            "IsCanceled",
	"timeout":             "IsTimeout",
}

// assertNetErrorKind checks NetErrorKind and that exactly the matching classifier reports err.
func assertNetErrorKind(t *testing.T, err error, want ErrorKind) {
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
		want ErrorKind
	}{
		{msg: "read tcp 127.0.0.1:1->127.0.0.1:2: read: connection reset by peer", want: "conn_reset"},
		{msg: "listen tcp :80: bind: address already in use", want: "addr_in_use"},
		{msg: "Only one usage of each socket address is normally permitted.", want: "addr_in_use"},
		{msg: "bind: cannot assign requested address", want: "addr_not_available"},
		{msg: "write udp: sendto: message too long", want: "message_too_large"},
		{msg: "wsarecv: An existing connection was forcibly closed by the remote host.", want: "conn_reset"},
		{msg: "wsarecv: The specified network name is no longer available.", want: "conn_reset"},
		{msg: "accept: software caused connection abort", want: "conn_aborted"},
		{msg: "wsasend: An established connection was aborted by the software in your host machine.", want: "conn_aborted"},
		{msg: "write tcp 127.0.0.1:1->127.0.0.1:2: write: broken pipe", want: "broken_pipe"},
		{msg: "wsasend: A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call.", want: "broken_pipe"},
		{msg: "dial tcp 127.0.0.1:1: connect: connection refused", want: "conn_refused"},
		{msg: "dial tcp 127.0.0.1:1: connectex: No connection could be made because the target machine actively refused it.", want: "conn_refused"},
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
		t.Run(string(tt.want)+"/"+tt.msg, func(t *testing.T) {
			assertNetErrorKind(t, errors.New(tt.msg), tt.want)
		})
	}
}

func TestNetErrorClassifiersMatchErrnoTables(t *testing.T) {
	tables := []struct {
		kind   ErrorKind
		name   string
		errnos []error
	}{
		{kind: "conn_reset", name: "ECONNRESET", errnos: connResetErrnos},
		{kind: "conn_aborted", name: "ECONNABORTED", errnos: connAbortedErrnos},
		{kind: "broken_pipe", name: "EPIPE", errnos: brokenPipeErrnos},
		{kind: "conn_refused", name: "ECONNREFUSED", errnos: connRefusedErrnos},
		{kind: "host_unreachable", name: "EHOSTUNREACH", errnos: hostUnreachErrnos},
		{kind: "network_unreachable", name: "ENETUNREACH", errnos: netUnreachErrnos},
		{kind: "permission_denied", name: "EACCES", errnos: accessErrnos},
		{kind: "permission_denied", name: "EPERM", errnos: permErrnos},
		{kind: "timeout", name: "ETIMEDOUT", errnos: timedOutErrnos},
		{kind: "addr_in_use", name: "EADDRINUSE", errnos: addrInUseErrnos},
		{kind: "addr_not_available", name: "EADDRNOTAVAIL", errnos: addrNotAvailErrnos},
		{kind: "message_too_large", name: "EMSGSIZE", errnos: msgSizeErrnos},
	}
	for _, table := range tables {
		for _, errno := range table.errnos {
			t.Run(fmt.Sprintf("%s/%v", table.name, errno), func(t *testing.T) {
				err := &net.OpError{Op: "dial", Net: "tcp", Err: localizedError{err: errno}}
				assertNetErrorKind(t, err, table.kind)
				if runtime.GOOS == "plan9" {
					return // plan9 errors carry no errno
				}
				if got := NetErrorDetails(err, nil).String(); !strings.HasSuffix(got, " errno_name="+table.name) {
					t.Fatalf("NetErrorDetails().String() = %q, want errno_name=%s", got, table.name)
				}
			})
		}
	}
}

func TestNetErrorKindGenericErrors(t *testing.T) {
	tests := []struct {
		err  error
		want ErrorKind
	}{
		{err: nil, want: "none"},
		{err: fakeNetError{msg: "deadline", timeout: true}, want: "timeout"},
		{err: fmt.Errorf("read frame: %w", io.ErrUnexpectedEOF), want: "unexpected_eof"},
		{err: io.EOF, want: "eof"},
		{err: &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}, want: "closed"},
		{err: &net.DNSError{Err: "no such host", Name: "missing.example"}, want: "dns"},
		{err: errors.New("something else"), want: "other"},
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
	if got := NetErrorDetails(nil, nil).String(); got != "kind=none" {
		t.Fatalf("NetErrorDetails(nil).String() = %q, want kind=none", got)
	}
}

func TestNetErrorDetailsIncludesConnAndTimeout(t *testing.T) {
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
	got := NetErrorDetails(err, c).String()
	for _, want := range []string{"kind=timeout", "timeout=true", "local=pipe", "remote=pipe", "op=read", "net=tcp"} {
		if !strings.Contains(got, want) {
			t.Fatalf("NetErrorDetails().String() = %q, want %s", got, want)
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
		assertNetErrorKind(t, err, "conn_refused")
		switch runtime.GOOS {
		case "plan9", "js", "wasip1":
			return // plan9 errors carry no errno; js and wasip1 flatten dial errors to text
		}
		if got := NetErrorDetails(err, nil).String(); !strings.Contains(got, "errno_name=ECONNREFUSED") {
			t.Fatalf("NetErrorDetails().String() = %q, want errno_name=ECONNREFUSED", got)
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
		assertNetErrorKind(t, err, "conn_reset")
		if got := NetErrorDetails(err, client).String(); !strings.Contains(got, "errno_name=ECONNRESET") {
			t.Fatalf("NetErrorDetails().String() = %q, want errno_name=ECONNRESET", got)
		}
	})
}

// NetErrorDetails gives an error's information as fields.
func TestNetErrorDetails(t *testing.T) {
	err := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", connResetErrnos[0])}
	info := NetErrorDetails(err, nil)
	if info.Kind != KindConnReset || info.Op != "read" || info.Net != "tcp" || info.Syscall != "read" {
		t.Fatalf("NetErrorDetails() = %+v", info)
	}
	if runtime.GOOS != "plan9" && (info.ErrnoName != "ECONNRESET" || ErrnoName(err) != "ECONNRESET" || info.Errno == 0) {
		t.Fatalf("errno fields = %d %q", info.Errno, info.ErrnoName)
	}
	if NetErrorDetails(nil, nil).Kind != KindNone || ErrnoName(errors.New("x")) != "" {
		t.Fatal("details of a nil or plain error")
	}
}

// Lookups and cancellations get kinds of their own.
func TestErrorKindDNSAndCanceled(t *testing.T) {
	notFound := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}}
	if !IsDNSError(notFound) || !IsDNSNotFound(notFound) || NetErrorKind(notFound) != KindDNS {
		t.Fatalf("not found: dns %t, not found %t, kind %v", IsDNSError(notFound), IsDNSNotFound(notFound), NetErrorKind(notFound))
	}
	dnsTimeout := &net.DNSError{Err: "i/o timeout", Name: "x.example", IsTimeout: true}
	if IsDNSNotFound(dnsTimeout) || NetErrorKind(dnsTimeout) != KindDNS {
		t.Fatalf("lookup timeout: not found %t, kind %v", IsDNSNotFound(dnsTimeout), NetErrorKind(dnsTimeout))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:1")
	if !IsCanceled(err) || NetErrorKind(err) != KindCanceled {
		t.Fatalf("canceled dial %v: canceled %t, kind %v", err, IsCanceled(err), NetErrorKind(err))
	}
	if !IsCanceled(errors.New("read: operation was canceled")) || IsCanceled(io.EOF) {
		t.Fatal("canceled text")
	}
}

// A lookup is KindDNS whatever its cause, and a canceled one KindCanceled.
func TestErrorKindDNSFirst(t *testing.T) {
	refused := &net.DNSError{Err: "read udp 10.0.0.1:5353->10.0.0.53:53: connection refused", Name: "x.example"}
	if got := NetErrorKind(refused); got != KindDNS {
		t.Fatalf("NetErrorKind(lookup refused) = %v, want dns", got)
	}
	canceled := &net.DNSError{Err: "operation was canceled", Name: "x.example"}
	if got := NetErrorKind(canceled); got != KindCanceled {
		t.Fatalf("NetErrorKind(canceled lookup) = %v, want canceled", got)
	}
}
