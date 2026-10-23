package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// The classifiers below match the platform errno first, so they work whatever
// the system language is, and then fall back to well-known English messages
// for errors that only carry text.

// IsTimeout reports whether err is a timeout. It matches ETIMEDOUT
// (WSAETIMEDOUT on Windows) anywhere in the chain first, then the first
// net.Error's Timeout method, and only then English timeout messages.
func IsTimeout(err error) bool {
	return err != nil && isTimeout(&errText{err: err})
}

func isTimeout(t *errText) bool {
	// Checked first because Errno.Timeout is false for WSAETIMEDOUT on Windows.
	if t.hasErrno(errnoSet(1) << eTimedOut) {
		return true
	}
	if ne, ok := errors.AsType[net.Error](t.err); ok {
		return ne.Timeout()
	}
	// Spaces are kept so that words such as "runtime output" do not match.
	s := t.lower()
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "timed out") ||
		strings.Contains(s, "did not properly respond after a period of time")
}

// IsClosed reports whether err comes from using a closed connection or
// listener: net.ErrClosed, io.ErrClosedPipe, or the "use of closed network
// connection" text that some wrappers pass on without the error value.
func IsClosed(err error) bool {
	return err != nil && isClosed(&errText{err: err})
}

func isClosed(t *errText) bool {
	if errors.Is(t.err, net.ErrClosed) || errors.Is(t.err, io.ErrClosedPipe) {
		return true
	}
	return strings.Contains(t.text(), "use of closed network connection")
}

// IsCanceled reports whether err comes from a canceled context or
// operation: context.Canceled, which a canceled dial or lookup of package
// net matches, or the "operation was canceled" text that some wrappers pass
// on without the error value.
func IsCanceled(err error) bool {
	return err != nil && isCanceled(&errText{err: err})
}

func isCanceled(t *errText) bool {
	return errors.Is(t.err, context.Canceled) || strings.Contains(t.text(), "operation was canceled")
}

// IsDNSError reports whether err is a failed name lookup: a *net.DNSError in
// the chain.
func IsDNSError(err error) bool {
	_, ok := errors.AsType[*net.DNSError](err)
	return ok
}

// IsDNSNotFound reports whether err is a lookup of a name or record that does
// not exist, as opposed to a failure to ask, such as a timeout.
func IsDNSNotFound(err error) bool {
	de, ok := errors.AsType[*net.DNSError](err)
	return ok && de.IsNotFound
}

// errorClass is how a classifier matches an error: by the platform errnos
// of its POSIX names anywhere in the chain, then by the error's text with
// spaces, hyphens and underscores removed.
type errorClass struct {
	errnos errnoSet
	texts  []string
}

func (c *errorClass) match(t *errText) bool {
	return t.hasErrno(c.errnos) || t.has(c.texts...)
}

// is reports whether err is of the class.
func (c *errorClass) is(err error) bool {
	return err != nil && c.match(&errText{err: err})
}

var (
	connReset = errorClass{errnoSet(1) << eConnReset, []string{
		"connectionresetbypeer",
		"forciblyclosedbytheremotehost",
		"networknameisnolongeravailable"}}
	connAborted = errorClass{errnoSet(1) << eConnAborted, []string{
		"connectionaborted",
		"connectionwasaborted",
		"softwarecausedconnectionabort"}}
	brokenPipe = errorClass{errnoSet(1) << ePipe, []string{
		"brokenpipe",
		"sockethadalreadybeenshutdown"}}
	connRefused = errorClass{errnoSet(1) << eConnRefused, []string{
		"connectionrefused",
		"activelyrefusedit"}}
	hostUnreachable = errorClass{errnoSet(1) << eHostUnreach, []string{
		"noroutetohost",
		"hostunreachable",
		"hostisunreachable",
		"unreachablehost"}}
	networkUnreachable = errorClass{errnoSet(1) << eNetUnreach, []string{
		"networkunreachable",
		"networkisunreachable",
		"unreachablenetwork"}}
	permissionDenied = errorClass{errnoSet(1)<<eAccess | errnoSet(1)<<ePerm, []string{
		"permissiondenied",
		"operationnotpermitted",
		"accessisdenied",
		"forbiddenbyitsaccesspermissions"}}
	addrInUse = errorClass{errnoSet(1) << eAddrInUse, []string{
		"addressalreadyinuse",
		"onlyoneusageofeachsocketaddress"}}
	addrNotAvailable = errorClass{errnoSet(1) << eAddrNotAvail, []string{
		"cannotassignrequestedaddress",
		"requestedaddressisnotvalidinitscontext"}}
	messageTooLarge = errorClass{errnoSet(1) << eMsgSize, []string{
		"messagetoolong",
		"messagesentonadatagramsocketwaslarger"}}
)

// IsConnReset reports whether err looks like a connection reset.
func IsConnReset(err error) bool { return connReset.is(err) }

// IsConnAborted reports whether err looks like an aborted connection.
func IsConnAborted(err error) bool { return connAborted.is(err) }

// IsBrokenPipe reports whether err looks like a broken pipe.
func IsBrokenPipe(err error) bool { return brokenPipe.is(err) }

// IsConnRefused reports whether err looks like a refused connection attempt.
func IsConnRefused(err error) bool { return connRefused.is(err) }

// IsHostUnreachable reports whether err looks like an unreachable host. A
// failed lookup is KindDNS for NetErrorKind, whatever its cause; IsDNSError
// tells it apart.
func IsHostUnreachable(err error) bool { return hostUnreachable.is(err) }

// IsNetworkUnreachable reports whether err looks like an unreachable network.
func IsNetworkUnreachable(err error) bool { return networkUnreachable.is(err) }

// IsPermissionDenied reports whether err looks like a permission failure
// (EACCES or EPERM), such as a connect blocked by a local firewall rule.
func IsPermissionDenied(err error) bool { return permissionDenied.is(err) }

// IsAddrInUse reports whether err looks like an address already in use,
// as when a listener's port is taken.
func IsAddrInUse(err error) bool { return addrInUse.is(err) }

// IsAddrNotAvailable reports whether err looks like an address that is not
// available on this host, as when binding to an address of another host.
func IsAddrNotAvailable(err error) bool { return addrNotAvailable.is(err) }

// IsMessageTooLarge reports whether err looks like a datagram too large to
// send or receive whole.
func IsMessageTooLarge(err error) bool { return messageTooLarge.is(err) }

// ErrorKind is a stable category of a network error, for metrics and logs;
// see NetErrorKind.
type ErrorKind string

// The kinds that NetErrorKind returns, named after the classifier that
// matches each.
const (
	KindNone               ErrorKind = "none"
	KindCanceled           ErrorKind = "canceled"
	KindDNS                ErrorKind = "dns"
	KindConnReset          ErrorKind = "conn_reset"
	KindConnAborted        ErrorKind = "conn_aborted"
	KindBrokenPipe         ErrorKind = "broken_pipe"
	KindConnRefused        ErrorKind = "conn_refused"
	KindHostUnreachable    ErrorKind = "host_unreachable"
	KindNetworkUnreachable ErrorKind = "network_unreachable"
	KindPermissionDenied   ErrorKind = "permission_denied"
	KindAddrInUse          ErrorKind = "addr_in_use"
	KindAddrNotAvailable   ErrorKind = "addr_not_available"
	KindMessageTooLarge    ErrorKind = "message_too_large"
	KindTimeout            ErrorKind = "timeout"
	KindUnexpectedEOF      ErrorKind = "unexpected_eof"
	KindEOF                ErrorKind = "eof"
	KindClosed             ErrorKind = "closed"
	KindOther              ErrorKind = "other"
)

// NetErrorKind returns the category of err: KindNone for nil, the kind of
// the first classifier that matches it, in the order of the constants, or
// KindOther.
func NetErrorKind(err error) ErrorKind {
	if err == nil {
		return KindNone
	}
	return netErrorKind(&errText{err: err})
}

// netErrorKind is NetErrorKind for a non-nil error. The classifiers share t,
// so the error's chain is searched for errnos, and its text formatted and
// normalized, at most once.
func netErrorKind(t *errText) ErrorKind {
	switch {
	// Before the others, whose text fallbacks would match the cause that a
	// lookup or a canceled operation carries.
	case isCanceled(t):
		return KindCanceled
	case IsDNSError(t.err):
		return KindDNS
	case connReset.match(t):
		return KindConnReset
	case connAborted.match(t):
		return KindConnAborted
	case brokenPipe.match(t):
		return KindBrokenPipe
	case connRefused.match(t):
		return KindConnRefused
	case hostUnreachable.match(t):
		return KindHostUnreachable
	case networkUnreachable.match(t):
		return KindNetworkUnreachable
	case permissionDenied.match(t):
		return KindPermissionDenied
	case addrInUse.match(t):
		return KindAddrInUse
	case addrNotAvailable.match(t):
		return KindAddrNotAvailable
	case messageTooLarge.match(t):
		return KindMessageTooLarge
	case isTimeout(t):
		return KindTimeout
	case errors.Is(t.err, io.ErrUnexpectedEOF):
		return KindUnexpectedEOF
	case errors.Is(t.err, io.EOF):
		return KindEOF
	case isClosed(t):
		return KindClosed
	default:
		return KindOther
	}
}

// NetErrorInfo describes a network error for diagnostics; see
// NetErrorDetails. Empty fields are not known.
type NetErrorInfo struct {
	Kind    ErrorKind
	Err     string // err.Error()
	Timeout bool
	Local   string // the connection's local address
	Remote  string // the connection's remote address
	Op      string // of the *net.OpError in the chain
	Net     string
	Source  string
	Addr    string
	Syscall string // of the *os.SyscallError in the chain
	// Errno is the platform errno in the chain, 0 for none, and ErrnoName
	// its POSIX name for the errnos that the classifiers know (ECONNRESET
	// also for WSAECONNRESET, for example), which depends on neither the
	// platform nor the system language.
	Errno     int
	ErrnoName string
}

// NetErrorDetails describes err, and the addresses of c if it is not nil, as
// fields, which String formats as one compact line for logs.
func NetErrorDetails(err error, c net.Conn) NetErrorInfo {
	if err == nil {
		return NetErrorInfo{Kind: KindNone}
	}
	t := &errText{err: err}
	info := NetErrorInfo{Kind: netErrorKind(t), Err: t.text(), Timeout: isTimeout(t)}
	if c != nil {
		if local := c.LocalAddr(); local != nil {
			info.Local = local.String()
		}
		if remote := c.RemoteAddr(); remote != nil {
			info.Remote = remote.String()
		}
	}
	if opErr, ok := errors.AsType[*net.OpError](err); ok {
		info.Op, info.Net = opErr.Op, opErr.Net
		if opErr.Source != nil {
			info.Source = opErr.Source.String()
		}
		if opErr.Addr != nil {
			info.Addr = opErr.Addr.String()
		}
	}
	if sysErr, ok := errors.AsType[*os.SyscallError](err); ok {
		info.Syscall = sysErr.Syscall
	}
	info.Errno, info.ErrnoName = errnoOf(err)
	return info
}

// String formats i as space-separated key=value fields, such as
// `kind=conn_reset err="..." remote=192.0.2.1:443 timeout=false errno=104
// errno_name=ECONNRESET`.
func (i NetErrorInfo) String() string {
	if i.Kind == KindNone {
		return "kind=none"
	}
	parts := []string{"kind=" + string(i.Kind), fmt.Sprintf("err=%q", i.Err)}
	for _, f := range [...]struct{ key, value string }{{"local", i.Local}, {"remote", i.Remote}} {
		if f.value != "" {
			parts = append(parts, f.key+"="+f.value)
		}
	}
	parts = append(parts, fmt.Sprintf("timeout=%t", i.Timeout))
	for _, f := range [...]struct{ key, value string }{
		{"op", i.Op}, {"net", i.Net}, {"source", i.Source}, {"addr", i.Addr}, {"syscall", i.Syscall},
	} {
		if f.value != "" {
			parts = append(parts, f.key+"="+f.value)
		}
	}
	if i.Errno != 0 {
		parts = append(parts, fmt.Sprintf("errno=%d", i.Errno))
		if i.ErrnoName != "" {
			parts = append(parts, "errno_name="+i.ErrnoName)
		}
	}
	return strings.Join(parts, " ")
}

// ErrnoName returns the POSIX name of the platform errno in err's chain for
// the errnos that the classifiers know, such as ECONNRESET also for
// WSAECONNRESET, or "".
func ErrnoName(err error) string {
	_, name := errnoOf(err)
	return name
}

// errText holds the text of an error for the classifiers' fallbacks. Each
// form is computed on first use, so that NetErrorKind, which may try every
// classifier, formats and normalizes the error only once.
type errText struct {
	err    error
	raw    string   // err.Error()
	low    string   // raw in lower case
	norm   string   // low without spaces, hyphens and underscores
	errnos errnoSet // the errnos in err's chain
	have   uint8    // which of the fields above are set
}

const (
	haveRaw uint8 = 1 << iota
	haveLow
	haveNorm
	haveErrnos
)

// findErrnos finds the errnos in the chain of t's error, all in one walk.
func (t *errText) findErrnos() {
	if t.have&haveErrnos == 0 {
		t.errnos = chainErrnos(t.err)
		t.have |= haveErrnos
	}
}

// hasErrno reports whether t's error matches any of the errnos of set, as
// errors.Is would.
func (t *errText) hasErrno(set errnoSet) bool {
	t.findErrnos()
	return t.errnos&set != 0
}

func (t *errText) text() string {
	if t.have&haveRaw == 0 {
		t.raw = t.err.Error()
		t.have |= haveRaw
	}
	return t.raw
}

func (t *errText) lower() string {
	if t.have&haveLow == 0 {
		t.low = strings.ToLower(t.text())
		t.have |= haveLow
	}
	return t.low
}

// has reports whether the normalized text contains any of subs.
func (t *errText) has(subs ...string) bool {
	if t.have&haveNorm == 0 {
		t.norm = stripSeparators(t.lower())
		t.have |= haveNorm
	}
	for _, sub := range subs {
		if strings.Contains(t.norm, sub) {
			return true
		}
	}
	return false
}

// stripSeparators removes the spaces, hyphens and underscores from s, so that
// "connection reset by peer" and "connection-reset" variants compare alike.
func stripSeparators(s string) string {
	if !strings.ContainsAny(s, " -_") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		switch c := s[i]; c {
		case ' ', '-', '_':
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// errnoID names a POSIX errno that the classifiers know. platformErrnos
// holds each one's errnos on the platform; errnoNames, in the same order,
// their names.
type errnoID uint8

const (
	eConnReset errnoID = iota
	eConnAborted
	ePipe
	eConnRefused
	eHostUnreach
	eNetUnreach
	eAccess
	ePerm
	eTimedOut
	eAddrInUse
	eAddrNotAvail
	eMsgSize
	numErrnoIDs
)

var errnoNames = [numErrnoIDs]string{
	eConnReset:    "ECONNRESET",
	eConnAborted:  "ECONNABORTED",
	ePipe:         "EPIPE",
	eConnRefused:  "ECONNREFUSED",
	eHostUnreach:  "EHOSTUNREACH",
	eNetUnreach:   "ENETUNREACH",
	eAccess:       "EACCES",
	ePerm:         "EPERM",
	eTimedOut:     "ETIMEDOUT",
	eAddrInUse:    "EADDRINUSE",
	eAddrNotAvail: "EADDRNOTAVAIL",
	eMsgSize:      "EMSGSIZE",
}

// errnoSet is a set of errnoIDs.
type errnoSet uint16

// chainErrnos returns the errnos that err's chain matches, as errors.Is
// would for each of them, in one walk of the chain.
func chainErrnos(err error) errnoSet {
	var set errnoSet
	for err != nil {
		set |= errnosOf(err)
		switch u := err.(type) {
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		case interface{ Unwrap() []error }:
			for _, e := range u.Unwrap() {
				set |= chainErrnos(e)
			}
			return set
		default:
			return set
		}
	}
	return set
}

// errnosOf returns the errnos that err itself matches, as errors.Is
// compares each error of a chain with its target.
func errnosOf(err error) errnoSet {
	// An errno equals its targets or none: its Is matches the os errors
	// alone.
	if set, ok := errnoValueSet(err); ok {
		return set
	}
	is, ok := err.(interface{ Is(error) bool })
	if !ok {
		return 0
	}
	var set errnoSet
	for id, targets := range platformErrnos {
		for _, target := range targets {
			if is.Is(target) {
				set |= 1 << id
				break
			}
		}
	}
	return set
}
