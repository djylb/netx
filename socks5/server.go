package socks5

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/djylb/netx"
)

// ErrServerClosed is returned by Serve after Close.
var ErrServerClosed = errors.New("socks5: server closed")

// Default timeouts of a Server.
const (
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultDialTimeout      = 10 * time.Second
	DefaultUDPIdleTimeout   = 3 * time.Minute
)

// DefaultUDPQueue is how many client datagrams a UDP association buffers
// when Server.UDPQueue is not positive.
const DefaultUDPQueue = 128

// Request is a client request read by Server.Handshake.
type Request struct {
	// Version is Version5, or Version4 for a SOCKS4 or SOCKS4a request.
	Version byte
	Command Command
	replies uint8 // replies sent; next to the bytes above, sharing one word
	// Dst is the requested destination. For CmdUDPAssociate it is the address
	// the client expects to send datagrams from, often the zero Addr.
	Dst Addr
	// User is the identity returned by the authenticator, empty without
	// authentication. For SOCKS4 it is what the NoAuth authenticator
	// returned.
	User string
	// UserID4 is the user ID of a SOCKS4 or SOCKS4a request, which the client
	// sends without authentication; empty for SOCKS5.
	UserID4 string
	// Conn is the client's connection, positioned after the request: it
	// first returns the bytes a SOCKS4 client sent right after its request,
	// which reading the request buffered, and writes go to the served
	// connection. It is the connection to reply on and to relay.
	Conn net.Conn
}

// Reply sends a reply to r in its protocol version: for SOCKS4 code and bound
// are translated as by WriteReply4. A request gets one reply, except a BIND
// request, which gets two: the address the server listens on for the peer,
// and then the address of the peer that connected. A failure reply, which
// usually carries the zero Addr, is the last one, and the connection is then
// closed. Calls after the last reply return ErrReplied. Reply is not safe for
// concurrent use.
func (r *Request) Reply(code Reply, bound Addr) error {
	last := uint8(1)
	if r.Command == CmdBind {
		last = 2
	}
	if r.replies >= last {
		return ErrReplied
	}
	r.replies++
	if code != ReplySucceeded && code != Reply4Granted {
		r.replies = last
	}
	if r.Version == Version4 {
		return WriteReply4(r.Conn, code, bound)
	}
	return WriteReply(r.Conn, code, bound)
}

// Authenticator authenticates clients with one method.
type Authenticator interface {
	// Method returns the method the authenticator implements.
	Method() Method
	// Authenticate runs the method's sub-negotiation on c after the server
	// selected the method, and returns the client's identity.
	Authenticate(ctx context.Context, c net.Conn) (user string, err error)
}

// NoAuth accepts clients without authentication.
type NoAuth struct{}

// Method returns MethodNoAuth.
func (NoAuth) Method() Method { return MethodNoAuth }

// Authenticate accepts the client.
func (NoAuth) Authenticate(context.Context, net.Conn) (string, error) { return "", nil }

// UserPassAuth checks username/password credentials (RFC 1929).
type UserPassAuth struct {
	// Check reports whether the credentials that the client sent on c are
	// valid; ctx is bounded by the handshake. c tells the client's address,
	// for rules per address. An error, such as an unreachable account
	// backend, rejects the client too and is returned by Authenticate
	// instead of ErrAuthFailed, so that it is not mistaken for a wrong
	// password. Nil rejects all credentials. See Credentials for a fixed
	// account list.
	Check func(ctx context.Context, c net.Conn, user, password string) (bool, error)
}

// Method returns MethodUserPass.
func (UserPassAuth) Method() Method { return MethodUserPass }

// Authenticate reads the credentials, checks them, answers the client and
// returns the user name, or ErrAuthFailed, or the error of Check.
func (a UserPassAuth) Authenticate(ctx context.Context, c net.Conn) (string, error) {
	user, password, err := ReadUserPass(c)
	if err != nil {
		return "", err
	}
	ok := false
	var checkErr error
	if a.Check != nil {
		ok, checkErr = a.Check(ctx, c, user, password)
		ok = ok && checkErr == nil
	}
	if err := WriteUserPassStatus(c, ok); err != nil {
		return "", err
	}
	switch {
	case checkErr != nil:
		return "", checkErr
	case !ok:
		return "", ErrAuthFailed
	}
	return user, nil
}

// Credentials returns a UserPassAuth.Check function that accepts the given
// user names and passwords. It compares SHA-256 digests in constant time, and
// for unknown users compares against a digest of no account, so that the
// time taken tells neither the length of a password nor whether a user
// exists.
func Credentials(accounts map[string]string) func(ctx context.Context, c net.Conn, user, password string) (bool, error) {
	digests := make(map[string][sha256.Size]byte, len(accounts))
	for user, password := range accounts {
		digests[user] = sha256.Sum256([]byte(password))
	}
	var unknown [sha256.Size]byte // no password has this digest
	return func(_ context.Context, _ net.Conn, user, password string) (bool, error) {
		want, known := digests[user]
		if !known {
			want = unknown
		}
		got := sha256.Sum256([]byte(password))
		match := subtle.ConstantTimeCompare(want[:], got[:]) == 1
		return known && match, nil
	}
}

// Server serves SOCKS5 clients, and SOCKS4 and SOCKS4a clients when enabled.
//
// Every field is optional: the zero Server accepts clients without
// authentication, serves CONNECT with a direct dial, and refuses BIND and UDP
// ASSOCIATE. UDP ASSOCIATE is served once UDPSocket or ListenUDP is set.
// Other commands can be served by calling Handshake and then answering the
// request, or passing it to ServeRequest.
//
// The server sets no limit on the connections or UDP associations of a
// client, each of which holds a few sockets and buffers; bound them in the
// listener passed to Serve or in Allow.
type Server struct {
	// Auth lists the accepted authentication methods in order of
	// preference. Nil means NoAuth. An authenticator for MethodNoAuth, which
	// may check the connection itself (its address or TLS state), also
	// decides on SOCKS4 clients and on SOCKS5 clients whose method lists
	// match no authenticator.
	Auth []Authenticator

	// Allow is called by ServeRequest for each request. A non-nil error
	// refuses it with the error's ReplyFor code, or ReplyNotAllowed when that
	// is ReplyGeneralFailure.
	//
	// The request's Dst holds every IP address the client sends as IP,
	// including IPv4-mapped IPv6 addresses and domain names that are IP
	// literals, also with one trailing dot such as "127.0.0.1." (see
	// DecodeAddr). Other names are not resolved: a policy on IP
	// addresses must also check the addresses that names resolve to, in a
	// Dial hook, for example with a net.Dialer Control function, since some
	// resolvers turn legacy forms such as "127.1" or "0x7f.0.0.1" into
	// addresses. The unspecified addresses 0.0.0.0 and :: reach the server's
	// own host on many systems.
	Allow func(ctx context.Context, req *Request) error
	// AllowPacket, if set, drops the client datagrams to destinations it
	// rejects. Like Allow, it sees IP addresses as IP and other names
	// unresolved, so a policy on IP addresses must also check the addresses
	// that names resolve to, in a DialPacket whose PacketConn resolves them.
	AllowPacket func(req *Request, dst Addr) bool
	// OnError, if set, receives the errors that end connections accepted by
	// Serve, with the client connection, and those that drop UDP datagrams,
	// with the association's control connection. It is called from serving
	// goroutines and must be safe for concurrent use. Errors that come once
	// Close is called, which ends the connections and associations, are not
	// reported, whatever they are. The package does not log; route errors
	// to a logger such as log/slog here.
	OnError func(c net.Conn, err error)

	// Handle, if set, is called by ServeRequest for each request after Allow
	// and before the built-in commands, so that a server can serve commands
	// such as BIND itself, or take over CONNECT or UDP ASSOCIATE for some
	// requests, while Serve, Shutdown and ActiveConns still cover their
	// connections. When it returns handled true, or has replied with
	// req.Reply whatever it returns, it has served the request: it replied,
	// for BIND twice, and used req.Conn, which is closed when it returns,
	// and its error ends the exchange as the built-in commands' errors do.
	// Otherwise a non-nil error refuses the request with the error's
	// ReplyFor code, and nil leaves it to the built-in commands. ctx ends,
	// and req.Conn is closed, when Close is called.
	Handle func(ctx context.Context, req *Request) (handled bool, err error)

	// Dial connects to the destination of a CONNECT request; nil dials it
	// directly. ctx is bounded by DialTimeout. The error's ReplyFor code is
	// sent to the client, so return a *ReplyError to choose it.
	Dial func(ctx context.Context, req *Request) (net.Conn, error)
	// ConnectAddr returns the bound address of a successful CONNECT reply;
	// nil uses target's local address.
	ConnectAddr func(req *Request, target net.Conn) Addr
	// Relay copies data between req.Conn and the target of a CONNECT request
	// and closes both; nil uses netx.Relay with netx.WithRelayHalfClose, so
	// that a client that shuts down its writing side still gets the reply.
	// As with TCP itself, a half-closed connection then lasts until the
	// other side finishes or closes too; to bound how long an idle one may
	// last, relay through netx.NewTimeoutConn on both ends. ctx ends, and
	// both connections are closed, when Close is called.
	Relay func(ctx context.Context, req *Request, target net.Conn) error
	// RelayOptions, if set, returns options added to those of the default
	// relay of a CONNECT request, such as netx.WithRelayFlows for the
	// allowance or byte count of req.User, netx.WithRelayGroup or an idle
	// timeout. It is not used when Relay is set.
	RelayOptions func(req *Request) []netx.RelayOption

	// UDPSocket is the client-facing UDP socket shared by all associations,
	// which the clients are told to send to. Datagrams are routed to an
	// association by their source, which must have the IP address of its control
	// connection: to the association that announced the source's port, else
	// to the only association of that IP address that announced no port,
	// else to the only one pending for that IP address. An announced port
	// counts at the control connection's IP address whatever address comes
	// with it, since clients behind a NAT announce their private address and
	// clients that do not know theirs announce 0.0.0.0 or a name; a client
	// that announces the control connection's own address and a port gets
	// datagrams from that source alone, as no NAT rewrote it. A source
	// that matches none of these, such as one of several associations that
	// announced no port, is ambiguous while they wait for their first
	// datagram, and its datagrams are dropped. A request whose control
	// connection has no IP address, such as a tunneled stream, must announce
	// one, or it fails; nothing proves that announcement, so such a client
	// can claim the datagrams of any IP address, and its control
	// connections must come from trusted clients only. Serve untrusted
	// clients of that kind with ListenUDP, whose sockets are their own.
	// Close closes UDPSocket.
	UDPSocket net.PacketConn
	// ListenUDP, used when UDPSocket is nil, opens a UDP socket for one
	// association, which the association owns. Datagrams are taken as on
	// UDPSocket, except that when neither the control connection nor the
	// request gives the client's IP address, the first source that sends
	// becomes the client.
	ListenUDP func(ctx context.Context, req *Request) (net.PacketConn, error)
	// UDPAddr returns the address a UDP ASSOCIATE reply tells the client to
	// send to, given the association's socket address; nil uses that address
	// with the control connection's local IP when it is unspecified.
	UDPAddr func(req *Request, socket net.Addr) Addr
	// DialPacket opens the outbound side of a UDP association; nil uses a new
	// UDP socket from netx.ListenEphemeralUDP through NewPacketConn. That
	// socket reaches IPv4 and IPv6 targets where the system has dual-stack
	// sockets; on OpenBSD, which has none, it is IPv4 only. ctx is bounded by
	// DialTimeout and bounds the setup only. To relay through another SOCKS5
	// proxy, return a Dialer's ListenPacket.
	DialPacket func(ctx context.Context, req *Request) (PacketConn, error)
	// UDPQueue is how many client datagrams an association buffers;
	// DefaultUDPQueue if not positive.
	UDPQueue int

	// HandshakeTimeout bounds the negotiation and request;
	// DefaultHandshakeTimeout if not positive.
	HandshakeTimeout time.Duration
	// DialTimeout bounds Dial and DialPacket; DefaultDialTimeout if not
	// positive.
	DialTimeout time.Duration
	// UDPIdleTimeout ends a UDP association without datagrams in either
	// direction, or without a first datagram, for this long, and closes its
	// control connection; DefaultUDPIdleTimeout if not positive.
	UDPIdleTimeout time.Duration

	// Switches. The unexported flags follow them, so that the booleans
	// share one word.

	// SOCKS4 also serves SOCKS4 and SOCKS4a requests. They carry no
	// credentials, so they are refused unless Auth has a MethodNoAuth
	// authenticator, which then runs for them.
	SOCKS4 bool
	// UDPOutlivesControl keeps a UDP association after its control
	// connection closes, until UDPIdleTimeout, for clients that close or
	// half-close it right after the reply. By default the association ends
	// with the control connection, as RFC 1928 specifies.
	UDPOutlivesControl bool

	draining bool // Shutdown was called
	closed   bool // Close was called
	mu       sync.Mutex
	ctx      context.Context // canceled by Close
	cancel   context.CancelFunc
	// Tracked by pointer, as in net/http, since the dynamic types of a
	// net.Listener or a net.Conn need not be comparable.
	listeners map[*net.Listener]struct{}
	conns     map[*net.Conn]struct{}
	drained   chan struct{} // closed when conns empties during Shutdown
	shared    *udpRelay
	closeDone chan struct{} // closed when the first Close has returned
}

// Serve accepts connections on l and serves each with ServeConn, under a
// context that Close cancels, in its own goroutine. It returns
// ErrServerClosed after Shutdown or Close, which close l, or the error that
// ended Accept.
// Temporary Accept errors, such as timeouts and running out of file
// descriptors (EMFILE, ENFILE), are retried with a growing delay.
func (s *Server) Serve(l net.Listener) error {
	if !s.track(&l, true) {
		_ = l.Close()
		return ErrServerClosed
	}
	defer s.track(&l, false)
	ctx := s.baseContext()
	closed := ctx.Done()
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if s.stopping() {
				return ErrServerClosed
			}
			if temporary(err) {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				t := time.NewTimer(delay)
				select {
				case <-t.C:
				case <-closed:
					t.Stop()
					return ErrServerClosed
				}
				continue
			}
			return err
		}
		delay = 0
		// Tracked before the goroutine starts, so that Shutdown, once it
		// sees no connections, cannot miss one being started. One accepted
		// just before Shutdown or Close closed the listener is refused,
		// which is no failure.
		if !s.trackConn(&c, true) {
			_ = c.Close()
			continue
		}
		go func() {
			defer s.trackConn(&c, false)
			if err := s.serveConn(ctx, c); err != nil {
				s.onError(c, err)
			}
		}()
	}
}

// temporary reports whether an Accept error is worth retrying, as net/http
// decides: a timeout, or an error that reports itself temporary.
func temporary(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var te interface{ Temporary() bool }
	return errors.As(err, &te) && te.Temporary()
}

// ServeConn serves one client connection, as Handshake and ServeRequest do,
// and closes it. ctx ending ends the connection, as Close does. It returns
// the error that ended the exchange, if any. The connection counts in
// ActiveConns until ServeConn returns.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) error {
	if !s.trackConn(&c, true) {
		_ = c.Close()
		return ErrServerClosed
	}
	defer s.trackConn(&c, false)
	return s.serveConn(ctx, c)
}

// serveConn serves a tracked connection and closes it.
func (s *Server) serveConn(ctx context.Context, c net.Conn) error {
	defer func() { _ = c.Close() }()
	ctx, cancel, err := s.bindContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	req, err := s.handshake(ctx, c)
	if err != nil {
		return err
	}
	return s.serveRequest(ctx, req)
}

// Handshake reads a client's method negotiation, authentication and request
// on c, in SOCKS5 or, when enabled, SOCKS4 or SOCKS4a, and returns the
// request without replying to it. HandshakeTimeout bounds it, after which it
// returns an error matching os.ErrDeadlineExceeded, and ctx and Close end it
// too. Failures that the protocol answers, such as no acceptable method,
// rejected credentials or a malformed request, are answered before it
// returns. c has no deadline set after a success.
//
// On failure c is left open for the caller to close; after a timeout or the
// end of ctx it is unusable, and the connection beneath a *tls.Conn is
// already closed, so that closing it sends no close_notify the peer cannot
// authenticate.
//
// The request is served by ServeRequest, or by the caller, which replies
// with Request.Reply and reads and writes Request.Conn; Allow is then not
// called. A caller that serves connections itself, rather than with Serve or
// ServeConn, is not counted by ActiveConns and not waited for by Shutdown.
func (s *Server) Handshake(ctx context.Context, c net.Conn) (*Request, error) {
	ctx, cancel, err := s.bindContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return s.handshake(ctx, c)
}

// ServeRequest serves a request from Handshake and closes req.Conn. It calls
// Allow, then Handle, then serves CONNECT, and UDP ASSOCIATE when UDPSocket
// or ListenUDP is set; other commands, and UDP ASSOCIATE from SOCKS4, are
// answered with ReplyCommandNotSupported and returned as a *ReplyError. A
// refused request is returned as a *ReplyError whose Err is the cause. ctx
// and Close end it, closing req.Conn. It returns the error that ended the
// exchange, if any.
func (s *Server) ServeRequest(ctx context.Context, req *Request) error {
	ctx, cancel, err := s.bindContext(ctx)
	if err != nil {
		_ = req.Conn.Close()
		return err
	}
	defer cancel()
	return s.serveRequest(ctx, req)
}

// bindContext returns a context that also ends with Close, or ErrServerClosed
// after Close.
func (s *Server) bindContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if s.isClosed() {
		return nil, nil, ErrServerClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.baseContext(), cancel)
	return ctx, func() { stop(); cancel() }, nil
}

// handshake runs the handshake on c under HandshakeTimeout and ctx.
func (s *Server) handshake(ctx context.Context, c net.Conn) (*Request, error) {
	// The authenticators' context ends with the handshake timeout too.
	hctx, cancel := context.WithTimeout(ctx, positive(s.HandshakeTimeout, DefaultHandshakeTimeout))
	defer cancel()
	var req *Request
	err := netx.DoWithContext(hctx, c, func() (err error) {
		req, err = s.readRequest(hctx, c)
		return err
	})
	if err == nil {
		return req, nil
	}
	// The connection's deadline is hctx's, so an I/O timeout can come just
	// before hctx reports it; the deadline having passed tells them apart
	// from the timeouts of an authenticator's own backend.
	deadline, _ := hctx.Deadline()
	timedOut := hctx.Err() != nil || !time.Now().Before(deadline)
	if timedOut && ctx.Err() == nil {
		err = os.ErrDeadlineExceeded
	}
	if timedOut || ctx.Err() != nil {
		closeBeneathTLS(c)
	}
	return nil, err
}

// serveRequest serves req and closes its connection.
func (s *Server) serveRequest(ctx context.Context, req *Request) error {
	defer func() { _ = req.Conn.Close() }()
	// Ending ctx, as Close does, ends the exchange whatever it waits for.
	stop := context.AfterFunc(ctx, func() { _ = req.Conn.Close() })
	defer stop()
	if s.Allow != nil {
		if err := s.Allow(ctx, req); err != nil {
			code := ReplyFor(err)
			if code == ReplyGeneralFailure {
				code = ReplyNotAllowed
			}
			return refuse(req, code, err)
		}
	}
	if s.Handle != nil {
		handled, err := s.Handle(ctx, req)
		switch {
		case handled || req.replies > 0:
			// A request that Handle replied to is its own, whatever it
			// says, as the built-in commands could not reply again.
			return err
		case err != nil:
			return refuse(req, ReplyFor(err), err)
		}
	}
	switch {
	case req.Command == CmdConnect:
		return s.connect(ctx, req)
	case req.Command == CmdUDPAssociate && req.Version != Version4 && (s.UDPSocket != nil || s.ListenUDP != nil):
		return s.associate(ctx, req)
	}
	return refuse(req, ReplyCommandNotSupported, errors.New(req.Command.String()))
}

// refuse replies code to req and returns err as a *ReplyError that carries
// code, unless it already is one.
func refuse(req *Request, code Reply, err error) error {
	_ = req.Reply(code, Addr{})
	if replyErr, ok := errors.AsType[*ReplyError](err); ok && replyErr.Reply == code {
		return err
	}
	return &ReplyError{Reply: code, Err: err}
}

// readRequest reads the client's negotiation and request in either version.
func (s *Server) readRequest(ctx context.Context, c net.Conn) (*Request, error) {
	var first [1]byte
	if _, err := io.ReadFull(c, first[:]); err != nil {
		return nil, err
	}
	switch {
	case first[0] == Version5:
		return s.handshake5(ctx, c, first[:])
	case first[0] == Version4 && s.SOCKS4:
		return s.handshake4(ctx, c, first[:])
	default:
		return nil, ErrVersion
	}
}

func (s *Server) handshake5(ctx context.Context, c net.Conn, first []byte) (*Request, error) {
	methods, err := ReadMethods(io.MultiReader(bytes.NewReader(first), c))
	if err != nil {
		return nil, err
	}
	auth := s.authenticator(methods)
	if auth == nil {
		_ = WriteMethod(c, MethodNoAcceptable)
		return nil, ErrNoAcceptableMethod
	}
	if err := WriteMethod(c, auth.Method()); err != nil {
		return nil, err
	}
	user, err := auth.Authenticate(ctx, c)
	if err != nil {
		return nil, err
	}
	cmd, dst, err := ReadRequest(c)
	if err != nil {
		code := ReplyGeneralFailure
		if errors.Is(err, ErrAddrType) {
			code = ReplyAddrTypeNotSupported
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			_ = WriteReply(c, code, Addr{})
		}
		return nil, err
	}
	return &Request{Version: Version5, Command: cmd, Dst: dst, User: user, Conn: c}, nil
}

// authenticator returns the first configured authenticator whose method the
// client offers. When authentication is optional it also serves clients that
// offer no method or only methods it lacks: an empty list or anything but
// username/password gets NoAuth, and username/password alone is accepted with
// any credentials and no identity.
func (s *Server) authenticator(offered []Method) Authenticator {
	for _, a := range s.authenticators() {
		if slices.Contains(offered, a.Method()) {
			return a
		}
	}
	// For non-standard clients the NoAuth authenticator also takes empty and
	// unmatched method lists, behind username/password if offered.
	noAuth := s.noAuth()
	switch {
	case noAuth == nil:
		return nil
	case slices.Contains(offered, MethodUserPass):
		return anyUserPass{noAuth: noAuth}
	default:
		return noAuth
	}
}

// noAuth returns the authenticator for MethodNoAuth, or nil when
// authentication is required.
func (s *Server) noAuth() Authenticator {
	for _, a := range s.authenticators() {
		if a.Method() == MethodNoAuth {
			return a
		}
	}
	return nil
}

// anyUserPass completes username/password authentication with any
// credentials when the server does not require authentication, leaving the
// decision to the NoAuth authenticator.
type anyUserPass struct {
	noAuth Authenticator
}

func (anyUserPass) Method() Method { return MethodUserPass }

func (a anyUserPass) Authenticate(ctx context.Context, c net.Conn) (string, error) {
	if _, _, err := ReadUserPass(c); err != nil {
		return "", err
	}
	user, err := a.noAuth.Authenticate(ctx, c)
	if err != nil {
		_ = WriteUserPassStatus(c, false)
		return "", err
	}
	if err := WriteUserPassStatus(c, true); err != nil {
		return "", err
	}
	return user, nil
}

func (s *Server) authenticators() []Authenticator {
	if len(s.Auth) == 0 {
		return []Authenticator{NoAuth{}}
	}
	return s.Auth
}

func (s *Server) connect(ctx context.Context, req *Request) error {
	dialCtx, cancel := context.WithTimeout(ctx, positive(s.DialTimeout, DefaultDialTimeout))
	target, err := s.dial(dialCtx, req)
	cancel()
	if err != nil {
		return refuse(req, ReplyFor(err), err)
	}
	bound := AddrFromNetAddr(target.LocalAddr())
	if s.ConnectAddr != nil {
		bound = s.ConnectAddr(req, target)
	}
	if err := req.Reply(ReplySucceeded, bound); err != nil {
		_ = target.Close()
		return err
	}
	// Ending ctx closes the client connection; the target is closed too, or
	// a relay waiting on it, for example after the client half-closed, would
	// outlive Close.
	stop := context.AfterFunc(ctx, func() { _ = target.Close() })
	defer stop()
	// Also for a Relay hook that leaves it open.
	defer func() { _ = target.Close() }()
	if s.Relay != nil {
		return s.Relay(ctx, req, target)
	}
	opts := []netx.RelayOption{netx.WithRelayHalfClose()}
	if s.RelayOptions != nil {
		opts = append(opts, s.RelayOptions(req)...)
	}
	_, _, err = netx.Relay(ctx, req.Conn, target, opts...)
	return err
}

func (s *Server) dial(ctx context.Context, req *Request) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, req)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", req.Dst.String())
}

func (s *Server) baseContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
		if s.closed {
			s.cancel()
		}
	}
	return s.ctx
}

// Shutdown stops the server gracefully: it closes the listeners passed to
// Serve, which then returns ErrServerClosed, makes ServeConn refuse new
// connections, and waits until the connections being served end, the
// control connections of UDP associations among them; then it calls Close.
// When ctx ends first, Close ends the remaining connections and Shutdown
// returns ctx's error too.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.Close() // waits for the Close in progress
	}
	s.draining = true
	// Taken out, so that Close does not close them again.
	listeners := slices.Collect(maps.Keys(s.listeners))
	clear(s.listeners)
	var drained chan struct{}
	if len(s.conns) > 0 {
		if s.drained == nil {
			s.drained = make(chan struct{})
		}
		drained = s.drained
	}
	s.mu.Unlock()
	var errs []error
	for _, l := range listeners {
		errs = append(errs, (*l).Close())
	}
	if drained != nil {
		select {
		case <-drained:
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		}
	}
	return errors.Join(append(errs, s.Close())...)
}

// ActiveConns returns the number of connections being served by Serve and
// ServeConn, the control connections of UDP associations among them.
func (s *Server) ActiveConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Close stops the listeners passed to Serve, closes the connections being
// served, ends the UDP associations, closing UDPSocket, and ends the
// Handshake and ServeRequest calls in progress. Serve then returns
// ErrServerClosed. Later calls, also of Shutdown, wait until the first has
// finished and return nil.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closeDone == nil {
		s.closeDone = make(chan struct{})
	}
	done := s.closeDone
	if s.closed {
		s.mu.Unlock()
		<-done // the first Close finishes its work before any call returns
		return nil
	}
	s.closed = true
	defer close(done)
	if s.cancel != nil {
		s.cancel()
	}
	// Close outside the lock: closing a *tls.Conn can block for seconds while
	// it sends close_notify, and serving goroutines need the lock to finish.
	listeners := slices.Collect(maps.Keys(s.listeners))
	conns := slices.Collect(maps.Keys(s.conns))
	shared := s.shared
	s.mu.Unlock()
	var errs []error
	for _, l := range listeners {
		errs = append(errs, (*l).Close())
	}
	for _, c := range conns {
		_ = (*c).Close()
	}
	if shared != nil {
		errs = append(errs, shared.close())
	} else if s.UDPSocket != nil {
		errs = append(errs, s.UDPSocket.Close())
	}
	return errors.Join(errs...)
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// stopping reports whether Shutdown or Close was called.
func (s *Server) stopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || s.draining
}

func (s *Server) track(l *net.Listener, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed || s.draining {
			return false
		}
		if s.listeners == nil {
			s.listeners = make(map[*net.Listener]struct{})
		}
		s.listeners[l] = struct{}{}
		return true
	}
	delete(s.listeners, l)
	return true
}

func (s *Server) trackConn(c *net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed || s.draining {
			return false
		}
		if s.conns == nil {
			s.conns = make(map[*net.Conn]struct{})
		}
		s.conns[c] = struct{}{}
		return true
	}
	delete(s.conns, c)
	if len(s.conns) == 0 && s.drained != nil {
		close(s.drained)
		s.drained = nil
	}
	return true
}

// onError passes err to OnError unless Close was called: Close ends the
// connections and associations it serves and cancels the context of their
// hooks and dials, so whatever error they then end with, such as a hook's
// own error for its cancelled context, comes from Close.
func (s *Server) onError(c net.Conn, err error) {
	if s.OnError != nil && !s.isClosed() {
		s.OnError(c, err)
	}
}

// closeBeneathTLS closes the connection beneath c after a timeout when c is a
// *tls.Conn. One whose write timed out would still send close_notify on
// Close, under a record number that the peer cannot authenticate, so the peer
// would see a TLS failure instead of the end of the connection. Only the
// connection that c's Close closes anyway is closed, never one that c merely
// borrows, such as the parent of a netx.WrapConn.
func closeBeneathTLS(c net.Conn) {
	// Matched by its methods, so that the package does not link crypto/tls.
	if tc, ok := c.(interface {
		NetConn() net.Conn
		HandshakeContext(context.Context) error
	}); ok {
		if raw := tc.NetConn(); raw != nil {
			_ = raw.Close()
		}
	}
}

func positive(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
