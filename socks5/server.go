package socks5

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"maps"
	"net"
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

// Request is a client request being served.
type Request struct {
	// Version is 5, or 4 for a SOCKS4 or SOCKS4a request.
	Version int
	Command Command
	// Dst is the requested destination. For CmdUDPAssociate it is the address
	// the client expects to send datagrams from, often the zero Addr.
	Dst Addr
	// User is the identity returned by the authenticator, empty without
	// authentication.
	User string
	// Conn is the client's control connection.
	Conn net.Conn
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
	// Check reports whether the credentials are valid. Nil rejects all of
	// them. See Credentials for a fixed account list.
	Check func(user, password string) bool
}

// Method returns MethodUserPass.
func (UserPassAuth) Method() Method { return MethodUserPass }

// Authenticate reads the credentials, answers the client and returns the user
// name, or ErrAuthFailed.
func (a UserPassAuth) Authenticate(_ context.Context, c net.Conn) (string, error) {
	user, password, err := ReadUserPass(c)
	if err != nil {
		return "", err
	}
	ok := a.Check != nil && a.Check(user, password)
	if err := WriteUserPassStatus(c, ok); err != nil {
		return "", err
	}
	if !ok {
		return "", ErrAuthFailed
	}
	return user, nil
}

// Credentials returns a UserPassAuth.Check function that accepts the given
// user names and passwords, comparing passwords in constant time.
func Credentials(accounts map[string]string) func(user, password string) bool {
	accounts = maps.Clone(accounts)
	return func(user, password string) bool {
		want, ok := accounts[user]
		return ok && subtle.ConstantTimeCompare([]byte(want), []byte(password)) == 1
	}
}

// Server serves SOCKS5 clients, and SOCKS4 and SOCKS4a clients when enabled.
//
// Every field is optional: the zero Server accepts clients without
// authentication, serves CONNECT with a direct dial, and refuses BIND and UDP
// ASSOCIATE. UDP ASSOCIATE is served once PacketConn or ListenUDP is set.
type Server struct {
	// PacketConn is the UDP socket shared by all UDP associations, which the
	// clients are told to send to. Datagrams are routed to an association by
	// their source, which must have the IP address of its control
	// connection: the exact address the client announced in its request, or
	// else the only pending association of that IP address. While several
	// associations of one IP address wait for their first datagram, an
	// unannounced source is ambiguous and its datagrams are dropped. An
	// announced address with another IP is ignored, unless the control
	// connection has no IP address; a request then fails unless it announces
	// one. Close closes PacketConn.
	PacketConn net.PacketConn
	ctx        context.Context
	// Allow is called for each request after authentication. A non-nil error
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
	// addresses.
	Allow func(ctx context.Context, req *Request) error
	// Dial connects to the destination of a CONNECT request; nil dials it
	// directly. ctx is bounded by DialTimeout. The error's ReplyFor code is
	// sent to the client, so return a *ReplyError to choose it.
	Dial func(ctx context.Context, req *Request) (net.Conn, error)
	// ConnectAddr returns the bound address of a successful CONNECT reply;
	// nil uses target's local address.
	ConnectAddr func(req *Request, target net.Conn) Addr
	// Relay copies data between the client and target of a CONNECT request
	// and closes both; nil uses netx.Relay.
	Relay func(ctx context.Context, req *Request, client, target net.Conn) error
	// ListenUDP, used when PacketConn is nil, opens a UDP socket for one
	// association, which the association owns. Datagrams are taken as on
	// PacketConn, except that when neither the control connection nor the
	// request gives the client's IP address, the first source that sends
	// becomes the client.
	ListenUDP func(ctx context.Context, req *Request) (net.PacketConn, error)
	// UDPAddr returns the address a UDP ASSOCIATE reply tells the client to
	// send to, given the association's socket address; nil uses that address
	// with the control connection's local IP when it is unspecified.
	UDPAddr func(req *Request, socket net.Addr) Addr
	// DialPacket opens the outbound side of a UDP association; nil uses a new
	// UDP socket through NewPacketConn.
	DialPacket func(ctx context.Context, req *Request) (PacketConn, error)
	// AllowPacket, if set, drops the client datagrams to destinations it
	// rejects. Like Allow, it sees IP addresses as IP and other names
	// unresolved, so a policy on IP addresses must also check the addresses
	// that names resolve to, in a DialPacket whose PacketConn resolves them.
	AllowPacket func(req *Request, dst Addr) bool
	// OnError, if set, receives the errors that end connections accepted by
	// Serve, with the client connection, and those that drop UDP datagrams,
	// with the association's control connection. It is called from serving
	// goroutines and must be safe for concurrent use. The package does not
	// log; route errors to a logger such as log/slog here.
	OnError   func(c net.Conn, err error)
	listeners map[net.Listener]struct{}
	conns     map[net.Conn]struct{}
	shared    *udpRelay
	cancel    context.CancelFunc
	// Auth lists the accepted authentication methods in order of
	// preference. Nil means NoAuth. An authenticator for MethodNoAuth, which
	// may check the connection itself (its address or TLS state), also
	// decides on SOCKS4 clients and on SOCKS5 clients whose method lists
	// match no authenticator.
	Auth []Authenticator
	// HandshakeTimeout bounds the negotiation and request;
	// DefaultHandshakeTimeout if not positive.
	HandshakeTimeout time.Duration
	// DialTimeout bounds Dial; DefaultDialTimeout if not positive.
	DialTimeout time.Duration
	// UDPIdleTimeout ends a UDP association without datagrams in either
	// direction, or without a first datagram, for this long, and closes its
	// control connection; DefaultUDPIdleTimeout if not positive.
	UDPIdleTimeout time.Duration
	// UDPQueue is how many client datagrams an association buffers, 128 if
	// not positive.
	UDPQueue int
	mu       sync.Mutex
	// SOCKS4 also serves SOCKS4 and SOCKS4a CONNECT requests. They carry no
	// credentials, so they are refused unless Auth has a MethodNoAuth
	// authenticator, which then runs for them.
	SOCKS4 bool
	// UDPOutlivesControl keeps a UDP association after its control
	// connection closes, until UDPIdleTimeout, for clients that close or
	// half-close it right after the reply. By default the association ends
	// with the control connection, as RFC 1928 specifies.
	UDPOutlivesControl bool
	closed             bool
}

// Serve accepts connections on l and serves each in its own goroutine. It
// returns ErrServerClosed after Close, or the error that ended Accept.
// Temporary Accept errors, such as timeouts and running out of file
// descriptors (EMFILE, ENFILE), are retried with a growing delay.
func (s *Server) Serve(l net.Listener) error {
	if !s.track(l, true) {
		return ErrServerClosed
	}
	defer s.track(l, false)
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if s.isClosed() {
				return ErrServerClosed
			}
			if temporary(err) {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		go func() {
			if err := s.ServeConn(c); err != nil {
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

// ServeConn serves one client connection and closes it. It returns the error
// that ended the exchange, if any.
func (s *Server) ServeConn(c net.Conn) error {
	if !s.trackConn(c, true) {
		_ = c.Close()
		return ErrServerClosed
	}
	defer s.trackConn(c, false)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithCancel(s.baseContext())
	defer cancel()

	_ = c.SetDeadline(time.Now().Add(positive(s.HandshakeTimeout, DefaultHandshakeTimeout)))
	var first [1]byte
	if _, err := io.ReadFull(c, first[:]); err != nil {
		return err
	}
	var req *Request
	var err error
	switch {
	case first[0] == Version:
		req, err = s.handshake5(ctx, c, first[:])
	case first[0] == Version4 && s.SOCKS4:
		req, err = s.handshake4(ctx, c, first[:])
	default:
		return ErrVersion
	}
	if err != nil {
		return err
	}
	_ = c.SetDeadline(time.Time{})

	if s.Allow != nil {
		if err := s.Allow(ctx, req); err != nil {
			code := ReplyFor(err)
			if code == ReplyGeneralFailure {
				code = ReplyNotAllowed
			}
			_ = s.reply(req, code, Addr{})
			return err
		}
	}
	switch req.Command {
	case CmdConnect:
		return s.connect(ctx, req)
	case CmdUDPAssociate:
		if s.PacketConn != nil || s.ListenUDP != nil {
			return s.associate(ctx, req)
		}
	}
	_ = s.reply(req, ReplyCommandNotSupported, Addr{})
	return &ReplyError{Reply: ReplyCommandNotSupported}
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
	return &Request{Version: 5, Command: cmd, Dst: dst, User: user, Conn: c}, nil
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

// reply writes a reply in the request's protocol version.
func (s *Server) reply(req *Request, code Reply, bound Addr) error {
	if req.Version == 4 {
		return WriteReply4(req.Conn, code, bound)
	}
	return WriteReply(req.Conn, code, bound)
}

func (s *Server) connect(ctx context.Context, req *Request) error {
	dialCtx, cancel := context.WithTimeout(ctx, positive(s.DialTimeout, DefaultDialTimeout))
	target, err := s.dial(dialCtx, req)
	cancel()
	if err != nil {
		_ = s.reply(req, ReplyFor(err), Addr{})
		return err
	}
	bound := AddrFromNetAddr(target.LocalAddr())
	if s.ConnectAddr != nil {
		bound = s.ConnectAddr(req, target)
	}
	if err := s.reply(req, ReplySucceeded, bound); err != nil {
		_ = target.Close()
		return err
	}
	if s.Relay != nil {
		return s.Relay(ctx, req, req.Conn, target)
	}
	_, _, err = netx.Relay(req.Conn, target)
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
	}
	return s.ctx
}

// Close stops the listeners passed to Serve, closes the connections being
// served and ends the UDP associations, closing PacketConn. Serve then
// returns ErrServerClosed.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	var errs []error
	for l := range s.listeners {
		errs = append(errs, l.Close())
	}
	for c := range s.conns {
		_ = c.Close()
	}
	shared := s.shared
	s.mu.Unlock()
	if shared != nil {
		errs = append(errs, shared.close())
	} else if s.PacketConn != nil {
		errs = append(errs, s.PacketConn.Close())
	}
	return errors.Join(errs...)
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) track(l net.Listener, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed {
			return false
		}
		if s.listeners == nil {
			s.listeners = make(map[net.Listener]struct{})
		}
		s.listeners[l] = struct{}{}
		return true
	}
	delete(s.listeners, l)
	return true
}

func (s *Server) trackConn(c net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed {
			return false
		}
		if s.conns == nil {
			s.conns = make(map[net.Conn]struct{})
		}
		s.conns[c] = struct{}{}
		return true
	}
	delete(s.conns, c)
	return true
}

func (s *Server) onError(c net.Conn, err error) {
	if s.OnError != nil {
		s.OnError(c, err)
	}
}

func positive(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
