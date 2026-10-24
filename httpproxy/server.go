package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/internal/serve"
)

// ErrServerClosed is returned by Serve after Close.
var ErrServerClosed = errors.New("httpproxy: server closed")

// Defaults of a Server.
const (
	DefaultHandshakeTimeout   = 10 * time.Second
	DefaultDialTimeout        = 10 * time.Second
	DefaultIdleTimeout        = 2 * time.Minute
	DefaultMaxHeaderBytes     = 64 << 10
	DefaultIdleConnTimeout    = 90 * time.Second
	DefaultMaxIdleConnsPerKey = 16
	DefaultMaxIdleConns       = 1024
)

// Request is a request read by a Server.
type Request struct {
	// Method is the method as sent, such as "GET", or "CONNECT", which is
	// also taken in other cases.
	Method string
	// Target is the request-target as sent: the authority of a CONNECT
	// request, such as "example.com:443", an absolute URI, such as
	// "http://example.com/path", for a request to forward, or a path, or
	// "*", for a request that is not a proxy request.
	Target string
	// Proto is the protocol version as sent, such as "HTTP/1.1".
	Proto string
	// Header holds the fields of the request as sent.
	Header httphead.Header
	// Dst is the destination: the authority of a CONNECT request, with port
	// 443 when it names none, the host of an absolute http URI, with port 80
	// when it names none, or what Intercept returned for a request for a
	// path; the zero Addr for other requests. It is normalised as described
	// at netx.Addr: every form of an IP address as IP, names in lower case
	// and unresolved, with a trailing dot kept, so that a policy on names
	// must also match "localhost." for "localhost", and a policy on IP
	// addresses must also check the addresses that names resolve to, in
	// Dial. IPv6 zones are dropped.
	Dst netx.Addr
	// User is the identity returned by the authenticator, empty without
	// authentication.
	User string
	// Conn is the client's connection, positioned after the request head:
	// its reads return the bytes that the server buffered after the head,
	// and then the connection's own, and writes go to the client. Only
	// Handle may read or write it, to serve the request itself, and only
	// until it returns. Its NetConn method returns the connection being
	// served, which netx.ConnAs also finds, for its type, such as a
	// *tls.Conn and its connection state.
	Conn net.Conn

	conn      reqConn
	head      string
	tgt       httphead.Target
	minor     int // the minor version, 0 or 1
	length    int64
	body      httphead.Framing
	keepAlive bool // the client keeps the connection after this request
	upgrade   bool // a protocol upgrade passed on, such as to WebSocket
	intercept bool // a request for a path forwarded to what Intercept said
	result    Result
}

// RawHead returns the request head as the client sent it, for handing the
// connection to a server of origin requests with Handle, ahead of what
// Conn returns.
func (r *Request) RawHead() string { return r.head }

// Result is how a request ended, for Server.OnDone.
type Result struct {
	// Status is the status code of the final response sent to the client:
	// 200 for an established tunnel, the target's code for a forwarded
	// request, or the code of a refusal; 0 when none was sent.
	Status int
	// ToTarget and ToClient are the bytes relayed to the target and to the
	// client: those of the tunnel, or the heads and bodies of a forwarded
	// request and its responses, as they went over the connections.
	ToTarget, ToClient int64
	// Reused tells that a forwarded request went over a kept connection to
	// its target.
	Reused bool
	// Start is when the request head was read.
	Start time.Time
	// Err is the error that ended the request, if any, as OnError gets it.
	Err error
}

// reqConn is the connection of a request, which reads through the server's
// buffer and records that it was used.
type reqConn struct {
	net.Conn
	br   *bufio.Reader
	used bool
}

func (c *reqConn) Read(b []byte) (int, error) {
	c.used = true
	return c.br.Read(b)
}

func (c *reqConn) Write(b []byte) (int, error) {
	c.used = true
	return c.Conn.Write(b)
}

// NetConn returns the client's connection; see netx.InnermostConn.
func (c *reqConn) NetConn() net.Conn { return c.Conn }

// Server is an HTTP/1.x proxy server. It serves CONNECT requests with a
// tunnel to their destination, and forwards requests whose target is an
// absolute http URI, such as "GET http://example.com/ HTTP/1.1", to their
// destination, streaming bodies in both directions, also across requests to
// different hosts on one client connection, and keeping connections to
// targets for later requests. It answers OPTIONS * itself and other
// requests for a path with 400 Bad Request, unless Intercept forwards them
// or Handle serves them.
//
// Every field is optional: the zero Server accepts any client and dials
// directly, an open proxy, as the zero socks5.Server is. Serve it only to
// trusted clients, or set Auth and Allow. The server sets no limit on the
// connections of a client, each of which holds a few sockets and buffers;
// bound them in the listener passed to Serve or in Allow. Once a request
// head is read, nothing bounds a tunnel or a forwarded exchange, a slow
// request body or a target that does not answer, but ResponseHeaderTimeout
// and an idle timeout from RelayOptions, such as netx.WithRelayIdleTimeout,
// which servers open to untrusted clients should set.
type Server struct {
	// Auth lists the accepted authentication schemes, in the order of the
	// challenges of a 407 reply. Nil means NoAuth. A request whose
	// Proxy-Authorization field names a scheme of the list is decided by its
	// authenticator; one without credentials, or with another scheme, by the
	// NoAuth authenticator ("" scheme) when the list has one, which may
	// check the connection itself, and otherwise answered with 407. Proxy
	// requests are authenticated, those with a CONNECT or absolute URI
	// target, and those that Intercept forwards; others reach Handle
	// without a User. Credentials that passed are not checked again for the
	// later requests of the connection that carry the same field, as a
	// SOCKS client is authenticated once per connection. Only Basic is
	// built in; schemes such as Digest can be added as Authenticators,
	// while those that authenticate a connection rather than requests,
	// such as NTLM, are not supported.
	Auth []Authenticator

	// Allow is called for each request after authentication. A non-nil
	// error refuses it with the error's StatusFor code, or 403 Forbidden
	// when that is 502. See Request.Dst for what it sees of the
	// destination; CONNECT to any port is allowed unless Allow refuses it.
	Allow func(ctx context.Context, req *Request) error
	// OnError, if set, receives the errors that end requests and
	// connections accepted by Serve, with the client connection: refused
	// requests as a *StatusError holding the status sent and the cause,
	// failed dials and relays, malformed requests and handshake timeouts,
	// but not ErrAuthRequired, the first step of authentication, nor the
	// end of an idle connection. It is called from serving goroutines and
	// must be safe for concurrent use. Errors that come once Close is
	// called are not reported. The package does not log.
	OnError func(c net.Conn, err error)
	// OnDone, if set, is called once for each request when it ends, with
	// what it sent and relayed, for an access log or accounting; refused
	// and failed requests included. It is called from serving goroutines
	// and must be safe for concurrent use.
	OnDone func(req *Request, res Result)

	// Handle, if set, is called for each request after Allow and before the
	// built-in handling, so that a server can serve requests itself, such
	// as origin requests for a path on the same port, or take over CONNECT
	// for some destinations, while Serve, Shutdown and ActiveConns still
	// cover their connections. When it returns handled true, or has read or
	// written req.Conn whatever it returns, it has served the request: the
	// connection is closed when it returns, and its error ends the
	// exchange. Otherwise a non-nil error refuses the request with the
	// error's StatusFor code, and nil leaves it to the built-in handling.
	// ctx ends, and the connection is closed, when Close is called.
	Handle func(ctx context.Context, req *Request) (handled bool, err error)
	// Intercept, if set, is called for each request for a path, as clients
	// send to the origin, and returning true forwards the request to the
	// address it returns, which becomes Request.Dst, as a request to
	// forward, authenticated and allowed as one. It serves clients whose
	// connections are redirected to the proxy without their knowing:
	// HostDst returns the destination that the Host field names, and for a
	// redirected connection the original destination can be read from it.
	Intercept func(req *Request) (netx.Addr, bool)

	// Dial connects to req.Dst for a CONNECT request or a request to
	// forward; nil dials it directly; an IP policy on resolved addresses
	// belongs here (see Request.Dst). ctx is bounded by DialTimeout. The
	// error's StatusFor code is sent to the client, so return a
	// *StatusError to choose it. A connection for forwarded requests is
	// kept for later requests with the same reuse key (see ReuseKey), which
	// do not call Dial.
	Dial func(ctx context.Context, req *Request) (net.Conn, error)
	// RelayOptions, if set, returns options for the netx.Relay between the
	// client and the target of each CONNECT tunnel and each forwarded
	// request, such as netx.WithRelayFlows for the allowance or byte count
	// of req.User, netx.WithRelayGroup or netx.WithRelayIdleTimeout. They
	// follow netx.WithRelayHalfClose, which the relay always has. A
	// forwarded request's relay carries the request head and body to the
	// target and the responses to the client, so its flows count and pace
	// those, and its idle timeout also bounds the wait for a response. The
	// relays end when Close is called.
	RelayOptions func(req *Request) []netx.RelayOption

	// ReuseKey, if set, returns the key under which the connection of a
	// forwarded request is kept for later requests, which share kept
	// connections only with requests of the same key, or false to use a
	// connection for this request alone. Nil keys connections by Dst and
	// User, which suits a Dial that depends on no more; one that depends on
	// other parts of the request, such as a field, must have a ReuseKey
	// that holds them.
	ReuseKey func(req *Request) (key string, ok bool)
	// MaxIdleConnsPerKey bounds the kept connections of one key;
	// DefaultMaxIdleConnsPerKey if 0, and none are kept if negative.
	MaxIdleConnsPerKey int
	// MaxIdleConns bounds the kept connections of all keys;
	// DefaultMaxIdleConns if 0, and unbounded if negative.
	MaxIdleConns int
	// IdleConnTimeout closes a kept connection that served no request for
	// this long; DefaultIdleConnTimeout if not positive.
	IdleConnTimeout time.Duration

	// Via, if not empty, is the pseudonym that the server adds to the Via
	// field of forwarded requests and responses, as "1.1 " + Via (RFC
	// 9110, section 7.6.3).
	Via string
	// ForwardHeader, if set, is called with the header of each request
	// forwarded to req.Dst, after the fields for this connection only
	// (RFC 9110, section 7.6.1), Proxy-Authorization among them, are
	// removed, to add fields such as X-Forwarded-For or Forwarded, or
	// remove others. The server then adds Host, the fields that delimit the
	// body and Connection itself, so the hook cannot change how the body is
	// read; fields that are not valid are refused with 500.
	ForwardHeader func(req *Request, h *httphead.Header)
	// ResponseHeader, if set, is called likewise with the status code and
	// header of each response sent back to the client, interim 1xx
	// responses among them.
	ResponseHeader func(req *Request, status int, h *httphead.Header)

	// HandshakeTimeout bounds reading each request head and authenticating
	// it; DefaultHandshakeTimeout if not positive.
	HandshakeTimeout time.Duration
	// DialTimeout bounds Dial; DefaultDialTimeout if not positive.
	DialTimeout time.Duration
	// IdleTimeout bounds the wait for the next request on a kept-alive
	// client connection; DefaultIdleTimeout if not positive.
	IdleTimeout time.Duration
	// ResponseHeaderTimeout, if positive, bounds the wait for the head of a
	// forwarded request's response once the request has been sent; the
	// client then gets 504 Gateway Timeout.
	ResponseHeaderTimeout time.Duration
	// MaxHeaderBytes bounds a request or response head, and a trailer
	// section; DefaultMaxHeaderBytes if not positive. A larger request head
	// is answered with 431 Request Header Fields Too Large, a larger
	// response head with 502 Bad Gateway.
	MaxHeaderBytes int

	life     serve.Tracker
	poolOnce sync.Once
	pool     pool
}

// ListenAndServe listens on the TCP address addr, ":8080" when empty, and
// serves the connections as Serve does. It returns ErrServerClosed after
// Shutdown or Close, or the error that ended listening or accepting.
func (s *Server) ListenAndServe(addr string) error {
	if addr == "" {
		addr = ":8080"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve accepts connections on l and serves each with ServeConn, under a
// context that Close cancels, in its own goroutine. It returns
// ErrServerClosed after Shutdown or Close, which close l, or the error that
// ended Accept. Accept errors for which netx.IsAcceptRetryable reports
// true are retried as netx.Accept does.
func (s *Server) Serve(l net.Listener) error {
	return s.life.Serve(l, ErrServerClosed, netx.Accept, s.serveConn, s.onError)
}

// ServeConn serves the requests of one client connection, which may be any
// net.Conn, such as a TLS connection or a netx.PrefixConn holding bytes
// already read from it, and closes it. ctx ending ends the connection, as
// Close does. It returns the error that ended the connection, if any,
// which is also passed to OnError for each request that failed before it
// was ended. The connection counts in ActiveConns until ServeConn returns.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) error {
	if !s.life.TrackConn(&c, true) {
		_ = c.Close()
		return ErrServerClosed
	}
	defer s.life.TrackConn(&c, false)
	return s.serveConn(ctx, c)
}

// Shutdown stops the server gracefully: it closes the listeners passed to
// Serve, which then returns ErrServerClosed, makes ServeConn refuse new
// connections, and waits until the connections being served end; then it
// calls Close. Kept-alive connections end when idle, after the request in
// progress. When ctx ends first, Close ends the remaining connections and
// Shutdown returns ctx's error too.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.life.Shutdown(ctx, s.Close)
}

// ActiveConns returns the number of connections being served by Serve and
// ServeConn.
func (s *Server) ActiveConns() int { return s.life.ActiveConns() }

// IdleConns returns the number of connections to targets kept for later
// requests.
func (s *Server) IdleConns() int { return s.targets().idleConns() }

// Close stops the listeners passed to Serve, closes the connections being
// served and those kept to targets, and ends the relays and hooks in
// progress. Serve then returns ErrServerClosed. Later calls, also of
// Shutdown, wait until the first has finished and return nil.
func (s *Server) Close() error {
	return s.life.Close(func() error {
		s.targets().close()
		return nil
	})
}

// targets returns the pool of kept connections, set up on first use.
func (s *Server) targets() *pool {
	s.poolOnce.Do(func() {
		s.pool.perKey = s.MaxIdleConnsPerKey
		if s.pool.perKey == 0 {
			s.pool.perKey = DefaultMaxIdleConnsPerKey
		}
		s.pool.total = s.MaxIdleConns
		if s.pool.total == 0 {
			s.pool.total = DefaultMaxIdleConns
		}
		s.pool.timeout = positive(s.IdleConnTimeout, DefaultIdleConnTimeout)
	})
	return &s.pool
}

// onError passes err to OnError unless Close was called, which ends the
// connections whatever they were doing, or err is ErrAuthRequired.
func (s *Server) onError(c net.Conn, err error) {
	if s.OnError != nil && !s.life.IsClosed() && !errors.Is(err, ErrAuthRequired) {
		s.OnError(c, err)
	}
}

func positive[T time.Duration | int](v, def T) T {
	if v > 0 {
		return v
	}
	return def
}

// readerSize is the buffer of each connection, client or target, which a
// chunk-size line must fit.
const readerSize = 4 << 10

var readers = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, readerSize) }}

func getReader(r io.Reader) *bufio.Reader {
	br := readers.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

func putReader(br *bufio.Reader) {
	br.Reset(nil)
	readers.Put(br)
}

// serverConn is the state of one client connection.
type serverConn struct {
	s  *Server
	c  net.Conn
	br *bufio.Reader
	// Buffers reused across requests: the request head read, the head
	// written to the target or a reply, the response head read and the
	// response head written to the client.
	headBuf, outBuf, respBuf, respOut []byte
	// The Proxy-Authorization value that passed, and its identity.
	authValue, authUser string
	// linger is set when the connection is closed after a reply with
	// request bytes perhaps unread, which closing at once could turn into a
	// reset that destroys the reply.
	linger bool
	x      exchange
}

// maxKeptBuf bounds the buffers kept between requests.
const maxKeptBuf = 16 << 10

func (sc *serverConn) trimBuffers() {
	for _, b := range [...]*[]byte{&sc.headBuf, &sc.outBuf, &sc.respBuf, &sc.respOut, &sc.x.reqStream.trailer, &sc.x.respStream.trailer} {
		if cap(*b) > maxKeptBuf {
			*b = nil
		}
	}
}

// serveConn serves a tracked connection and closes it.
func (s *Server) serveConn(ctx context.Context, c net.Conn) error {
	defer func() { _ = c.Close() }()
	ctx, cancel, ok := s.life.Bind(ctx)
	if !ok {
		return ErrServerClosed
	}
	defer cancel()
	// Ending ctx, as Close does, ends the connection whatever it waits for.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	sc := &serverConn{s: s, c: c, br: getReader(c)}
	defer func() {
		if sc.linger {
			sc.lingerClose()
		}
		if sc.br != nil {
			putReader(sc.br)
		}
	}()
	for first := true; ; first = false {
		req, err := sc.readRequest(first)
		if err != nil {
			if errors.Is(err, errIdleEnd) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		keep, err := sc.serveRequest(ctx, req)
		// Shutdown lets the request in progress finish, but not the next.
		if !keep || ctx.Err() != nil || s.life.Stopping() {
			return err
		}
		if err != nil {
			s.onError(c, err)
		}
		sc.trimBuffers()
	}
}

// Bounds of the read that keeps a connection open for a while after a
// reply that ends it, while the client may still be sending.
const (
	lingerTimeout = 500 * time.Millisecond
	lingerBytes   = 256 << 10
)

// lingerClose shuts down the writing side of the connection, so that the
// client sees the end after the reply, and reads what the client still
// sends for a while, so that closing with unread data does not reset the
// connection before the client has read the reply.
func (sc *serverConn) lingerClose() {
	if closeWrite(sc.c) != nil {
		return
	}
	_ = sc.c.SetReadDeadline(time.Now().Add(lingerTimeout))
	var r io.Reader = sc.c
	if sc.br != nil {
		r = sc.br
	}
	_, _ = io.CopyN(io.Discard, r, lingerBytes)
}

// errIdleEnd ends a connection idle between requests, which is no failure.
var errIdleEnd = errors.New("idle connection ended")

// readRequest reads and parses the next request head under the handshake
// timeout, after waiting up to the idle timeout for it to start when it is
// not the first. A malformed request is answered before it returns.
func (sc *serverConn) readRequest(first bool) (*Request, error) {
	s := sc.s
	if !first {
		// Idle: Shutdown ends the wait, which the client of a kept-alive
		// connection is ready for.
		stop := sc.readDeadline(positive(s.IdleTimeout, DefaultIdleTimeout))
		drained := context.AfterFunc(s.life.DrainContext(), func() { _ = sc.c.SetReadDeadline(time.Unix(1, 0)) })
		_, err := sc.br.Peek(1)
		if !drained() {
			return nil, errIdleEnd
		}
		stop()
		if err != nil {
			if err == io.EOF || netx.IsTimeout(err) || isClosedRead(err) {
				return nil, errIdleEnd
			}
			return nil, err
		}
	}
	stop := sc.readDeadline(positive(s.HandshakeTimeout, DefaultHandshakeTimeout))
	var err error
	sc.headBuf, err = httphead.Read(sc.br, sc.headBuf, positive(s.MaxHeaderBytes, DefaultMaxHeaderBytes))
	stop()
	if err != nil {
		switch {
		case err == io.EOF:
			// Closed before a request, also after a Peek that saw a byte
			// of empty lines only.
			return nil, errIdleEnd
		case errors.Is(err, httphead.ErrTooLarge):
			err = headStatus(err)
			sc.reply(nil, 431, nil, true)
		case netx.IsTimeout(err):
			err = os.ErrDeadlineExceeded
		}
		return nil, err
	}
	req, err := sc.parseRequest(string(sc.headBuf))
	if err != nil {
		sc.reply(nil, StatusFor(err), nil, true)
		return nil, err
	}
	return req, nil
}

// readDeadline bounds the reads of the connection for d, and returns a
// function that lifts the bound. A connection without deadlines is closed
// instead when d passes.
func (sc *serverConn) readDeadline(d time.Duration) func() {
	if err := sc.c.SetReadDeadline(time.Now().Add(d)); err == nil {
		return func() { _ = sc.c.SetReadDeadline(time.Time{}) }
	}
	t := time.AfterFunc(d, func() { _ = sc.c.Close() })
	return func() { t.Stop() }
}

// serveRequest serves req and reports whether the connection serves
// another request, and calls OnDone.
func (sc *serverConn) serveRequest(ctx context.Context, req *Request) (bool, error) {
	req.result.Start = time.Now()
	keep, err := sc.serveRequest1(ctx, req)
	if sc.s.OnDone != nil {
		req.result.Err = err
		sc.s.OnDone(req, req.result)
	}
	return keep, err
}

func (sc *serverConn) serveRequest1(ctx context.Context, req *Request) (bool, error) {
	s := sc.s
	if req.tgt.Form == httphead.OriginForm && s.Intercept != nil {
		if dst, ok := s.Intercept(req); ok {
			req.Dst, req.intercept = dst, true
		}
	}
	proxy := req.tgt.Form == httphead.AuthorityForm || req.tgt.Form == httphead.AbsoluteForm || req.intercept
	if proxy {
		if err := sc.authenticate(ctx, req); err != nil {
			code := StatusFor(err)
			if code == 502 && !errors.Is(err, ErrAuthRequired) && !errors.Is(err, ErrAuthFailed) {
				code = 503
			}
			keep := code == 407 && req.body == httphead.NoBody && req.keepAlive
			sc.reply(req, code, sc.challenges(code), !keep)
			return keep, refusal(code, err)
		}
	}
	if s.Allow != nil {
		if err := s.Allow(ctx, req); err != nil {
			code := StatusFor(err)
			if code == 502 {
				code = 403
			}
			return sc.refuse(req, code, err)
		}
	}
	if s.Handle != nil {
		handled, err := s.Handle(ctx, req)
		switch {
		case handled || req.conn.used:
			return false, err
		case err != nil:
			return sc.refuse(req, StatusFor(err), err)
		}
	}
	switch {
	case req.tgt.Form == httphead.AuthorityForm:
		return false, sc.connect(ctx, req)
	case req.Dst.IsZero() && req.tgt.Form == httphead.AbsoluteForm:
		return sc.refuse(req, 501, errors.New("unsupported scheme "+strconv.Quote(req.tgt.Scheme)))
	case proxy:
		if done, keep, err := sc.maxForwards(req); done {
			return keep, err
		}
		return sc.forward(ctx, req)
	case req.tgt.Form == httphead.AsteriskForm && req.Method == "OPTIONS":
		// About the proxy itself (RFC 9110, section 9.3.7).
		keep := req.body == httphead.NoBody && req.keepAlive
		sc.reply(req, 200, nil, !keep)
		return keep, nil
	}
	return sc.refuse(req, 400, errors.New("not a proxy request: "+strconv.Quote(req.Target)))
}

// maxForwards answers a TRACE or OPTIONS request whose Max-Forwards is 0
// itself, as its last recipient, and counts it down otherwise (RFC 9110,
// section 7.6.2). It reports whether it answered.
func (sc *serverConn) maxForwards(req *Request) (bool, bool, error) {
	if req.Method != "TRACE" && req.Method != "OPTIONS" || req.Header.Count("Max-Forwards") != 1 {
		return false, false, nil
	}
	v := req.Header.Get("Max-Forwards")
	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil {
		return false, false, nil // forwarded as it is
	}
	if n > 0 {
		h := append(httphead.Header(nil), req.Header...)
		h.Set("Max-Forwards", strconv.FormatUint(n-1, 10))
		req.Header = h
		return false, false, nil
	}
	keep := req.body == httphead.NoBody && req.keepAlive
	if req.Method == "OPTIONS" {
		sc.reply(req, 200, nil, !keep)
		return true, keep, nil
	}
	// TRACE echoes the request as received, without the credentials meant
	// for this proxy (RFC 9110, section 9.3.8).
	msg := append([]byte(nil), req.Method+" "+req.Target+" "+req.Proto+"\r\n"...)
	fields := append(httphead.Header(nil), req.Header...)
	fields.Del("Proxy-Authorization")
	msg, _ = fields.AppendTo(msg)
	msg = append(msg, "\r\n"...)
	b := appendStatusLine(sc.outBuf[:0], 200, "OK")
	b = append(b, "Content-Type: message/http\r\nContent-Length: "...)
	b = strconv.AppendInt(b, int64(len(msg)), 10)
	b = append(b, "\r\n"...)
	if !keep {
		b = append(b, "Connection: close\r\n"...)
	}
	b = append(b, "\r\n"...)
	b = append(b, msg...)
	sc.outBuf = b
	req.result.Status = 200
	req.result.ToClient = int64(len(b))
	_, err = sc.c.Write(b)
	if !keep {
		sc.linger = req.body != httphead.NoBody
	}
	return true, keep && err == nil, err
}

// refuse answers req with code and returns err as a *StatusError that
// carries code; the connection serves the next request when req has no
// body to skip.
func (sc *serverConn) refuse(req *Request, code int, err error) (bool, error) {
	keep := req.body == httphead.NoBody && req.keepAlive && req.tgt.Form != httphead.AuthorityForm
	sc.reply(req, code, nil, !keep)
	return keep, refusal(code, err)
}

// refusal returns err as a *StatusError that carries code, unless it is one.
func refusal(code int, err error) error {
	if se, ok := errors.AsType[*StatusError](err); ok && se.Code == code {
		return err
	}
	return &StatusError{Code: code, Err: err}
}

// challenges returns the challenges of a 407 reply.
func (sc *serverConn) challenges(code int) []string {
	if code != 407 {
		return nil
	}
	var cs []string
	for _, a := range sc.s.Auth {
		if a.Scheme() != "" {
			cs = append(cs, a.Challenge())
		}
	}
	return cs
}

// authenticate sets req.User from the authenticator that the request's
// credentials choose.
func (sc *serverConn) authenticate(ctx context.Context, req *Request) error {
	auth := sc.s.Auth
	if len(auth) == 0 {
		return nil
	}
	if req.Header.Count("Proxy-Authorization") > 1 {
		return badRequest("more than one Proxy-Authorization field")
	}
	value := req.Header.Get("Proxy-Authorization")
	if value != "" && value == sc.authValue {
		req.User = sc.authUser
		return nil
	}
	scheme, credentials, _ := strings.Cut(value, " ")
	var a Authenticator
	for _, candidate := range auth {
		if s := candidate.Scheme(); s != "" && strings.EqualFold(s, scheme) {
			a = candidate
			break
		}
	}
	if a == nil {
		// Without credentials, or with a scheme that no authenticator
		// takes: the NoAuth authenticator decides, if there is one.
		for _, candidate := range auth {
			if candidate.Scheme() == "" {
				a, credentials = candidate, ""
				break
			}
		}
	}
	if a == nil {
		if value == "" {
			return ErrAuthRequired
		}
		return ErrAuthFailed
	}
	hctx, cancel := context.WithTimeout(ctx, positive(sc.s.HandshakeTimeout, DefaultHandshakeTimeout))
	defer cancel()
	user, err := a.Authenticate(hctx, req, credentials)
	if err != nil {
		return err
	}
	req.User = user
	if a.Scheme() != "" {
		sc.authValue, sc.authUser = value, user
	}
	return nil
}

// reply sends a response without a body, with Proxy-Authenticate fields
// for challenges, closing the connection afterwards when closing is set.
// req is nil for a request that could not be parsed.
func (sc *serverConn) reply(req *Request, code int, challenges []string, closing bool) {
	b := sc.outBuf[:0]
	b = appendStatusLine(b, code, StatusText(code))
	for _, c := range challenges {
		b = append(b, "Proxy-Authenticate: "...)
		b = append(b, c...)
		b = append(b, "\r\n"...)
	}
	b = append(b, "Content-Length: 0\r\n"...)
	if closing {
		b = append(b, "Connection: close\r\n"...)
		// The rest of the request may be on its way.
		sc.linger = req == nil || req.body != httphead.NoBody || sc.br != nil && sc.br.Buffered() > 0
	}
	b = append(b, "\r\n"...)
	sc.outBuf = b
	if req != nil {
		req.result.Status = code
		req.result.ToClient += int64(len(b))
	}
	_, _ = sc.c.Write(b)
}

func appendStatusLine(b []byte, code int, reason string) []byte {
	b = append(b, "HTTP/1.1 "...)
	b = strconv.AppendInt(b, int64(code), 10)
	b = append(b, ' ')
	b = append(b, reason...)
	return append(b, "\r\n"...)
}

// connectReply answers a CONNECT request that the target accepted.
var connectReply = []byte("HTTP/1.1 200 Connection established\r\n\r\n")

// dial dials req.Dst under DialTimeout.
func (sc *serverConn) dial(ctx context.Context, req *Request) (net.Conn, error) {
	s := sc.s
	ctx, cancel := context.WithTimeout(ctx, positive(s.DialTimeout, DefaultDialTimeout))
	defer cancel()
	if s.Dial != nil {
		c, err := s.Dial(ctx, req)
		if err == nil && c == nil {
			err = errors.New("httpproxy: Dial returned no connection")
		}
		return c, err
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", req.Dst.String())
}

// connect serves a CONNECT request with a tunnel.
func (sc *serverConn) connect(ctx context.Context, req *Request) error {
	target, err := sc.dial(ctx, req)
	if err != nil {
		code := StatusFor(err)
		sc.reply(req, code, nil, true)
		return refusal(code, err)
	}
	// Ending ctx closes the client connection, which ends the reply, and
	// the relay, which closes both ends.
	defer func() { _ = target.Close() }()
	if _, err := sc.c.Write(connectReply); err != nil {
		return err
	}
	req.result.Status = 200
	// The bytes that the client sent right after the request, such as a TLS
	// ClientHello, belong to the tunnel; the relay sees through the
	// PrefixConn and splices the rest.
	client := sc.c
	if n := sc.br.Buffered(); n > 0 {
		b, _ := sc.br.Peek(n)
		client = netx.NewPrefixConn(sc.c, append([]byte(nil), b...))
	}
	putReader(sc.br)
	sc.br = nil
	opts := []netx.RelayOption{netx.WithRelayHalfClose()}
	if sc.s.RelayOptions != nil {
		opts = append(opts, sc.s.RelayOptions(req)...)
	}
	toTarget, toClient, err := netx.Relay(ctx, client, target, opts...)
	req.result.ToTarget, req.result.ToClient = toTarget, toClient+int64(len(connectReply))
	return err
}

// closeWrite shuts down the writing side of c, if it can.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}
