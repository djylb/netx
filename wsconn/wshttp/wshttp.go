// Package wshttp connects package wsconn to net/http: Upgrade and Serve
// turn the requests of a handler into WebSocket connections, and Dialer
// dials WebSocket over HTTP/2. It is a package of its own so that programs
// that use wsconn without net/http do not link net/http.
//
// # HTTP/2
//
// WebSocket over HTTP/2 (RFC 8441) runs on an extended CONNECT stream,
// many to one connection. net/http's server accepts extended CONNECT only
// when the program starts with GODEBUG=http2xconnect=1 in its environment
// (net/http reads it once, at initialisation; a //go:debug directive does
// not set it): only then does it announce SETTINGS_ENABLE_CONNECT_PROTOCOL,
// and an extended CONNECT reaches the handler as a CONNECT request whose
// header holds ":protocol". Without it every WebSocket request is HTTP/1.1
// and Upgrade hijacks it. net/http's own client cannot send extended
// CONNECT, as it refuses the ":protocol" field; Dialer takes an HTTP/2
// RoundTripper that can.
//
// A connection over an HTTP/2 stream lives only as long as the handler:
// once the handler returns, net/http ends the stream, and using the
// connection after that would use the ResponseWriter after its handler
// returned, which net/http answers with a panic. Serve keeps the handler
// running until the connection is closed; with Upgrade, wait for Done(c)
// before returning. Deadlines on a stream do not leave it usable, as they
// do on a TCP connection: on the server, as net/http implements them, an
// expired write deadline resets the stream and an expired read deadline
// fails its reads for good; on the client, Dialer's streams are reset
// when either expires.
package wshttp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/wsconn"
)

// Upgrade upgrades the request r to a WebSocket connection, as
// wsconn.CheckRequest and Handshake.Accept do: a request that it refuses
// is answered through w with its status and an error is returned.
//
// An HTTP/1.1 request is answered with 101 and hijacked: the connection
// then belongs to the returned Conn, or is closed after a failure, the
// bytes that the client sent after the request stay readable, and the
// handler may return while the connection is in use. An HTTP/2 extended
// CONNECT is answered with 200 and the connection runs over its stream,
// for which the handler must not return before Done(c) is closed; Serve
// does that. The fields of w.Header() and of opts.Header go out with the
// response. The request's context bounds the HTTP/1.1 response write, as
// does opts.HandshakeTimeout. opts may be nil.
//
// r.Header and r.Host are seen by opts.CheckOrigin as the fields of a
// wsconn request, with Host first.
func Upgrade(w http.ResponseWriter, r *http.Request, opts *wsconn.ServerOptions) (*wsconn.Conn, error) {
	if opts == nil {
		opts = &wsconn.ServerOptions{}
	}
	extended := r.ProtoMajor == 2 && r.Method == http.MethodConnect && r.Header.Get(":protocol") != ""
	if r.ProtoMajor != 1 && !extended {
		http.Error(w, "WebSocket needs HTTP/1.1, or HTTP/2 extended CONNECT", http.StatusHTTPVersionNotSupported)
		return nil, &wsconn.HandshakeError{Status: http.StatusHTTPVersionNotSupported, Msg: r.Proto + " request"}
	}
	if !extended && len(w.Header()) > 0 {
		// The fields set on w go out with the 101 response.
		o := *opts
		o.Header = make(httphead.Header, 0, len(opts.Header)+len(w.Header()))
		o.Header = append(o.Header, opts.Header...)
		for name, vs := range w.Header() {
			for _, v := range vs {
				o.Header = append(o.Header, httphead.Field{Name: name, Value: v})
			}
		}
		opts = &o
	}
	req := Request(r)
	hs, err := wsconn.CheckRequest(req, opts)
	if err != nil {
		var he *wsconn.HandshakeError
		if errors.As(err, &he) {
			if he.Status == http.StatusUpgradeRequired {
				if !extended {
					w.Header().Set("Upgrade", "websocket")
				}
				w.Header().Set("Sec-WebSocket-Version", "13")
			}
			http.Error(w, he.Msg, he.Status)
		}
		return nil, err
	}
	if extended {
		return acceptStream(w, r, hs)
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "connection cannot be upgraded", http.StatusInternalServerError)
		return nil, err
	}
	var br *bufio.Reader
	if brw != nil {
		if brw.Writer.Buffered() > 0 {
			_ = brw.Flush()
		}
		br = brw.Reader
	}
	return hs.Accept(r.Context(), conn, br)
}

// Serve upgrades r as Upgrade does and runs fn with the connection on the
// handler's goroutine; when fn returns, it closes the connection, and on
// HTTP/2 waits for the stream to be done, so that the handler cannot
// return while the connection is in use. It returns Upgrade's error, after
// which fn is not called.
func Serve(w http.ResponseWriter, r *http.Request, opts *wsconn.ServerOptions, fn func(*wsconn.Conn)) error {
	c, err := Upgrade(w, r, opts)
	if err != nil {
		return err
	}
	defer func() {
		_ = c.Close()
		<-Done(c)
	}()
	fn(c)
	return nil
}

// closedChan is the Done of connections that do not hold their handler.
var closedChan = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// Done returns a channel that is closed once c no longer uses its
// handler's ResponseWriter: for a connection over an HTTP/2 stream once it
// is closed, also by the peer or the end of the HTTP/2 connection, after
// which the handler may return; for any other connection a closed channel.
func Done(c *wsconn.Conn) <-chan struct{} {
	if sc, ok := c.NetConn().(*streamConn); ok {
		return sc.done
	}
	return closedChan
}

// acceptStream answers an extended CONNECT with 200 and returns the
// connection over its stream.
func acceptStream(w http.ResponseWriter, r *http.Request, hs *wsconn.Handshake) (*wsconn.Conn, error) {
	h := w.Header()
	for _, f := range hs.ResponseHeader() {
		if !httphead.ValidFieldName(f.Name) || !httphead.ValidFieldValue(f.Value) {
			http.Error(w, "invalid response field", http.StatusInternalServerError)
			return nil, errors.New("wshttp: invalid response field " + strconv.Quote(f.Name))
		}
		h.Add(f.Name, f.Value)
	}
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return nil, err
	}
	sc := &streamConn{w: w, rc: rc, body: r.Body, remote: remoteAddr(r.RemoteAddr), done: make(chan struct{})}
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		sc.local = a
	}
	// The end of the stream or of the HTTP/2 connection ends the
	// connection while the handler still runs.
	// The callback may run at once, for a context already done; it waits in
	// Close for life, which is held until stop is set.
	sc.life.Lock()
	sc.stop = context.AfterFunc(r.Context(), func() { _ = sc.Close() })
	sc.life.Unlock()
	return hs.NewConn(sc, nil), nil
}

// remoteAddr parses a request's RemoteAddr, keeping its port.
func remoteAddr(s string) net.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	return strAddr(s)
}

// strAddr is an address net/http gave as a string only.
type strAddr string

func (a strAddr) Network() string { return "tcp" }
func (a strAddr) String() string  { return string(a) }

// streamConn is a net.Conn over the stream of an extended CONNECT on the
// server: it reads the request body and writes the response.
type streamConn struct {
	w      http.ResponseWriter
	rc     *http.ResponseController
	body   io.ReadCloser
	local  net.Addr
	remote net.Addr
	stop   func() bool // set under life

	// life is held for reading while the ResponseWriter is used, and for
	// writing by Close, after which it is not used.
	life    sync.RWMutex
	closed  bool
	closing atomic.Bool
	writing atomic.Bool
	once    sync.Once
	done    chan struct{}
}

func (c *streamConn) Read(p []byte) (int, error) { return c.body.Read(p) }

func (c *streamConn) Write(p []byte) (int, error) {
	c.life.RLock()
	defer c.life.RUnlock()
	// writing is set before closing is checked, and Close sets closing
	// before it checks writing, so that one of them sees the other.
	c.writing.Store(true)
	defer c.writing.Store(false)
	if c.closed || c.closing.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.w.Write(p)
	if err == nil {
		err = c.rc.Flush()
	}
	return n, err
}

// Close ends the connection: it unblocks reads and a blocked write, which
// resets the stream, waits for the write to return and lets the handler
// return.
func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.closing.Store(true)
		if c.writing.Load() {
			_ = c.rc.SetWriteDeadline(time.Unix(1, 0))
		}
		_ = c.body.Close()
		c.life.Lock()
		c.closed = true
		stop := c.stop
		c.life.Unlock()
		if stop != nil {
			stop()
		}
		close(c.done)
	})
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.life.RLock()
	defer c.life.RUnlock()
	if c.closed {
		return net.ErrClosed
	}
	return c.rc.SetReadDeadline(t)
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	c.life.RLock()
	defer c.life.RUnlock()
	if c.closed {
		return net.ErrClosed
	}
	return c.rc.SetWriteDeadline(t)
}

// Request returns r as a wsconn request: its method, its request-target,
// its version and its fields, starting with Host.
func Request(r *http.Request) *httphead.Request {
	n := 1
	for _, vs := range r.Header {
		n += len(vs)
	}
	h := make(httphead.Header, 0, n)
	if r.Host != "" {
		h = append(h, httphead.Field{Name: "Host", Value: r.Host})
	}
	for name, vs := range r.Header {
		for _, v := range vs {
			h = append(h, httphead.Field{Name: name, Value: v})
		}
	}
	target := r.RequestURI
	if target == "" && r.URL != nil {
		target = r.URL.RequestURI()
	}
	return &httphead.Request{
		Method: r.Method,
		Target: target,
		Proto:  "HTTP/" + strconv.Itoa(r.ProtoMajor) + "." + strconv.Itoa(r.ProtoMinor),
		Minor:  r.ProtoMinor,
		Header: h,
	}
}
