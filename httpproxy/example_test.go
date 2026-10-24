package httpproxy_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/httpproxy"
	"github.com/djylb/netx/proxydial"
	"github.com/djylb/netx/socks5"
	"github.com/djylb/netx/tlsconn"
)

// A proxy with a fixed account list and a policy, used by net/http for a
// forwarded request and by proxydial for a CONNECT tunnel.
func ExampleServer() {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from "+r.Host[:9])
	}))
	defer site.Close()

	s := &httpproxy.Server{
		Auth: []httpproxy.Authenticator{httpproxy.Credentials(map[string]string{"alice": "secret"})},
		Allow: func(_ context.Context, req *httpproxy.Request) error {
			if req.Dst.Port == 25 {
				return &httpproxy.StatusError{Code: 403, Err: errors.New("no mail")}
			}
			return nil
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	defer func() { _ = s.Close() }()

	proxyURL := &url.URL{Scheme: "http", Host: ln.Addr().String(), User: url.UserPassword("alice", "secret")}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get(site.URL)
	if err != nil {
		log.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Println(resp.Status, string(body))

	d := &proxydial.HTTPDialer{ProxyAddr: ln.Addr().String(), Username: "alice", Password: "secret"}
	_, err = d.DialContext(context.Background(), "tcp", "127.0.0.1:25")
	fmt.Println(err)
	// Output:
	// 200 OK hello from 127.0.0.1
	// proxydial: CONNECT: "403 Forbidden"
}

// One port for SOCKS5, SOCKS4, HTTP proxy requests, and both over TLS,
// with one account list, policy and dialer for all: the first byte tells
// SOCKS (5 or 4) from TLS (0x16) and from HTTP, and the bytes read to tell
// are replayed by the connection that Peek returns.
func Example_mixedProxy() {
	accounts := map[string]string{"alice": "secret"}
	check := socks5.Credentials(accounts).Check // one check for both servers

	allow := func(user string, dst netx.Addr) error {
		if dst.Port == 25 {
			return errors.New("no mail")
		}
		return nil
	}
	var dialer net.Dialer // or one through a tunnel, per user
	dial := func(ctx context.Context, user string, dst netx.Addr) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", dst.String())
	}
	group := new(netx.ConnGroup) // e.g. to end every relay of a user

	socks := &socks5.Server{
		SOCKS4: true,
		Auth:   []socks5.Authenticator{socks5.UserPassAuth{Check: check}},
		Allow:  func(_ context.Context, r *socks5.Request) error { return allow(r.User, r.Dst) },
		Dial:   func(ctx context.Context, r *socks5.Request) (net.Conn, error) { return dial(ctx, r.User, r.Dst) },
		RelayOptions: func(*socks5.Request) []netx.RelayOption {
			return []netx.RelayOption{netx.WithRelayGroup(group)}
		},
	}
	web := &httpproxy.Server{
		Auth:  []httpproxy.Authenticator{httpproxy.BasicAuth{Check: check}},
		Allow: func(_ context.Context, r *httpproxy.Request) error { return allow(r.User, r.Dst) },
		Dial:  func(ctx context.Context, r *httpproxy.Request) (net.Conn, error) { return dial(ctx, r.User, r.Dst) },
		RelayOptions: func(*httpproxy.Request) []netx.RelayOption {
			return []netx.RelayOption{netx.WithRelayGroup(group)}
		},
	}

	var cert tls.Certificate // the proxy's certificate
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	var serveConn func(ctx context.Context, c net.Conn, overTLS bool)
	serveConn = func(ctx context.Context, c net.Conn, overTLS bool) {
		peekCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		c, first, err := netx.Peek(peekCtx, c, 1)
		cancel()
		if err != nil || len(first) == 0 {
			_ = c.Close()
			return
		}
		switch {
		case first[0] == socks5.Version5 || first[0] == socks5.Version4:
			_ = socks.ServeConn(ctx, c)
		case first[0] == 0x16 && !overTLS:
			tc, err := tlsconn.Server(ctx, c, tlsConfig)
			if err != nil {
				return // closed by tlsconn.Server
			}
			serveConn(ctx, tc, true)
		default:
			_ = web.ServeConn(ctx, c)
		}
	}

	run := func(ln net.Listener) error {
		ctx := context.Background()
		for {
			c, err := netx.Accept(ctx, ln)
			if err != nil {
				return err
			}
			go serveConn(ctx, c, false)
		}
	}
	_ = run
}

// A proxy that reaches every destination through an upstream proxy, here
// an HTTP one with CONNECT, for tunnels and forwarded requests alike, which
// then go through tunnels to port 80; a socks5.Dialer works the same way.
// Kept connections are keyed by destination and user, as the upstream
// dialer depends on nothing else.
func ExampleServer_upstreamProxy() {
	upstream := &proxydial.HTTPDialer{ProxyAddr: "upstream.example:3128", Username: "proxy-user", Password: "proxy-secret"}
	s := &httpproxy.Server{
		Dial: func(ctx context.Context, req *httpproxy.Request) (net.Conn, error) {
			return upstream.DialContext(ctx, "tcp", req.Dst.String())
		},
	}
	_ = s // s.ListenAndServe(":8080")
}

// An access log from OnDone, with the identity, status and bytes of each
// request, and X-Forwarded-For added to forwarded requests.
func ExampleServer_accessLog() {
	s := &httpproxy.Server{
		OnDone: func(req *httpproxy.Request, r httpproxy.Result) {
			log.Printf("%s %q %s %s %d up=%d down=%d reused=%v %v err=%v",
				req.Conn.RemoteAddr(), req.User, req.Method, req.Target, r.Status,
				r.ToTarget, r.ToClient, r.Reused, time.Since(r.Start), r.Err)
		},
		ForwardHeader: func(req *httpproxy.Request, h *httphead.Header) {
			if host, _, err := net.SplitHostPort(req.Conn.RemoteAddr().String()); err == nil {
				h.Add("X-Forwarded-For", host)
			}
		},
	}
	_ = s
}
