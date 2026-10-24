package httpproxy

import (
	"errors"
	"strings"

	"github.com/djylb/netx"
	"github.com/djylb/netx/httphead"
)

// headStatus returns the status code that answers a request head that
// could not be read or parsed, with err as its cause.
func headStatus(err error) error {
	code := 400
	switch {
	case errors.Is(err, httphead.ErrTooLarge):
		code = 431
	case errors.Is(err, httphead.ErrVersion):
		code = 505
	case errors.Is(err, httphead.ErrTransferCoding):
		code = 501
	}
	return &StatusError{Code: code, Err: err}
}

// parseRequest parses a request head into req.
func (sc *serverConn) parseRequest(raw string) (*Request, error) {
	h, err := httphead.ParseRequest(raw, nil)
	if err != nil {
		return nil, headStatus(err)
	}
	t, err := httphead.ParseTarget(h.Method, h.Target)
	if err != nil {
		return nil, headStatus(err)
	}
	req := &Request{Method: h.Method, Target: h.Target, Proto: h.Proto, Header: h.Header, head: raw, tgt: t, minor: h.Minor}
	req.conn = reqConn{Conn: sc.c, br: sc.br}
	req.Conn = &req.conn
	switch t.Form {
	case httphead.AuthorityForm:
		// The method is case-sensitive, but CONNECT, which is never
		// forwarded, is also taken in other cases from non-standard
		// clients, and then reaches the hooks as "CONNECT".
		req.Method = "CONNECT"
		// A port is required (RFC 9110, section 9.3.6); clients that leave
		// it out mean 443.
		req.Dst = targetAddr(t, 443)
	case httphead.AbsoluteForm:
		if t.Scheme == "http" {
			req.Dst = targetAddr(t, 80)
		}
	case httphead.OriginForm, httphead.AsteriskForm:
		// Not a proxy request: the target names no destination, which
		// Intercept may give.
	}
	// A missing Host field is accepted from non-standard clients: the
	// destination comes from the target, and forwarded requests get it
	// from there.
	if h.Header.Count("Host") > 1 {
		return nil, badRequest("more than one Host field")
	}
	if req.body, req.length, err = httphead.RequestBody(h.Header, h.Minor); err != nil {
		return nil, headStatus(err)
	}
	if h.Minor == 0 {
		req.keepAlive = h.Header.HasToken("Connection", "keep-alive") || h.Header.HasToken("Proxy-Connection", "keep-alive")
	} else {
		req.keepAlive = !h.Header.HasToken("Connection", "close") && !h.Header.HasToken("Proxy-Connection", "close")
	}
	req.upgrade = h.Minor == 1 && t.Form != httphead.AuthorityForm &&
		h.Header.HasToken("Connection", "upgrade") && h.Header.Has("Upgrade")
	return req, nil
}

// targetAddr returns the destination of a target, with port def when it
// names none.
func targetAddr(t httphead.Target, def uint16) netx.Addr {
	port := t.Port
	if port == 0 {
		port = def
	}
	return netx.HostAddr(t.Host, port)
}

// HostDst returns the destination that the Host field of req names, with
// port 80 when it names none, for Server.Intercept, as for clients whose
// requests are redirected to the proxy without their knowing. It reports
// false when req has no valid Host field.
func HostDst(req *Request) (netx.Addr, bool) {
	if req.Header.Count("Host") != 1 {
		return netx.Addr{}, false
	}
	host := req.Header.Get("Host")
	t, err := httphead.ParseTarget("CONNECT", host)
	if err != nil || strings.TrimSpace(host) == "" {
		return netx.Addr{}, false
	}
	return targetAddr(t, 80), true
}

// badRequest is a malformed request.
func badRequest(msg string) error {
	return &StatusError{Code: 400, Err: errors.New(msg)}
}
