package httprewrite

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/djylb/netx/forwarded"
)

// lookup resolves a variable name in vars, then in the built-in variables.
func lookup(name string, vars Vars) (segment, bool) {
	if f, ok := vars[name]; ok && f != nil {
		return segment{fn: f}, true
	}
	switch name {
	case "scheme":
		return segment{str: varScheme}, true
	case "https":
		return segment{str: varHTTPS}, true
	case "host":
		return segment{str: varHost}, true
	case "request_method":
		return segment{str: varMethod}, true
	case "request_uri":
		return segment{str: varRequestURI}, true
	case "uri":
		return segment{str: varURI}, true
	case "args", "query_string":
		return segment{str: varArgs}, true
	case "is_args":
		return segment{str: varIsArgs}, true
	case "remote_addr", "remote_ip":
		return segment{app: varRemoteIP}, true
	case "remote_port":
		return segment{app: varRemotePort}, true
	case "peer_addr":
		return segment{app: varPeerIP}, true
	case "peer_port":
		return segment{app: varPeerPort}, true
	case "server_addr":
		return segment{app: varServerAddr}, true
	case "server_port":
		return segment{app: varServerPort}, true
	case "forwarded_proto":
		return segment{str: varForwardedProto}, true
	case "forwarded_host":
		return segment{str: varForwardedHost}, true
	case "proxy_add_x_forwarded_for":
		return segment{app: varAddXFF}, true
	case "proxy_add_forwarded":
		return segment{app: varAddForwarded}, true
	case "http_host":
		return segment{str: varHTTPHost}, true
	case "status":
		return segment{app: varStatus}, true
	case "msec":
		return segment{app: varMsec}, true
	case "time_iso8601":
		return segment{app: varISO8601}, true
	case "time_http":
		return segment{app: varHTTPTime}, true
	}
	for _, fam := range [...]struct {
		prefix string
		str    func(*Context, string) string
		field  bool
	}{
		{"upstream_http_", varUpstreamField, true},
		{"http_", varField, true},
		{"cookie_", varCookie, false},
		{"arg_", varArg, false},
	} {
		if arg, ok := strings.CutPrefix(name, fam.prefix); ok && arg != "" {
			if fam.field {
				arg = http.CanonicalHeaderKey(strings.ReplaceAll(arg, "_", "-"))
			}
			return segment{str: fam.str, arg: arg}, true
		}
	}
	return segment{}, false
}

func varScheme(c *Context, _ string) string {
	if c.Request != nil && c.Request.TLS != nil {
		return "https"
	}
	return "http"
}

func varHTTPS(c *Context, _ string) string {
	if c.Request != nil && c.Request.TLS != nil {
		return "on"
	}
	return ""
}

func varHost(c *Context, _ string) string {
	if c.Request == nil {
		return ""
	}
	h := c.Request.Host
	if h == "" && c.Request.URL != nil {
		h = c.Request.URL.Host
	}
	return lowerASCII(stripPort(h))
}

// stripPort returns host without a port; an IPv6 address keeps its
// brackets.
func stripPort(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i >= 0 {
			return h[:i+1]
		}
		return h
	}
	if i := strings.IndexByte(h, ':'); i >= 0 && strings.IndexByte(h[i+1:], ':') < 0 {
		return h[:i]
	}
	return h
}

func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}

func varMethod(c *Context, _ string) string {
	if c.Request == nil {
		return ""
	}
	return c.Request.Method
}

func varRequestURI(c *Context, _ string) string {
	switch {
	case c.Request == nil:
		return ""
	case c.Request.RequestURI != "":
		return c.Request.RequestURI
	case c.Request.URL != nil:
		return c.Request.URL.RequestURI()
	}
	return ""
}

func varURI(c *Context, _ string) string {
	if c.Request == nil || c.Request.URL == nil {
		return ""
	}
	return c.Request.URL.Path
}

func varArgs(c *Context, _ string) string {
	if c.Request == nil || c.Request.URL == nil {
		return ""
	}
	return c.Request.URL.RawQuery
}

func varIsArgs(c *Context, _ string) string {
	if varArgs(c, "") != "" {
		return "?"
	}
	return ""
}

// peer returns the TCP peer of the request.
func (c *Context) peer() netip.AddrPort {
	if c.Request == nil {
		return netip.AddrPort{}
	}
	ap, _ := forwarded.ParseNode(c.Request.RemoteAddr)
	return ap
}

// client returns Client, or the TCP peer when it is unset.
func (c *Context) client() forwarded.Client {
	if c.Client.Addr.Addr().IsValid() {
		return c.Client
	}
	return forwarded.Client{Addr: c.peer()}
}

func appendIP(dst []byte, a netip.Addr) []byte {
	if !a.IsValid() {
		return dst
	}
	return a.AppendTo(dst)
}

func appendPort(dst []byte, p uint16) []byte {
	if p == 0 {
		return dst
	}
	return strconv.AppendUint(dst, uint64(p), 10)
}

func varRemoteIP(dst []byte, c *Context, _ string) []byte {
	return appendIP(dst, c.client().Addr.Addr())
}

func varRemotePort(dst []byte, c *Context, _ string) []byte {
	return appendPort(dst, c.client().Addr.Port())
}

func varPeerIP(dst []byte, c *Context, _ string) []byte {
	return appendIP(dst, c.peer().Addr())
}

func varPeerPort(dst []byte, c *Context, _ string) []byte {
	return appendPort(dst, c.peer().Port())
}

// local returns the local address of the connection that the request came
// in on.
func (c *Context) local() netip.AddrPort {
	if c.Request == nil {
		return netip.AddrPort{}
	}
	switch a := c.Request.Context().Value(http.LocalAddrContextKey).(type) {
	case *net.TCPAddr:
		if a != nil {
			return a.AddrPort()
		}
	case net.Addr:
		ap, _ := forwarded.ParseNode(a.String())
		return ap
	}
	return netip.AddrPort{}
}

func varServerAddr(dst []byte, c *Context, _ string) []byte {
	return appendIP(dst, c.local().Addr().Unmap())
}

func varServerPort(dst []byte, c *Context, _ string) []byte {
	return appendPort(dst, c.local().Port())
}

func varForwardedProto(c *Context, _ string) string {
	if p := c.client().Proto; p != "" {
		return p
	}
	return varScheme(c, "")
}

func varForwardedHost(c *Context, _ string) string {
	if h := c.client().Host; h != "" {
		return h
	}
	return varHTTPHost(c, "")
}

func varAddXFF(dst []byte, c *Context, _ string) []byte {
	if c.Request == nil {
		return dst
	}
	return forwarded.AppendXForwardedFor(dst, c.Request.Header["X-Forwarded-For"], c.peer().Addr())
}

func varAddForwarded(dst []byte, c *Context, _ string) []byte {
	if c.Request == nil {
		return dst
	}
	e := forwarded.Element{
		For:   netip.AddrPortFrom(c.peer().Addr(), 0),
		Host:  c.Request.Host,
		Proto: varScheme(c, ""),
	}
	return forwarded.AppendForwarded(dst, c.Request.Header["Forwarded"], e)
}

func varHTTPHost(c *Context, _ string) string {
	if c.Request == nil {
		return ""
	}
	return c.Request.Host
}

func varField(c *Context, name string) string {
	if c.Request == nil {
		return ""
	}
	if name == "Host" {
		return c.Request.Host
	}
	if vs := c.Request.Header[name]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func varUpstreamField(c *Context, name string) string {
	if c.Response == nil {
		return ""
	}
	if vs := c.Response.Header[name]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func varCookie(c *Context, name string) string {
	if c.Request == nil {
		return ""
	}
	for _, line := range c.Request.Header["Cookie"] {
		for line != "" {
			var pair string
			pair, line, _ = strings.Cut(line, ";")
			k, v, _ := strings.Cut(strings.TrimLeft(pair, " \t"), "=")
			if k == name {
				return strings.TrimRight(v, " \t")
			}
		}
	}
	return ""
}

func varArg(c *Context, name string) string {
	q := varArgs(c, "")
	for q != "" {
		var pair string
		pair, q, _ = strings.Cut(q, "&")
		if k, v, _ := strings.Cut(pair, "="); k == name {
			return v
		}
	}
	return ""
}

func varStatus(dst []byte, c *Context, _ string) []byte {
	if c.Response == nil {
		return dst
	}
	return strconv.AppendInt(dst, int64(c.Response.StatusCode), 10)
}

func (c *Context) now() time.Time {
	if c.Time.IsZero() {
		return time.Now()
	}
	return c.Time
}

func varMsec(dst []byte, c *Context, _ string) []byte {
	ms := c.now().UnixMilli()
	sec, frac := ms/1000, ms%1000
	if frac < 0 { // before 1970
		sec, frac = sec-1, frac+1000
	}
	dst = strconv.AppendInt(dst, sec, 10)
	return append(dst, '.', byte('0'+frac/100), byte('0'+frac/10%10), byte('0'+frac%10))
}

func varISO8601(dst []byte, c *Context, _ string) []byte {
	return c.now().AppendFormat(dst, time.RFC3339)
}

func varHTTPTime(dst []byte, c *Context, _ string) []byte {
	return c.now().UTC().AppendFormat(dst, http.TimeFormat)
}
