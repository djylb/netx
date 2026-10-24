package httprewrite

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/djylb/netx/forwarded"
)

func testRequest() *http.Request {
	r := httptest.NewRequest("GET", "/a%20b/c?x=1&y=two&x=3", nil)
	r.Host = "Example.COM:8080"
	r.RemoteAddr = "10.0.0.1:41000"
	r.Header.Set("User-Agent", "test/1")
	r.Header.Add("X-Forwarded-For", "198.51.100.1")
	r.Header.Add("X-Forwarded-For", "10.0.0.9")
	r.Header.Set("Forwarded", "for=198.51.100.1")
	r.Header.Set("Cookie", "a=1; sid=abc ; b=2")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8080}
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
}

func TestVariables(t *testing.T) {
	r := testRequest()
	tlsReq := r.Clone(r.Context())
	tlsReq.TLS = &tls.ConnectionState{}
	res := &http.Response{StatusCode: 302, Header: http.Header{"Location": {"/next"}, "X-Up": {"u1", "u2"}}}
	when := time.Date(2026, 10, 24, 1, 2, 3, 456e6, time.UTC)
	client := forwarded.Client{Addr: netip.MustParseAddrPort("198.51.100.1:0"), Hops: 2, Proto: "https", Host: "public.example"}
	for _, tt := range []struct {
		tmpl string
		c    Context
		want string
	}{
		{"${scheme}", Context{Request: r}, "http"},
		{"${scheme}|${https}", Context{Request: tlsReq}, "https|on"},
		{"[${https}]", Context{Request: r}, "[]"},
		{"${host}", Context{Request: r}, "example.com"},
		{"${http_host}", Context{Request: r}, "Example.COM:8080"},
		{"${request_method} ${request_uri}", Context{Request: r}, "GET /a%20b/c?x=1&y=two&x=3"},
		{"${uri}${is_args}${args}", Context{Request: r}, "/a b/c?x=1&y=two&x=3"},
		{"${query_string}", Context{Request: r}, "x=1&y=two&x=3"},
		{"${arg_x},${arg_y},${arg_z}", Context{Request: r}, "1,two,"},
		{"${cookie_sid}|${cookie_b}|${cookie_c}", Context{Request: r}, "abc|2|"},
		{"${remote_addr} ${remote_ip}:${remote_port}", Context{Request: r}, "10.0.0.1 10.0.0.1:41000"},
		{"${remote_addr}:${remote_port}", Context{Request: r, Client: client}, "198.51.100.1:"},
		{"${peer_addr}:${peer_port}", Context{Request: r, Client: client}, "10.0.0.1:41000"},
		{"${server_addr}:${server_port}", Context{Request: r}, "192.0.2.10:8080"},
		{"${forwarded_proto}://${forwarded_host}", Context{Request: r, Client: client}, "https://public.example"},
		{"${forwarded_proto}://${forwarded_host}", Context{Request: r}, "http://Example.COM:8080"},
		{"${proxy_add_x_forwarded_for}", Context{Request: r}, "198.51.100.1, 10.0.0.9, 10.0.0.1"},
		{"${proxy_add_forwarded}", Context{Request: r}, `for=198.51.100.1, for=10.0.0.1;host="Example.COM:8080";proto=http`},
		{"${http_user_agent}|${http_x_missing}|${http_upgrade}|${http_connection}", Context{Request: r}, "test/1||websocket|Upgrade"},
		{"${status} ${upstream_http_location} ${upstream_http_x_up}", Context{Request: r, Response: res}, "302 /next u1"},
		{"[${status}${upstream_http_location}]", Context{Request: r}, "[]"},
		{"${msec}", Context{Time: when}, "1792803723.456"},
		{"${time_iso8601}", Context{Time: when}, "2026-10-24T01:02:03Z"},
		{"${time_http}", Context{Time: when.In(time.FixedZone("x", 3600))}, "Sat, 24 Oct 2026 01:02:03 GMT"},
		{"${msec}", Context{Time: time.UnixMilli(-1500)}, "-2.500"},
		{"${scheme}${host}${remote_addr}${proxy_add_x_forwarded_for}", Context{}, "http"},
		{"$$${scheme}$ $x $", Context{Request: r}, "$http$ $x $"},
		{"${scheme}://${host}${request_uri}", Context{Request: r}, "http://example.com/a%20b/c?x=1&y=two&x=3"},
	} {
		tm, err := Compile(tt.tmpl, nil)
		if err != nil {
			t.Errorf("Compile(%q): %v", tt.tmpl, err)
			continue
		}
		got, err := tm.Expand(&tt.c)
		if err != nil || got != tt.want {
			t.Errorf("Expand(%q) = %q, %v, want %q", tt.tmpl, got, err, tt.want)
		}
		b, err := tm.Append([]byte("<"), &tt.c)
		if err != nil || string(b) != "<"+tt.want {
			t.Errorf("Append(%q) = %q, %v", tt.tmpl, b, err)
		}
		if tm.String() != tt.tmpl {
			t.Errorf("String() = %q", tm.String())
		}
	}
}

func TestHostVariants(t *testing.T) {
	for _, tt := range []struct{ host, want string }{
		{"[2001:DB8::1]:443", "[2001:db8::1]"},
		{"[::1]", "[::1]"},
		{"a.example", "a.example"},
		{"2001:db8::1", "2001:db8::1"},
		{"", "url.example"},
	} {
		r := &http.Request{Host: tt.host, URL: &url.URL{Host: "url.example:1"}, Header: http.Header{}}
		if got := varHost(&Context{Request: r}, ""); got != tt.want {
			t.Errorf("host of %q = %q, want %q", tt.host, got, tt.want)
		}
	}
	r := &http.Request{URL: &url.URL{Path: "/p", RawQuery: "q"}, Header: http.Header{}}
	if got := varRequestURI(&Context{Request: r}, ""); got != "/p?q" {
		t.Errorf("request_uri of a client request = %q", got)
	}
}

func TestCompileErrors(t *testing.T) {
	for _, tt := range []struct {
		tmpl string
		err  error
	}{
		{"${scheme", ErrSyntax},
		{"${}", ErrSyntax},
		{"${a-b}", ErrSyntax},
		{"${ scheme }", ErrSyntax},
		{"${nope}", ErrUnknownVariable},
		{"${Scheme}", ErrUnknownVariable},
		{"${http_}", ErrUnknownVariable},
		{"${unset}", ErrUnknownVariable},
		{"a\r\nX-Evil: 1", ErrInvalidValue},
		{"a\x00", ErrInvalidValue},
		{"a\x7f", ErrInvalidValue},
	} {
		if _, err := Compile(tt.tmpl, nil); !errors.Is(err, tt.err) {
			t.Errorf("Compile(%q) error = %v, want %v", tt.tmpl, err, tt.err)
		}
	}
	if _, err := Compile("a\tb ü", nil); err != nil {
		t.Errorf("tab and UTF-8: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustCompile did not panic")
		}
	}()
	MustCompile("${", nil)
}

func TestCallerVars(t *testing.T) {
	type route struct{ id string }
	vars := Vars{
		"route_id": func(dst []byte, c *Context) []byte { return append(dst, c.Data.(*route).id...) },
		"scheme":   func(dst []byte, c *Context) []byte { return append(dst, "custom"...) },
		"bad":      func(dst []byte, c *Context) []byte { return append(dst, "x\r\ny"...) },
	}
	tm := MustCompile("${route_id}/${scheme}", vars)
	got, err := tm.Expand(&Context{Data: &route{"r7"}})
	if err != nil || got != "r7/custom" {
		t.Errorf("Expand = %q, %v", got, err)
	}
	bad := MustCompile("v=${bad}", vars)
	if b, err := bad.Append([]byte("keep"), &Context{}); !errors.Is(err, ErrInvalidValue) || string(b) != "keep" {
		t.Errorf("Append(bad) = %q, %v", b, err)
	}
}

// TestInjection checks that values decoded from the request cannot add
// fields.
func TestInjection(t *testing.T) {
	r := httptest.NewRequest("GET", "/x%0d%0aX-Evil:%201", nil)
	c := &Context{Request: r}
	for _, tmpl := range []string{"${uri}", "/p${uri}", "${uri}${uri}"} {
		if v, err := MustCompile(tmpl, nil).Expand(c); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expand(%q) = %q, %v", tmpl, v, err)
		}
	}
	rules, err := ParseRules("X-Path: ${uri}\nX-Ok: yes", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	if err := ApplyHeader(h, rules, c); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ApplyHeader error = %v", err)
	}
	if len(h) != 1 || h.Get("X-Ok") != "yes" {
		t.Errorf("header = %v", h)
	}
	// The request URI as sent stays escaped and passes.
	if v, err := MustCompile("${request_uri}", nil).Expand(c); err != nil || v != "/x%0d%0aX-Evil:%201" {
		t.Errorf("request_uri = %q, %v", v, err)
	}
}

func TestParseRules(t *testing.T) {
	text := "# comment\r\n\r\nx-real-ip: ${remote_addr}\nX-Drop:  ${unset}  \r\n Host : backend.internal\nX-Url: ${scheme}://a:b\n"
	rules, err := ParseRules(text, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 || rules[0].Name != "X-Real-Ip" || rules[1].Value != nil || rules[2].Name != "Host" || rules[3].Value.String() != "${scheme}://a:b" {
		t.Fatalf("rules = %+v", rules)
	}
	for _, tt := range []struct {
		text, msg string
		err       error
	}{
		{"no colon", "line 1", ErrSyntax},
		{"\n\nBad Name: x", "line 3", ErrSyntax},
		{": x", "line 1", ErrSyntax},
		{"A: 1\nX: ${nope}", "line 2", ErrUnknownVariable},
	} {
		_, err := ParseRules(tt.text, nil)
		if !errors.Is(err, tt.err) || !strings.Contains(err.Error(), tt.msg) {
			t.Errorf("ParseRules(%q) error = %v", tt.text, err)
		}
	}
}

func TestApplyRequest(t *testing.T) {
	in := testRequest()
	out := in.Clone(in.Context())
	out.Header.Set("X-Old", "1")
	out.Header.Set("X-Keep", "k")
	rules := []Rule{
		{Name: "x-real-ip", Value: MustCompile("${remote_addr}", nil)},
		{Name: "X-Old"},
		{Name: "X-Keep", Value: MustCompile("k2", nil), Add: true},
		{Name: "X-Empty", Value: MustCompile("${http_x_missing}", nil)},
		{Name: "X-Keep", Value: MustCompile("${http_x_missing}", nil), Add: true},
		{Name: "Host", Value: MustCompile("backend:${server_port}", nil)},
		{Name: "Bad Name", Value: MustCompile("x", nil)},
		{Name: "X-After", Value: MustCompile("after", nil)},
	}
	err := ApplyRequest(out, rules, &Context{Request: in})
	if !errors.Is(err, ErrSyntax) {
		t.Errorf("error = %v", err)
	}
	if out.Header.Get("X-Real-Ip") != "10.0.0.1" || out.Header["X-Old"] != nil || strings.Join(out.Header["X-Keep"], ",") != "k,k2" ||
		out.Header["X-Empty"] != nil || out.Host != "backend:8080" || out.Header["Host"] != nil || out.Header.Get("X-After") != "after" {
		t.Errorf("out = %q %v", out.Host, out.Header)
	}
	if err := ApplyRequest(out, []Rule{{Name: "host"}}, &Context{Request: in}); err != nil || out.Host != "" {
		t.Errorf("delete Host: %q %v", out.Host, err)
	}
	empty := &http.Request{}
	if err := ApplyRequest(empty, []Rule{{Name: "A", Value: MustCompile("1", nil)}}, &Context{}); err != nil || empty.Header.Get("A") != "1" {
		t.Errorf("nil header: %v %v", empty.Header, err)
	}
	h := http.Header{}
	if err := ApplyHeader(h, []Rule{{Name: "Host", Value: MustCompile("h", nil)}}, &Context{}); err != nil || h.Get("Host") != "h" {
		t.Errorf("ApplyHeader Host: %v %v", h, err)
	}
}

func TestApplyRedirects(t *testing.T) {
	in := testRequest()
	outURL, _ := url.Parse("http://backend.internal:8080/app/x")
	res := &http.Response{Request: &http.Request{URL: outURL}}
	c := &Context{Request: in, Response: res}
	to := MustCompile("${scheme}://${http_host}", nil)
	redirects := []Redirect{
		{From: "http://other.internal/a/", To: MustCompile("https://pub.example/b/", nil)},
		{To: to},
	}
	for _, tt := range []struct{ field, in, want string }{
		{"Location", "http://backend.internal:8080/login?next=/", "http://Example.COM:8080/login?next=/"},
		{"Location", "HTTP://Backend.Internal:8080", "http://Example.COM:8080"},
		{"Location", "http://backend.internal:8080#f", "http://Example.COM:8080#f"},
		{"Location", "http://backend.internal:80801/", "http://backend.internal:80801/"},
		{"Location", "http://backend.internal/", "http://backend.internal/"},
		{"Location", "/relative", "/relative"},
		{"Location", "http://OTHER.internal/a/z", "https://pub.example/b/z"},
		{"Location", "http://other.internal/A/z", "http://other.internal/A/z"},
		{"Refresh", "5; url=http://backend.internal:8080/x", "5; url=http://Example.COM:8080/x"},
		{"Refresh", "0;URL='http://backend.internal:8080/x' ", "0;URL='http://Example.COM:8080/x' "},
		{"Refresh", `1; Url = "http://backend.internal:8080"`, `1; Url = "http://Example.COM:8080"`},
		{"Refresh", "5", "5"},
		{"Refresh", "5; other=1", "5; other=1"},
	} {
		h := http.Header{tt.field: {tt.in}}
		if err := ApplyRedirects(h, redirects, c); err != nil || h.Get(tt.field) != tt.want {
			t.Errorf("%s %q -> %q, %v, want %q", tt.field, tt.in, h.Get(tt.field), err, tt.want)
		}
	}
	// No response request: the default redirect does not apply.
	h := http.Header{"Location": {"http://backend.internal:8080/"}}
	if err := ApplyRedirects(h, redirects, &Context{Request: in}); err != nil || h.Get("Location") != "http://backend.internal:8080/" {
		t.Errorf("without response: %v %v", h, err)
	}
	bad := []Redirect{{To: MustCompile("http://x${uri}", nil)}}
	evil := httptest.NewRequest("GET", "/%0d%0a", nil)
	h = http.Header{"Location": {"http://backend.internal:8080/"}}
	if err := ApplyRedirects(h, bad, &Context{Request: evil, Response: res}); !errors.Is(err, ErrInvalidValue) || h.Get("Location") != "http://backend.internal:8080/" {
		t.Errorf("invalid expansion: %v %v", h, err)
	}
}

// TestRedirectBoundary checks that a From without a trailing "/" matches
// only a whole host or path segment, and that path Froms rewrite relative
// URLs.
func TestRedirectBoundary(t *testing.T) {
	c := &Context{Request: testRequest()}
	redirects := []Redirect{
		{From: "http://backend", To: MustCompile("https://public.example.com", nil)},
		{From: "/app", To: MustCompile("/public", nil)},
		{From: "http://svc/api/", To: MustCompile("https://public.example.com/v1/", nil)},
	}
	for _, tt := range []struct{ in, want string }{
		{"http://backend.corp.example/x", "http://backend.corp.example/x"},
		{"http://backend:8080/x", "http://backend:8080/x"},
		{"http://backend-2/x", "http://backend-2/x"},
		{"http://backend", "https://public.example.com"},
		{"http://BACKEND/x", "https://public.example.com/x"},
		{"http://backend?q", "https://public.example.com?q"},
		{"http://backend#f", "https://public.example.com#f"},
		{"/apple", "/apple"},
		{"/app", "/public"},
		{"/app/login", "/public/login"},
		{"/app?next=1", "/public?next=1"},
		{"http://svc/api/users", "https://public.example.com/v1/users"},
		{"http://svc/apis", "http://svc/apis"},
		{"other/app", "other/app"},
	} {
		h := http.Header{"Location": {tt.in}}
		if err := ApplyRedirects(h, redirects, c); err != nil || h.Get("Location") != tt.want {
			t.Errorf("%q -> %q, %v, want %q", tt.in, h.Get("Location"), err, tt.want)
		}
	}
}

// TestModifyResponseNoRequest checks a response that carries no request.
func TestModifyResponseNoRequest(t *testing.T) {
	rw := &Rewriter{
		Response:  []Rule{{Name: "X-Client", Value: MustCompile("${remote_addr}", nil)}, {Name: "X-Status", Value: MustCompile("${status}", nil)}},
		Redirects: []Redirect{{To: MustCompile("https://${http_host}", nil)}, {From: "http://b/", To: MustCompile("https://p/", nil)}},
		Resolver:  &forwarded.Resolver{},
		Data:      func(in *http.Request) any { t.Error("Data called"); return nil },
	}
	res := &http.Response{StatusCode: 301, Header: http.Header{"Location": {"http://b/x"}, "X-Client": {"old"}}}
	if err := rw.ModifyResponse(res); err != nil {
		t.Fatal(err)
	}
	if res.Header.Get("Location") != "https://p/x" || res.Header["X-Client"] != nil || res.Header.Get("X-Status") != "301" {
		t.Errorf("header = %v", res.Header)
	}
}

// roundTripFunc is a transport that answers without a network, so that the
// proxy tests run the same on every port.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRewriterReverseProxy(t *testing.T) {
	backend, _ := url.Parse("http://backend.internal:8080")
	rules, err := ParseRules(`
X-Forwarded-For: ${proxy_add_x_forwarded_for}
X-Forwarded-Proto: ${forwarded_proto}
X-Real-IP: ${remote_addr}
X-Route: ${route}
Upgrade: ${http_upgrade}
Connection: ${http_connection}
X-Hop: kept
Host: ${host}
`, Vars{"route": func(dst []byte, c *Context) []byte { return append(dst, c.Data.(string)...) }})
	if err != nil {
		t.Fatal(err)
	}
	respRules, err := ParseRules("Server: ${unset}\nX-Status: ${status}\nX-Client: ${remote_addr}", nil)
	if err != nil {
		t.Fatal(err)
	}
	trusted, _ := forwarded.ParsePrefixSet("10.0.0.0/8")
	rw := &Rewriter{
		Request:   rules,
		Response:  respRules,
		Redirects: []Redirect{{To: MustCompile("${scheme}://${http_host}", nil)}},
		Resolver:  &forwarded.Resolver{Trusted: trusted},
		Data:      func(in *http.Request) any { return "r1" },
	}
	var seen *http.Request
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend)
			if err := rw.Rewrite(pr); err != nil {
				t.Errorf("Rewrite: %v", err)
			}
		},
		ModifyResponse: rw.ModifyResponse,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seen = r
			return &http.Response{
				StatusCode: 302,
				Header:     http.Header{"Location": {"http://backend.internal:8080/login"}, "Server": {"secret/1.0"}, "Content-Length": {"0"}},
				Body:       http.NoBody,
				Request:    r,
			}, nil
		}),
	}
	in := httptest.NewRequest("GET", "http://Public.Example/app?q=1", nil)
	in.RemoteAddr = "10.0.0.1:5000"
	in.Header.Set("X-Forwarded-For", "198.51.100.1")
	in.Header.Set("X-Forwarded-Proto", "https")
	in.Header.Set("X-Hop", "client")
	in.Header.Set("Connection", "X-Hop, keep-alive")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, in)

	if seen == nil {
		t.Fatalf("not forwarded: %d %s", rec.Code, rec.Body)
	}
	want := map[string]string{
		"X-Forwarded-For":   "198.51.100.1, 10.0.0.1",
		"X-Forwarded-Proto": "https",
		"X-Real-Ip":         "198.51.100.1",
		"X-Route":           "r1",
		"Connection":        "X-Hop, keep-alive",
		"X-Hop":             "kept",
	}
	for k, v := range want {
		if got := strings.Join(seen.Header[k], ","); got != v {
			t.Errorf("backend %s = %q, want %q", k, got, v)
		}
	}
	if seen.Header["Upgrade"] != nil || seen.Host != "public.example" {
		t.Errorf("backend Upgrade %q Host %q", seen.Header["Upgrade"], seen.Host)
	}
	if loc := rec.Header().Get("Location"); loc != "http://Public.Example/login" {
		t.Errorf("Location = %q", loc)
	}
	if rec.Header()["Server"] != nil || rec.Header().Get("X-Status") != "302" || rec.Header().Get("X-Client") != "198.51.100.1" {
		t.Errorf("response header = %v", rec.Header())
	}

	// ModifyResponse without Rewrite reads the response's request.
	res := &http.Response{StatusCode: 200, Header: http.Header{}, Request: in}
	if err := rw.ModifyResponse(res); err != nil || res.Header.Get("X-Client") != "198.51.100.1" {
		t.Errorf("ModifyResponse alone: %v %v", res.Header, err)
	}
}

// TestRewriterUpgrade checks that ReverseProxy's own upgrade fields reach
// the backend when the rules leave them alone.
func TestRewriterUpgrade(t *testing.T) {
	backend, _ := url.Parse("http://backend.internal")
	rw := &Rewriter{Request: []Rule{{Name: "X-A", Value: MustCompile("a", nil)}}}
	var seen *http.Request
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend)
			_ = rw.Rewrite(pr)
		},
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seen = r
			return &http.Response{StatusCode: 400, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
		}),
	}
	in := httptest.NewRequest("GET", "http://public.example/ws", nil)
	in.Header.Set("Connection", "Upgrade")
	in.Header.Set("Upgrade", "websocket")
	proxy.ServeHTTP(httptest.NewRecorder(), in)
	if seen == nil || seen.Header.Get("Upgrade") != "websocket" || seen.Header.Get("Connection") != "Upgrade" || seen.Header.Get("X-A") != "a" {
		t.Fatalf("backend header = %v", seen.Header)
	}
}

func TestAllocs(t *testing.T) {
	r := testRequest()
	r.Host = "example.com:8080" // ${host} lowers the case of others
	c := &Context{Request: r}
	buf := make([]byte, 0, 256)
	for _, tmpl := range []string{"${scheme}://${host}${request_uri}", "${proxy_add_x_forwarded_for}", "${remote_addr}:${remote_port}"} {
		tm := MustCompile(tmpl, nil)
		if n := testing.AllocsPerRun(100, func() { _, _ = tm.Append(buf[:0], c) }); n != 0 {
			t.Errorf("Append(%q) allocates %v times", tmpl, n)
		}
	}
	for _, tmpl := range []string{"literal", "${http_host}", "${http_user_agent}", "${cookie_sid}"} {
		tm := MustCompile(tmpl, nil)
		if n := testing.AllocsPerRun(100, func() { _, _ = tm.Expand(c) }); n != 0 {
			t.Errorf("Expand(%q) allocates %v times", tmpl, n)
		}
	}
}

func FuzzCompile(f *testing.F) {
	for _, s := range []string{"${scheme}://${host}${request_uri}", "$${x}", "${", "a$", "${http_x_y}${arg_a}${cookie_b}", "${uri}"} {
		f.Add(s, "/a%0d%0a?b=1")
	}
	f.Fuzz(func(t *testing.T, tmpl, target string) {
		tm, err := Compile(tmpl, nil)
		if err != nil {
			return
		}
		if tm.String() != tmpl {
			t.Fatalf("String() = %q", tm.String())
		}
		u, err := url.Parse(target)
		if err != nil {
			return
		}
		r := &http.Request{Method: "GET", URL: u, Host: "h", RequestURI: target, RemoteAddr: "192.0.2.1:1",
			Header: http.Header{"Cookie": {target}, "X-Y": {target}}}
		v, err := tm.Expand(&Context{Request: r})
		if err != nil {
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("Expand error %v", err)
			}
			return
		}
		if !validValue(v) {
			t.Fatalf("Expand(%q) = %q", tmpl, v)
		}
	})
}

func FuzzApplyRedirects(f *testing.F) {
	f.Add("http://backend:1/x", "5; url='http://backend:1/'")
	f.Add("HTTP://BACKEND:1", "0;URL=")
	f.Fuzz(func(t *testing.T, loc, refresh string) {
		u, _ := url.Parse("http://backend:1/")
		res := &http.Response{Request: &http.Request{URL: u}}
		c := &Context{Request: &http.Request{Host: "pub", Header: http.Header{}}, Response: res}
		h := http.Header{"Location": {loc}, "Refresh": {refresh}}
		err := ApplyRedirects(h, []Redirect{{To: MustCompile("https://${http_host}", nil)}, {From: "http://", To: MustCompile("x:", nil)}}, c)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{h.Get("Location"), h.Get("Refresh")} {
			if validValue(loc) && validValue(refresh) && !validValue(v) {
				t.Fatalf("rewrote to %q", v)
			}
		}
	})
}

func BenchmarkExpand(b *testing.B) {
	r := testRequest()
	r.Host = "example.com:8080"
	c := &Context{Request: r}
	for _, bc := range []struct{ name, tmpl string }{
		{"literal", "no variables"},
		{"field", "${http_host}"},
		{"url", "${scheme}://${host}${request_uri}"},
		{"xff", "${proxy_add_x_forwarded_for}"},
	} {
		tm := MustCompile(bc.tmpl, nil)
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = tm.Expand(c)
			}
		})
		b.Run(bc.name+"/append", func(b *testing.B) {
			buf := make([]byte, 0, 256)
			b.ReportAllocs()
			for b.Loop() {
				buf, _ = tm.Append(buf[:0], c)
			}
		})
	}
}

func BenchmarkCompile(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Compile("${scheme}://${host}${request_uri}?via=${http_x_via}", nil)
	}
}

func BenchmarkApplyRequest(b *testing.B) {
	rules, err := ParseRules("X-Forwarded-For: ${proxy_add_x_forwarded_for}\nX-Forwarded-Proto: ${scheme}\nX-Real-IP: ${remote_addr}\nHost: ${host}\nX-Drop: ${unset}", nil)
	if err != nil {
		b.Fatal(err)
	}
	in := testRequest()
	c := &Context{Request: in}
	out := in.Clone(in.Context())
	b.ReportAllocs()
	for b.Loop() {
		_ = ApplyRequest(out, rules, c)
	}
}
