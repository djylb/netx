package cors

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func compile(t *testing.T, p Policy) *Compiled {
	t.Helper()
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestInvalidPolicy(t *testing.T) {
	for _, tc := range []struct {
		p      Policy
		fields []string
	}{
		{Policy{}, []string{"origins"}},
		{Policy{OriginMode: OriginAny, Credentials: true, Methods: []string{}, Headers: []string{"*"}, ExposeHeaders: []string{"a b"}}, []string{"origin_mode", "methods", "headers", "expose_headers"}},
		{Policy{OriginMode: OriginReflect, Origins: []string{"null"}, Methods: []string{"*"}}, []string{"origins", "methods"}},
		{Policy{Origins: []string{"reflect"}, MaxAge: time.Millisecond}, []string{"origins", "max_age"}},
		{Policy{OriginMode: 9, Preflight: 9, Origins: []string{"null"}}, []string{"origin_mode", "preflight"}},
		{Policy{Origins: []string{"null"}, Preflight: PreflightBackend, Headers: []string{}}, []string{"preflight"}},
		{Policy{Origins: []string{"null"}, Preflight: PreflightBackend, MaxAge: -1}, []string{"preflight"}},
	} {
		c, err := Compile(tc.p)
		bad, ok := errors.AsType[Errors](err)
		if c != nil || !ok || !errors.Is(err, ErrInvalid) || len(bad) != len(tc.fields) {
			t.Fatalf("policy %+v: %v", tc.p, err)
		}
		for i, field := range tc.fields {
			if bad[i].Path != field || bad[i].Message == "" || !strings.Contains(err.Error(), field) {
				t.Error(err)
			}
		}
	}
}

func TestOrigins(t *testing.T) {
	c := compile(t, Policy{Origins: []string{"https://*.Example.test.", "http://[2001:db8::1]:8080", "null", "http://127.0.0.1", "https://Example.test"}})
	for _, raw := range []string{"https://API.EXAMPLE.test:443", "https://example.test.", "http://[2001:db8:0:0::1]:8080", "http://127.0.0.1:80", "null"} {
		if got := c.AllowOrigin(raw); got != raw {
			t.Errorf("allow %q = %q", raw, got)
		}
	}
	for _, raw := range []string{"https://a.b.example.test", "http://a.example.test", "https://a.example.test:80", "https://else.test", "http://[2001:db8::1]"} {
		if c.AllowOrigin(raw) != "" {
			t.Error(raw)
		}
	}
	for _, raw := range []string{"", "https://a.test/", "https://a.test?", "https://a.test#", "ftp://a.test", "https://u@a.test", "https://a.test:", "https://a.test:0", "https://a.test:65536", "https://a,b", "https://[a.test]", "http://2001:db8::1", "http://[127.0.0.1]", "https://[::1.]", "http://[fe80::1%25eth0]", "https://K.test", "https://a..test", "https://-x.test", "https://x-.test", "https://a*a.test", "https://a.test\n", "https://a.test https://b.test", "https://" + strings.Repeat("a", 64) + ".test"} {
		if _, err := Compile(Policy{Origins: []string{raw}}); err == nil {
			t.Errorf("compiled %q", raw)
		}
		if got := compile(t, Policy{OriginMode: OriginReflect}).AllowOrigin(raw); got != "" {
			t.Errorf("reflected %q", got)
		}
	}
	if got := compile(t, Policy{OriginMode: OriginAny}).AllowOrigin("https://*.test"); got != "" {
		t.Errorf("wildcard in request: %q", got)
	}
}

func request(method string, origin, asked []string) *http.Request {
	r := &http.Request{Method: method, Header: make(http.Header)}
	for _, v := range origin {
		r.Header.Add("Origin", v)
	}
	for _, v := range asked {
		r.Header.Add(askMethod, v)
	}
	return r
}

func TestSelection(t *testing.T) {
	for _, tc := range []struct {
		method         string
		origins, asked []string
		calls          []string
		backend        bool
		local          bool
	}{
		{http.MethodOptions, []string{"null"}, []string{" PUT "}, []string{"PUT"}, false, true},
		{http.MethodOptions, []string{"null"}, []string{"PUT"}, []string{"PUT", http.MethodOptions}, true, false},
		{http.MethodOptions, nil, []string{"PUT"}, []string{http.MethodOptions}, false, false},
		{http.MethodOptions, []string{"null"}, nil, []string{http.MethodOptions}, false, false},
		{http.MethodPost, []string{"null"}, []string{"PUT"}, []string{http.MethodPost}, false, false},
	} {
		var calls []string
		got, local := SelectPreflight(request(tc.method, tc.origins, tc.asked), func(m string) (string, bool) { calls = append(calls, m); return m, !tc.backend })
		if local != tc.local || got != tc.calls[len(tc.calls)-1] || !slices.Equal(calls, tc.calls) {
			t.Errorf("%+v: %v %v %v", tc, got, local, calls)
		}
	}
}

func TestPreflight(t *testing.T) {
	p := Policy{Origins: []string{"https://*.example.test"}, Methods: []string{"PUT"}, Headers: []string{"X-A", "X-B"}, Credentials: true, MaxAge: -1}
	c := compile(t, p)
	p.Origins[0], p.Methods[0], p.Headers[0] = "*", "OTHER", "Other"
	const origin = "https://a.example.test"
	for _, tc := range []struct {
		origins, methods, headers []string
		code                      int
	}{
		{[]string{origin}, []string{"PUT"}, []string{"x-b, x-A", "X-B"}, 204},
		{[]string{"null"}, []string{"PUT"}, nil, 403},
		{[]string{origin}, []string{"put"}, nil, 403},
		{[]string{origin}, []string{"PUT"}, []string{"X-Other"}, 403},
		{[]string{origin}, []string{"PUT"}, []string{"X-Other,"}, 400},
		{[]string{origin, origin}, []string{"PUT"}, nil, 400},
		{[]string{origin}, []string{"PUT", "PUT"}, nil, 400},
		{[]string{origin}, []string{"P UT"}, nil, 400},
		{[]string{origin}, []string{"PUT"}, []string{"\u00a0X-A"}, 400},
	} {
		w := httptest.NewRecorder()
		w.Header().Set("Vary", "Accept, origin")
		w.Header().Set(allowOrigin, "*")
		w.Header().Set(credentials, "true")
		r := request(http.MethodOptions, tc.origins, tc.methods)
		for _, v := range tc.headers {
			r.Header.Add(askHeaders, v)
		}
		if !c.Preflight(w, r) || w.Code != tc.code || w.Body.Len() != 0 {
			t.Fatalf("%+v: %d", tc, w.Code)
		}
		h := w.Header()
		if h.Get("Vary") != "Accept, origin, Access-Control-Request-Method, Access-Control-Request-Headers" {
			t.Fatal(h)
		}
		if tc.code == 204 {
			if h.Get(allowOrigin) != origin || h.Get(credentials) != "true" || h.Get(allowMethods) != "PUT" || h.Get(allowHeaders) != "X-B, X-A" || h.Get(maxAge) != "0" {
				t.Fatal(h)
			}
		} else if h.Get(allowOrigin) != "" || h.Get(credentials) != "" || h.Get(allowMethods) != "" || h.Get(allowHeaders) != "" || h.Get(maxAge) != "" {
			t.Fatal(h)
		}
	}
}

func TestPreflightDefaults(t *testing.T) {
	c := compile(t, Policy{OriginMode: OriginAny})
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		r := request(http.MethodOptions, []string{"null"}, []string{m})
		w := httptest.NewRecorder()
		if !c.Preflight(w, r) {
			t.Fatal(m)
		}
		if m == http.MethodPost {
			if w.Code != 403 {
				t.Fatal(w.Code)
			}
			continue
		}
		if w.Code != 204 || w.Header().Get(allowOrigin) != "*" || w.Header().Get(maxAge) != "" || w.Header().Get(credentials) != "" {
			t.Fatal(w)
		}
	}
	for _, p := range []*Compiled{nil, {}, compile(t, Policy{OriginMode: OriginAny, Preflight: PreflightBackend})} {
		w := httptest.NewRecorder()
		if p.Preflight(w, request(http.MethodOptions, []string{"null"}, []string{"GET"})) || len(w.Header()) != 0 {
			t.Fatal(w)
		}
	}
	if c.Preflight(httptest.NewRecorder(), request(http.MethodOptions, nil, nil)) {
		t.Fatal("handled bare OPTIONS")
	}
}

func TestApplyResponse(t *testing.T) {
	const incoming = "https://visitor.example"
	const outgoing = "https://up.example"
	q := request(http.MethodGet, []string{incoming}, nil)
	for _, tc := range []struct {
		policy           string
		out, allow, vary string
		creds            bool
	}{
		{"reflect", outgoing, outgoing, "Accept, Origin", true},
		{"reflect", "", "", "Accept", false},
		{incoming, outgoing, incoming, "Accept, Origin", false},
		{"https://other.example", incoming, "", "Accept, Origin", false},
		{"*", outgoing, "*", "Accept, Origin", false},
	} {
		p := Policy{Credentials: tc.creds, ExposeHeaders: []string{"x-a", "X-A"}}
		switch tc.policy {
		case "*":
			p.OriginMode = OriginAny
		case "reflect":
			p.OriginMode = OriginReflect
		default:
			p.Origins = []string{tc.policy}
		}
		c := compile(t, p)
		res := &http.Response{StatusCode: http.StatusNotFound, Request: request(http.MethodGet, []string{tc.out}, nil), Header: http.Header{"Vary": {"Accept"}}}
		res.Header.Set(credentials, "orphan")
		c.ApplyResponse(res, q)
		h := res.Header
		if h.Get(allowOrigin) != tc.allow || h.Get("Vary") != tc.vary {
			t.Fatal(tc, h)
		}
		if tc.allow == "" {
			if h.Get("Access-Control-Expose-Headers") != "" || h.Get(credentials) != "orphan" {
				t.Fatal(h)
			}
			continue
		}
		if h.Get("Access-Control-Expose-Headers") != "X-A" || tc.creds != (h.Get(credentials) == "true") || !tc.creds && h.Get(credentials) != "" {
			t.Fatal(h)
		}
	}
	c := compile(t, Policy{OriginMode: OriginReflect, Credentials: true})
	for _, status := range []int{101, 200} {
		h := http.Header{"Vary": {"Origin", "Accept"}, allowOrigin: {"", "https://app.example"}, credentials: {"false", "true"}}
		if status == 101 {
			delete(h, allowOrigin)
		}
		want := h.Clone()
		c.ApplyResponse(&http.Response{StatusCode: status, Header: h}, q)
		if !reflect.DeepEqual(h, want) {
			t.Fatalf("%d mutated backend fields: %v", status, h)
		}
	}
	h := http.Header{"Vary": {"Accept", "*"}}
	c.ApplyResponse(&http.Response{StatusCode: http.StatusOK, Header: h}, q)
	if !slices.Equal(h.Values("Vary"), []string{"Accept", "*"}) || h.Get(allowOrigin) != incoming {
		t.Fatal(h)
	}
	h = http.Header{"Vary": {"origin, Accept", "ORIGIN, accept"}}
	wild := compile(t, Policy{OriginMode: OriginAny})
	wild.ApplyResponse(&http.Response{StatusCode: http.StatusOK, Header: h}, nil)
	if h.Get("Vary") != "origin, Accept" || h.Get(allowOrigin) != "" {
		t.Fatal(h)
	}
	res := &http.Response{StatusCode: http.StatusOK}
	wild.ApplyResponse(res, request(http.MethodGet, []string{"null", "null"}, nil))
	if res.Header.Get(allowOrigin) != "" || res.Header.Get("Vary") != "Origin" {
		t.Fatal(res.Header)
	}
}

func TestEmptyBackendOrigin(t *testing.T) {
	c := compile(t, Policy{OriginMode: OriginReflect})
	for _, raw := range []string{"null", "malformed"} {
		res := &http.Response{StatusCode: http.StatusOK, Header: http.Header{allowOrigin: {" ", ""}}}
		c.ApplyResponse(res, request(http.MethodGet, []string{raw}, nil))
		if got := res.Header.Values(allowOrigin); raw == "null" && !slices.Equal(got, []string{"null"}) || raw != "null" && len(got) != 0 {
			t.Fatalf("%s: %v", raw, got)
		}
	}
}

func TestSharedPolicy(t *testing.T) {
	p := Policy{Origins: []string{"https://a.example"}, Headers: []string{"X-Test"}, MaxAge: -1}
	c := compile(t, p)
	var group sync.WaitGroup
	group.Go(func() {
		for range 32 {
			p.Origins[0] = "*"
			p.Headers[0] = "X-Other"
		}
	})
	for range 8 {
		group.Go(func() {
			r := request(http.MethodOptions, []string{"https://a.example"}, []string{http.MethodGet})
			r.Header.Set(askHeaders, "X-Test")
			w := httptest.NewRecorder()
			c.Preflight(w, r)
			if w.Code != http.StatusNoContent || w.Header().Get(maxAge) != "0" || w.Header().Get(allowOrigin) != "https://a.example" {
				t.Error(w.Header())
			}
		})
	}
	group.Wait()
}

func TestMaxAge(t *testing.T) {
	for age, want := range map[time.Duration]string{0: "", -time.Second: "0", 90 * time.Second: "90"} {
		r := request(http.MethodOptions, []string{"https://a.example"}, []string{http.MethodGet})
		w := httptest.NewRecorder()
		compile(t, Policy{Origins: []string{"https://a.example"}, MaxAge: age}).Preflight(w, r)
		if got := w.Header().Get(maxAge); got != want {
			t.Errorf("%v: %q", age, got)
		}
	}
}
