package httprewrite_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"

	"github.com/djylb/netx/forwarded"
	"github.com/djylb/netx/httprewrite"
)

// Compile a template once and expand it for each request.
func ExampleCompile() {
	t, err := httprewrite.Compile("${scheme}://${host}${request_uri}", nil)
	if err != nil {
		log.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/search?q=go", nil)
	r.Host = "Example.com:8080"
	v, err := t.Expand(&httprewrite.Context{Request: r})
	fmt.Println(v, err)
	// Output: http://example.com/search?q=go <nil>
}

// Variables of the caller's own read its data, here the route a request
// matched.
func ExampleVars() {
	type route struct{ name string }
	vars := httprewrite.Vars{
		"route": func(dst []byte, c *httprewrite.Context) []byte {
			return append(dst, c.Data.(*route).name...)
		},
	}
	rules, err := httprewrite.ParseRules("X-Route: ${route}\nX-Debug: ${unset}", vars)
	if err != nil {
		log.Fatal(err)
	}
	h := http.Header{"X-Debug": {"1"}}
	err = httprewrite.ApplyHeader(h, rules, &httprewrite.Context{Data: &route{"api"}})
	fmt.Println(h, err)
	// Output: map[X-Route:[api]] <nil>
}

// A reverse proxy that passes the forwarding fields on, tells the backend
// the client found behind a trusted load balancer, and points the
// backend's redirects at the public address.
func ExampleRewriter() {
	backend, _ := url.Parse("http://backend.internal:8080")
	rules, err := httprewrite.ParseRules(`
X-Forwarded-For: ${proxy_add_x_forwarded_for}
X-Forwarded-Proto: ${forwarded_proto}
X-Real-IP: ${remote_addr}
`, nil)
	if err != nil {
		log.Fatal(err)
	}
	trusted, _ := forwarded.ParsePrefixSet("10.0.0.0/8")
	rw := &httprewrite.Rewriter{
		Request:   rules,
		Redirects: []httprewrite.Redirect{{To: httprewrite.MustCompile("${forwarded_proto}://${http_host}", nil)}},
		Resolver:  &forwarded.Resolver{Trusted: trusted},
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend)
			pr.Out.Host = pr.In.Host
			if err := rw.Rewrite(pr); err != nil {
				log.Print(err)
			}
		},
		ModifyResponse: rw.ModifyResponse,
		// The backend, answering in memory for the example.
		Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			fmt.Println("backend got", r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-Ip"))
			h := http.Header{"Location": {"http://backend.internal:8080/login"}}
			return &http.Response{StatusCode: 302, Header: h, Body: http.NoBody, Request: r}, nil
		}),
	}

	in := httptest.NewRequest("GET", "/account", nil)
	in.Host = "www.example.com"
	in.RemoteAddr = "10.0.0.2:40000" // the load balancer
	in.Header.Set("X-Forwarded-For", "198.51.100.7")
	in.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, in)
	fmt.Println(rec.Code, rec.Header().Get("Location"))
	// Output:
	// backend got www.example.com 198.51.100.7, 10.0.0.2 198.51.100.7
	// 302 https://www.example.com/login
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
