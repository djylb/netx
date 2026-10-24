package httprewrite

import (
	"context"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/djylb/netx/forwarded"
)

// Rewriter applies rules from the hooks of an httputil.ReverseProxy. Its
// fields must not change while it is in use; a Rewriter is then safe for
// concurrent use.
//
//	rw := &httprewrite.Rewriter{Request: rules, Redirects: []httprewrite.Redirect{{To: to}}}
//	proxy := &httputil.ReverseProxy{
//		Rewrite: func(pr *httputil.ProxyRequest) {
//			pr.SetURL(backend)
//			if err := rw.Rewrite(pr); err != nil {
//				log.Print(err)
//			}
//		},
//		ModifyResponse: rw.ModifyResponse,
//	}
type Rewriter struct {
	// Request holds the rules for the outbound request.
	Request []Rule
	// Response holds the rules for the response, applied after Redirects.
	Response []Rule
	// Redirects rewrite the Location and Refresh fields of responses.
	Redirects []Redirect
	// Resolver, if set, finds the client of each request for the client
	// variables; without it the client is the TCP peer.
	Resolver *forwarded.Resolver
	// Data, if set, returns Context.Data for an inbound request, for the
	// caller's variables.
	Data func(in *http.Request) any
}

type rewriterKey struct{}

// rewriteState is what Rewrite keeps for ModifyResponse.
type rewriteState struct {
	in     *http.Request
	client forwarded.Client
	data   any
	time   time.Time
}

// Rewrite applies the request rules to pr.Out, expanding them for pr.In,
// and keeps what ModifyResponse needs in the context of pr.Out, which it
// replaces. Call it from ReverseProxy.Rewrite after pr.SetURL and any other
// change to pr.Out. ReverseProxy.Rewrite cannot fail a request, so the
// rules that fail are left out, as ApplyRequest leaves them, and the first
// error is returned for the caller to log.
func (rw *Rewriter) Rewrite(pr *httputil.ProxyRequest) error {
	st := &rewriteState{in: pr.In, time: time.Now()}
	peer, _ := forwarded.ParseNode(pr.In.RemoteAddr)
	st.client = rw.Resolver.Resolve(peer, pr.In.Header)
	if rw.Data != nil {
		st.data = rw.Data(pr.In)
	}
	c := st.context(nil)
	err := ApplyRequest(pr.Out, rw.Request, &c)
	pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), rewriterKey{}, st))
	return err
}

// ModifyResponse applies Redirects and then the response rules to res,
// expanding them for the inbound request that Rewrite saw, or for
// res.Request when Rewrite did not run. Use it as ReverseProxy's
// ModifyResponse, or call it from one. An error fails the response, which
// ReverseProxy answers with 502 Bad Gateway; the rules that did not fail
// are applied. A response without a Request gets the response rules with
// request variables that expand to nothing, and Data is not called.
func (rw *Rewriter) ModifyResponse(res *http.Response) error {
	var st *rewriteState
	if res.Request != nil {
		st, _ = res.Request.Context().Value(rewriterKey{}).(*rewriteState)
	}
	switch {
	case res.Request == nil:
		// Nothing to read the request variables from: they expand to
		// nothing and the default redirect does not apply.
		st = &rewriteState{time: time.Now()}
	case st == nil:
		st = &rewriteState{in: res.Request, time: time.Now()}
		peer, _ := forwarded.ParseNode(res.Request.RemoteAddr)
		st.client = rw.Resolver.Resolve(peer, res.Request.Header)
		if rw.Data != nil {
			st.data = rw.Data(res.Request)
		}
	}
	c := st.context(res)
	err := ApplyRedirects(res.Header, rw.Redirects, &c)
	if err2 := ApplyHeader(res.Header, rw.Response, &c); err == nil {
		err = err2
	}
	return err
}

func (st *rewriteState) context(res *http.Response) Context {
	return Context{Request: st.in, Response: res, Client: st.client, Time: st.time, Data: st.data}
}
