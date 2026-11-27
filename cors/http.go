package cors

import (
	"net/http"
	"strings"

	"github.com/djylb/netx/internal/httptoken"
)

const (
	allowOrigin  = "Access-Control-Allow-Origin"
	credentials  = "Access-Control-Allow-Credentials"
	askMethod    = "Access-Control-Request-Method"
	askHeaders   = "Access-Control-Request-Headers"
	allowMethods = "Access-Control-Allow-Methods"
	allowHeaders = "Access-Control-Allow-Headers"
	maxAge       = "Access-Control-Max-Age"
)

func requestOrigin(r *http.Request) string {
	if r != nil {
		if v := r.Header.Values("Origin"); len(v) == 1 {
			return strings.Trim(v[0], " \t")
		}
	}
	return ""
}

func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && len(r.Header.Values("Origin")) > 0 && len(r.Header.Values(askMethod)) > 0
}

// SelectPreflight calls lookup with the requested method for a preflight.
// lookup returns the selected route and whether it handles local preflights.
// Otherwise the original method selects the route. The result's boolean is
// true when the caller should authorize and serve a local preflight.
func SelectPreflight[T any](r *http.Request, lookup func(method string) (T, bool)) (T, bool) {
	if isPreflight(r) {
		if route, local := lookup(strings.Trim(r.Header.Get(askMethod), " \t")); local {
			return route, true
		}
	}
	route, _ := lookup(r.Method)
	return route, false
}

// AddPreflightVary includes every preflight selector in Vary. Call it before
// any check that may deny a request ahead of Preflight, such as host or
// authorization checks, so that denials still vary on the preflight fields.
func AddPreflightVary(h http.Header) { mergeVary(h, "Origin", askMethod, askHeaders) }

func mergeVary(h http.Header, fields ...string) {
	var tokens []string
	seen := map[string]bool{}
	add := func(token string) {
		if key := strings.ToLower(token); key != "" && !seen[key] {
			tokens = append(tokens, token)
			seen[key] = true
		}
	}
	for _, line := range h.Values("Vary") {
		for token := range strings.SplitSeq(line, ",") {
			token = strings.Trim(token, " \t")
			if token == "*" {
				return
			}
			add(token)
		}
	}
	for _, field := range fields {
		add(field)
	}
	h.Set("Vary", strings.Join(tokens, ", "))
}

// LocalPreflight reports whether the policy handles its own preflights.
func (c *Compiled) LocalPreflight() bool { return c != nil && c.local }

// Preflight answers a local preflight and reports whether it wrote a response.
// Status 204 grants the requested method and headers, 400 indicates malformed
// input and 403 indicates a policy denial. Each answer has an empty body.
// Other requests and backend preflights pass through with w untouched.
func (c *Compiled) Preflight(w http.ResponseWriter, r *http.Request) bool {
	if !c.LocalPreflight() || !isPreflight(r) {
		return false
	}
	h := w.Header()
	AddPreflightVary(h)
	for _, name := range [...]string{allowOrigin, credentials, allowMethods, allowHeaders, maxAge} {
		h.Del(name)
	}
	w.WriteHeader(c.preflight(h, r))
	return true
}

func (c *Compiled) preflight(h http.Header, r *http.Request) int {
	raw := requestOrigin(r)
	o, ok := parseOrigin(raw, false)
	method := strings.Trim(r.Header.Get(askMethod), " \t")
	if !ok || len(r.Header.Values(askMethod)) != 1 || !httptoken.Valid(method) {
		return http.StatusBadRequest
	}
	var headers []string
	var denied bool
	seen := map[string]bool{}
	for _, line := range r.Header.Values(askHeaders) {
		for field := range strings.SplitSeq(line, ",") {
			field = strings.Trim(field, " \t")
			if !httptoken.Valid(field) {
				return http.StatusBadRequest
			}
			field = http.CanonicalHeaderKey(field)
			if _, allowed := c.headers[field]; !allowed {
				denied = true
				continue
			}
			if !seen[field] {
				headers = append(headers, field)
				seen[field] = true
			}
		}
	}
	allowed := c.allow(raw, o)
	if _, ok := c.methods[method]; !ok || allowed == "" || denied {
		return http.StatusForbidden
	}
	c.grant(h, allowed)
	h.Set(allowMethods, method)
	if len(headers) > 0 {
		h.Set(allowHeaders, strings.Join(headers, ", "))
	}
	if c.maxAge != "" {
		h.Set(maxAge, c.maxAge)
	}
	return http.StatusNoContent
}

func (c *Compiled) grant(h http.Header, allowed string) {
	h.Set(allowOrigin, allowed)
	if c.credentials {
		h.Set(credentials, "true")
	} else {
		h.Del(credentials)
	}
}

// ApplyResponse applies the policy to a final action response. A nonempty
// backend Allow-Origin preserves all backend fields, including Vary. Explicit
// origins and wildcards use the incoming request. Reflection uses res.Request
// after any outgoing header rewrite, falling back to incoming for local
// responses. Informational responses, including upgrades, pass through.
func (c *Compiled) ApplyResponse(res *http.Response, incoming *http.Request) {
	if c == nil || c.methods == nil || res == nil || res.StatusCode < 200 {
		return
	}
	for _, value := range res.Header.Values(allowOrigin) {
		if strings.Trim(value, " \t") != "" {
			return
		}
	}
	// Empty backend values convey no permission. Drop these lines even if
	// the request has no origin eligible for a replacement.
	res.Header.Del(allowOrigin)
	if c.mode == OriginReflect && res.Request != nil {
		incoming = res.Request
	}
	allowed := c.AllowOrigin(requestOrigin(incoming))
	if allowed == "" && c.mode == OriginReflect {
		return
	}
	if res.Header == nil {
		res.Header = make(http.Header)
	}
	mergeVary(res.Header, "Origin")
	if allowed != "" {
		c.grant(res.Header, allowed)
		if c.expose != "" {
			res.Header.Set("Access-Control-Expose-Headers", c.expose)
		}
	}
}
