// Package cors applies cross-origin resource sharing policies to HTTP responses.
package cors

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/djylb/netx/internal/httptoken"
)

// Policy describes a single CORS policy. Origins is an allowlist of HTTP(S)
// origins or "null". A leading "*." matches exactly one DNS label.
// A singleton "*" emits a wildcard; a singleton "reflect" echoes any valid
// origin. Only reflection and explicit origins may be combined with credentials.
//
// Methods defaults to GET and HEAD and is case-sensitive. Headers defaults to
// none and is case-insensitive. ExposeHeaders optionally lists response
// fields that browser scripts may read. All three lists enumerate tokens. MaxAge is in seconds;
// nil omits the header and a pointer to zero sends zero. Backend leaves
// preflights to the application and excludes Methods, Headers and MaxAge.
type Policy struct {
	Origins, Methods, Headers, ExposeHeaders []string
	MaxAge                                   *uint32
	Credentials, Backend                     bool
}

// PolicyError maps each invalid field to an explanation.
type PolicyError map[string]string

func (e PolicyError) Error() string {
	return fmt.Sprintf("cors: invalid policy: %v", map[string]string(e))
}

// Compiled is an immutable policy, safe for concurrent requests. A nil or
// zero Compiled applies no headers and handles no preflights.
type Compiled struct {
	origins, wildcards   map[origin]struct{}
	methods, headers     map[string]struct{}
	mode, maxAge, expose string
	credentials, local   bool
}

const reflectOrigin = "reflect"

// Compile validates the entire policy and snapshots its inputs. It returns
// a PolicyError on invalid configuration, including a missing origin list.
func Compile(p Policy) (*Compiled, error) {
	problems := PolicyError{}
	c := &Compiled{credentials: p.Credentials, local: !p.Backend}
	switch {
	case len(p.Origins) == 0:
		problems["origins"] = "supply at least one origin"
	case len(p.Origins) == 1 && (p.Origins[0] == "*" || p.Origins[0] == reflectOrigin):
		c.mode = p.Origins[0]
		if c.mode == "*" && p.Credentials {
			problems["origins"] = "wildcard cannot allow credentials"
		}
	default:
		c.origins = make(map[origin]struct{}, len(p.Origins))
		for _, raw := range p.Origins {
			o, ok := parseOrigin(raw, true)
			if !ok {
				problems["origins"] = fmt.Sprintf("invalid origin %q", raw)
				break
			}
			if suffix, pattern := strings.CutPrefix(o.host, "*."); pattern {
				if c.wildcards == nil {
					c.wildcards = make(map[origin]struct{})
				}
				o.host = suffix
				c.wildcards[o] = struct{}{}
			} else {
				c.origins[o] = struct{}{}
			}
		}
	}
	if p.Backend && (p.Methods != nil || p.Headers != nil || p.MaxAge != nil) {
		problems["preflight"] = "backend preflight excludes methods, headers and max age"
	}
	if p.Methods == nil {
		p.Methods = []string{http.MethodGet, http.MethodHead}
	} else if len(p.Methods) == 0 {
		problems["methods"] = "explicit method list is empty"
	}
	c.methods = tokenSet(p.Methods, "methods", problems)
	c.headers = tokenSet(p.Headers, "headers", problems)
	c.expose = strings.Join(slices.Sorted(maps.Keys(tokenSet(p.ExposeHeaders, "expose_headers", problems))), ", ")
	if p.MaxAge != nil {
		c.maxAge = strconv.FormatUint(uint64(*p.MaxAge), 10)
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return c, nil
}

func tokenSet(values []string, field string, problems PolicyError) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "*" || !httptoken.Valid(v) {
			problems[field] = fmt.Sprintf("invalid token %q", v)
			break
		}
		if field != "methods" {
			v = http.CanonicalHeaderKey(v)
		}
		set[v] = struct{}{}
	}
	return set
}

// AllowOrigin returns the value to use for Access-Control-Allow-Origin,
// or the empty string for a malformed or unlisted origin.
func (c *Compiled) AllowOrigin(raw string) string {
	o, ok := parseOrigin(raw, false)
	if !ok || c == nil {
		return ""
	}
	return c.allow(raw, o)
}

func (c *Compiled) allow(raw string, o origin) string {
	switch c.mode {
	case "*":
		return "*"
	case reflectOrigin:
		return raw
	}
	if _, ok := c.origins[o]; ok {
		return raw
	}
	if c.wildcards != nil && !o.ip {
		if _, suffix, found := strings.Cut(o.host, "."); found {
			o.host = suffix
			if _, ok := c.wildcards[o]; ok {
				return raw
			}
		}
	}
	return ""
}
