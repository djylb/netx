// Package cors applies cross-origin resource sharing policies to HTTP responses.
//
// Compile a Policy once and share the Compiled value. A router that keys
// routes by method calls SelectPreflight so a preflight selects the route of
// the method it asks for. When that route answers preflights locally, call
// AddPreflightVary before any check that can deny the request, then Preflight.
// Other requests reach the backend, and ApplyResponse adds the response
// headers to its reply. Invalid policies return Errors, which match ErrInvalid.
package cors

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/djylb/netx/internal/httptoken"
)

// OriginMode selects how a Policy matches request origins.
type OriginMode uint8

const (
	// OriginList allows only the origins in Policy.Origins.
	OriginList OriginMode = iota
	// OriginAny answers every valid origin with the wildcard "*".
	// It cannot be combined with credentials.
	OriginAny
	// OriginReflect echoes every valid origin.
	OriginReflect
)

// PreflightMode selects who answers preflight requests.
type PreflightMode uint8

const (
	// PreflightLocal answers preflights from the policy.
	PreflightLocal PreflightMode = iota
	// PreflightBackend leaves preflights to the application. Methods,
	// Headers and MaxAge must then be unset.
	PreflightBackend
)

// Policy describes a single CORS policy. The zero value is invalid because
// OriginList needs at least one origin.
type Policy struct {
	// Origins lists HTTP(S) origins or "null" for OriginList. A leading
	// "*." matches exactly one DNS label. It must be empty for other modes.
	Origins []string
	// Methods defaults to GET and HEAD and is case-sensitive. An explicit
	// empty list is invalid.
	Methods []string
	// Headers lists request fields a preflight may ask for. It defaults to
	// none and is case-insensitive.
	Headers []string
	// ExposeHeaders lists response fields that browser scripts may read.
	ExposeHeaders []string
	// MaxAge is sent as Access-Control-Max-Age in whole seconds. Zero omits
	// the header, leaving the browser default; a negative value sends zero,
	// disabling preflight caching.
	MaxAge time.Duration
	// OriginMode selects origin matching; the zero value is OriginList.
	OriginMode OriginMode
	// Preflight selects the preflight responder; the zero value is PreflightLocal.
	Preflight PreflightMode
	// Credentials sends Access-Control-Allow-Credentials. It requires
	// OriginList or OriginReflect.
	Credentials bool
}

// ErrInvalid reports an invalid Policy. Errors matches it with errors.Is.
var ErrInvalid = errors.New("cors: invalid policy")

// FieldError describes one invalid policy field. Path is the snake_case
// field name, such as "origins" or "max_age".
type FieldError struct {
	Path    string
	Message string
}

// Errors contains the field errors in field order.
type Errors []FieldError

func (e Errors) Error() string {
	var s strings.Builder
	s.WriteString(ErrInvalid.Error())
	for i, f := range e {
		if i == 0 {
			s.WriteString(": ")
		} else {
			s.WriteString("; ")
		}
		s.WriteString(f.Path)
		s.WriteString(": ")
		s.WriteString(f.Message)
	}
	return s.String()
}

// Is reports whether target is ErrInvalid.
func (e Errors) Is(target error) bool { return target == ErrInvalid }

// Compiled is an immutable policy, safe for concurrent requests. A nil or
// zero Compiled applies no headers and handles no preflights.
type Compiled struct {
	origins, wildcards map[origin]struct{}
	methods, headers   map[string]struct{}
	maxAge, expose     string
	mode               OriginMode
	credentials, local bool
}

// Compile validates the entire policy and snapshots its inputs. It returns
// Errors on invalid configuration, including a missing origin list.
func Compile(p Policy) (*Compiled, error) {
	var problems Errors
	add := func(path, msg string) { problems = append(problems, FieldError{path, msg}) }
	c := &Compiled{credentials: p.Credentials, mode: p.OriginMode}
	switch p.OriginMode {
	case OriginList:
		if len(p.Origins) == 0 {
			add("origins", "supply at least one origin")
		}
		c.origins = make(map[origin]struct{}, len(p.Origins))
		for _, raw := range p.Origins {
			o, ok := parseOrigin(raw, true)
			if !ok {
				add("origins", fmt.Sprintf("invalid origin %q", raw))
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
	case OriginAny, OriginReflect:
		if len(p.Origins) > 0 {
			add("origins", "only OriginList takes an origin list")
		}
		if p.OriginMode == OriginAny && p.Credentials {
			add("origin_mode", "wildcard cannot allow credentials")
		}
	default:
		add("origin_mode", "unknown origin mode")
	}
	switch p.Preflight {
	case PreflightLocal:
		c.local = true
	case PreflightBackend:
		if p.Methods != nil || p.Headers != nil || p.MaxAge != 0 {
			add("preflight", "backend preflight excludes methods, headers and max age")
		}
	default:
		add("preflight", "unknown preflight mode")
	}
	if p.Methods == nil {
		p.Methods = []string{http.MethodGet, http.MethodHead}
	} else if len(p.Methods) == 0 {
		add("methods", "explicit method list is empty")
	}
	c.methods = tokenSet(p.Methods, "methods", add)
	c.headers = tokenSet(p.Headers, "headers", add)
	c.expose = strings.Join(slices.Sorted(maps.Keys(tokenSet(p.ExposeHeaders, "expose_headers", add))), ", ")
	switch {
	case p.MaxAge < 0:
		c.maxAge = "0"
	case p.MaxAge%time.Second != 0:
		add("max_age", "expected whole seconds")
	case p.MaxAge > 0:
		c.maxAge = strconv.FormatInt(int64(p.MaxAge/time.Second), 10)
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return c, nil
}

func tokenSet(values []string, field string, add func(path, msg string)) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "*" || !httptoken.Valid(v) {
			add(field, fmt.Sprintf("invalid token %q", v))
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
	case OriginAny:
		return "*"
	case OriginReflect:
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
