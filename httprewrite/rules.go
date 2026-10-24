package httprewrite

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// Rule changes one header field.
type Rule struct {
	// Name is the field name, matched without regard to case. For request
	// rules, "Host" is the request's Host.
	Name string
	// Value is the template of the value. Nil deletes the field.
	Value *Template
	// Add adds a field line after those the field has instead of
	// replacing them. A rule that adds to Host sets it.
	Add bool
}

// Unset is the value of a rule in ParseRules that deletes the field.
const Unset = "${unset}"

// ParseRules parses rules, one per line in the form "Name: value": the
// field name, a colon, and the template of the value, spaces around it
// ignored. A value of Unset deletes the field, any other sets it. Empty
// lines and lines that begin with "#" are skipped; lines end with LF or
// CRLF. Templates are compiled with vars.
func ParseRules(text string, vars Vars) ([]Rule, error) {
	var rules []Rule
	for n := 1; text != ""; n++ {
		var line string
		line, text, _ = strings.Cut(text, "\n")
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || line[0] == '#' {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !validFieldName(name) {
			return nil, &rewriteError{ErrSyntax, "line " + strconv.Itoa(n) + ": not a field rule: " + quote(line)}
		}
		r := Rule{Name: http.CanonicalHeaderKey(name)}
		if value != Unset {
			t, err := Compile(value, vars)
			if err != nil {
				return nil, lineError(n, err)
			}
			r.Value = t
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func lineError(n int, err error) error {
	var re *rewriteError
	if errors.As(err, &re) {
		return &rewriteError{re.kind, "line " + strconv.Itoa(n) + ": " + re.msg}
	}
	return err
}

// ApplyHeader applies rules to h in order, expanding them for c. A rule
// that sets a field to an empty value deletes it, and one that adds an
// empty value adds nothing, so that "Upgrade: ${http_upgrade}" sends no
// Upgrade field for a request without one. A rule whose name is not a
// valid field name or whose expansion fails is not applied; ApplyHeader
// applies the others and returns the first such error.
func ApplyHeader(h http.Header, rules []Rule, c *Context) error {
	return apply(h, nil, rules, c)
}

// ApplyRequest applies rules to the header of r as ApplyHeader does,
// except that rules on Host set r.Host, which a deleting rule sets to ""
// so that a client sends the host of r.URL. For a reverse proxy, r is the
// outbound request and c.Request the inbound one.
func ApplyRequest(r *http.Request, rules []Rule, c *Context) error {
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	return apply(r.Header, &r.Host, rules, c)
}

func apply(h http.Header, host *string, rules []Rule, c *Context) error {
	var first error
	fail := func(err error) {
		if first == nil {
			first = err
		}
	}
	for i := range rules {
		r := &rules[i]
		if !validFieldName(r.Name) {
			fail(&rewriteError{ErrSyntax, "invalid field name " + quote(r.Name)})
			continue
		}
		key := http.CanonicalHeaderKey(r.Name)
		v := ""
		if r.Value != nil {
			var err error
			if v, err = r.Value.Expand(c); err != nil {
				fail(err)
				continue
			}
		}
		if host != nil && key == "Host" {
			if v != "" || !r.Add {
				*host = v
			}
			continue
		}
		switch {
		case v == "" && r.Add:
		case v == "":
			delete(h, key)
		case r.Add:
			h[key] = append(h[key], v)
		default:
			h[key] = []string{v}
		}
	}
	return first
}

// validFieldName reports whether s is a token (RFC 9110).
func validFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c < 0x80 && strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// Redirect rewrites the URLs of redirects: a Location field, and the URL
// of a Refresh field such as "0; url=http://backend:8080/login", that begin
// with From have From replaced with the expansion of To.
type Redirect struct {
	// From is the beginning of the URLs to rewrite, such as
	// "http://backend:8080/app/". Its scheme and host are matched without
	// regard to case, the rest exactly. A From that does not end with "/"
	// matches only where the URL's host or path segment ends there too,
	// followed by the end of the URL or by "/", "?" or "#", so that
	// "http://backend" does not match "http://backend.example/" and
	// "/app" does not match "/apple". URLs are matched as written: a From
	// that is a path, such as "/app/", rewrites relative URLs that begin
	// with it, which backends mounted under a prefix send, and an absolute
	// From only absolute URLs. Empty means the origin of the
	// request that the response answers, c.Response.Request.URL, such as
	// "http://backend:8080", followed by the end of the URL or by "/", "?"
	// or "#": the backend's own address, as a reverse proxy dialed it.
	From string
	// To is the template of the replacement, such as
	// "${scheme}://${http_host}/".
	To *Template
}

// ApplyRedirects rewrites the Location and Refresh fields of h with the
// first redirect whose From each URL begins with, expanding To for c.
// URLs that no From matches, such as relative ones when every From is
// absolute, are left alone. A redirect whose expansion fails is not
// applied; ApplyRedirects goes on and returns the first error.
func ApplyRedirects(h http.Header, redirects []Redirect, c *Context) error {
	var first error
	for _, key := range [...]string{"Location", "Refresh"} {
		lines := h[key]
		for i, line := range lines {
			start, end := 0, len(line)
			if key == "Refresh" {
				if start, end = refreshURL(line); start < 0 {
					continue
				}
			}
			u := line[start:end]
			for _, rd := range redirects {
				n := rd.match(u, c)
				if n < 0 || rd.To == nil {
					continue
				}
				bp := getBuf()
				b := append((*bp)[:0], line[:start]...)
				b, err := rd.To.Append(b, c)
				if err == nil {
					b = append(append(b, u[n:]...), line[end:]...)
					lines[i] = string(b)
				} else if first == nil {
					first = err
				}
				*bp = b
				putBuf(bp)
				break
			}
		}
	}
	return first
}

// match returns the length of the beginning of u that r replaces, or -1.
func (r *Redirect) match(u string, c *Context) int {
	if r.From == "" {
		if c.Response == nil || c.Response.Request == nil || c.Response.Request.URL == nil {
			return -1
		}
		o := c.Response.Request.URL
		if o.Scheme == "" || o.Host == "" {
			return -1
		}
		n := len(o.Scheme) + 3 + len(o.Host)
		if len(u) < n || !strings.EqualFold(u[:len(o.Scheme)], o.Scheme) || u[len(o.Scheme):len(o.Scheme)+3] != "://" ||
			!strings.EqualFold(u[len(o.Scheme)+3:n], o.Host) {
			return -1
		}
		if len(u) > n && strings.IndexByte("/?#", u[n]) < 0 {
			return -1
		}
		return n
	}
	if len(u) < len(r.From) {
		return -1
	}
	// The scheme and the host end at the first "/" after "://".
	fold := len(r.From)
	if i := strings.Index(r.From, "://"); i >= 0 {
		if j := strings.IndexByte(r.From[i+3:], '/'); j >= 0 {
			fold = i + 3 + j
		}
	} else {
		fold = 0
	}
	if !strings.EqualFold(u[:fold], r.From[:fold]) || u[fold:len(r.From)] != r.From[fold:] {
		return -1
	}
	// A From that does not end with "/" ends at a host or a path segment,
	// which the URL must end too: "http://backend" is not the beginning of
	// "http://backend.example/", nor "/app" of "/apple".
	if n := len(r.From); !strings.HasSuffix(r.From, "/") && len(u) > n && strings.IndexByte("/?#", u[n]) < 0 {
		return -1
	}
	return len(r.From)
}

// refreshURL returns the bounds of the URL in a Refresh value such as
// `5; url="http://example.com/"`, or -1.
func refreshURL(v string) (start, end int) {
	semi := strings.IndexByte(v, ';')
	if semi < 0 {
		return -1, -1
	}
	i := semi + 1
	skip := func() {
		for i < len(v) && (v[i] == ' ' || v[i] == '\t') {
			i++
		}
	}
	skip()
	if len(v)-i < 3 || !strings.EqualFold(v[i:i+3], "url") {
		return -1, -1
	}
	i += 3
	skip()
	if i == len(v) || v[i] != '=' {
		return -1, -1
	}
	i++
	skip()
	end = len(v)
	for end > i && (v[end-1] == ' ' || v[end-1] == '\t') {
		end--
	}
	if i < end && (v[i] == '"' || v[i] == '\'') {
		q := v[i]
		i++
		if end > i && v[end-1] == q {
			end--
		}
	}
	return i, end
}
