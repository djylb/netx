package cors

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type origin struct {
	scheme, host string
	port         uint16
	ip           bool
}

func parseOrigin(raw string, pattern bool) (origin, bool) {
	var o origin
	if raw == "null" {
		return o, true
	}
	// Origins are serialized ASCII. Reject escapes, fragments (even an
	// empty one) and lists before the URL parser can normalize anything.
	for i := range len(raw) {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return o, false
		}
	}
	if strings.ContainsAny(raw, ",#%") {
		return o, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.HasSuffix(u.Host, ":") {
		return o, false
	}
	o.scheme = u.Scheme
	switch o.scheme {
	case "http":
		o.port = 80
	case "https":
		o.port = 443
	default:
		return o, false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return o, false
		}
		o.port = uint16(n)
	}
	o.host = u.Hostname()
	bracketed := strings.HasPrefix(u.Host, "[")
	if !bracketed {
		o.host = strings.TrimSuffix(o.host, ".")
	}
	o.host = strings.ToLower(o.host)
	if ip, err := netip.ParseAddr(o.host); err == nil {
		if ip.Is6() != bracketed {
			return o, false
		}
		o.host = ip.String()
		o.ip = true
	} else if bracketed || !validHost(o.host, pattern) {
		return o, false
	}
	return o, true
}

func validHost(name string, pattern bool) bool {
	if len(name) > 253 {
		return false
	}
	if pattern {
		name, _ = strings.CutPrefix(name, "*.")
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			letter := c >= 'a' && c <= 'z'
			digit := c >= '0' && c <= '9'
			if !letter && !digit && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}
