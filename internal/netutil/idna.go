package netutil

import (
	"strings"
	"unicode/utf8"
)

// MaxLabelLen is the longest label of a DNS name.
const MaxLabelLen = 63

// IsASCII reports whether s holds ASCII alone.
func IsASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// ToASCII lowercases name and converts its non-ASCII labels to A-labels,
// or returns ok false if it is not valid UTF-8 or a label is too long.
func ToASCII(name string) (string, bool) {
	if !utf8.ValidString(name) {
		return "", false
	}
	var b strings.Builder
	first := true
	for label := range strings.SplitSeq(strings.ToLower(name), ".") {
		if !first {
			b.WriteByte('.')
		}
		first = false
		if IsASCII(label) {
			b.WriteString(label)
			continue
		}
		if utf8.RuneCountInString(label) > MaxLabelLen {
			return "", false
		}
		b.WriteString("xn--")
		b.WriteString(Punycode(label))
	}
	return b.String(), true
}

// Punycode parameters of RFC 3492.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 0x80
)

// Punycode encodes a label of valid UTF-8 by RFC 3492, without the "xn--"
// prefix. Labels are short (at most 63 runes), so the quadratic encoding
// does not matter and its integers cannot overflow.
func Punycode(label string) string {
	runes := []rune(label)
	out := make([]byte, 0, 2*len(label))
	for _, r := range runes {
		if r < pcInitialN {
			out = append(out, byte(r))
		}
	}
	basic := len(out)
	handled := basic
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := rune(pcInitialN), 0, pcInitialBias
	for handled < len(runes) {
		m := utf8.MaxRune + 1
		for _, r := range runes {
			if r >= n && r < m {
				m = r
			}
		}
		delta += int(m-n) * (handled + 1)
		n = m
		for _, r := range runes {
			if r < n {
				delta++
			}
			if r != n {
				continue
			}
			q := delta
			for k := pcBase; ; k += pcBase {
				t := min(max(k-bias, pcTMin), pcTMax)
				if q < t {
					break
				}
				out = append(out, punyDigit(t+(q-t)%(pcBase-t)))
				q = (q - t) / (pcBase - t)
			}
			out = append(out, punyDigit(q))
			bias = punyAdapt(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		delta++
		n++
	}
	return string(out)
}

func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func punyAdapt(delta, points int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / points
	k := 0
	for delta > (pcBase-pcTMin)*pcTMax/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}
