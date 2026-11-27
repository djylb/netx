// Package httptoken recognizes HTTP tokens (RFC 9110, section 5.6.2).
package httptoken

// tokenChars marks the bytes of a token (RFC 9110, section 5.6.2).
var tokenChars = func() (t [256]bool) {
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
		t[c-'a'+'A'] = true
	}
	for _, c := range "!#$%&'*+-.^_`|~" {
		t[c] = true
	}
	return t
}()

// Contains reports whether b is a token character.
func Contains(b byte) bool { return tokenChars[b] }

// Valid reports whether s contains one nonempty token.
func Valid[T ~string | ~[]byte](s T) bool {
	if len(s) == 0 {
		return false
	}
	for i := range len(s) {
		if !tokenChars[s[i]] {
			return false
		}
	}
	return true
}
