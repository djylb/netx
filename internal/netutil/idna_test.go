package netutil

import "testing"

// Samples of RFC 3492, section 7.1, that hold no uppercase letters.
func TestPunycodeRFC3492(t *testing.T) {
	tests := []struct{ in, want string }{
		{"ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn"},
		{"他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"},
		{"他們爲什麽不說中文", "ihqwctvzc91f659drss3x8bo0yb"},
		{"なぜみんな日本語を話してくれないのか", "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa"},
		{"-> $1.00 <-", "-> $1.00 <--"},
	}
	for _, tt := range tests {
		if got := Punycode(tt.in); got != tt.want {
			t.Errorf("Punycode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
