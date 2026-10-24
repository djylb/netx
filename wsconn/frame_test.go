package wsconn

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAcceptKey(t *testing.T) {
	// RFC 6455, section 1.3.
	if got := AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("AcceptKey = %q", got)
	}
	for n := range 300 {
		s := strings.Repeat("x", n)
		if sha1Sum(s) != sha1.Sum([]byte(s)) {
			t.Fatalf("sha1Sum of %d bytes differs", n)
		}
	}
}

// TestSHA1Vectors checks sha1Sum against the examples of FIPS 180-2
// (appendix A) and the one-million-'a' vector, and against crypto/sha1
// on random inputs.
func TestSHA1Vectors(t *testing.T) {
	for in, want := range map[string]string{
		"":    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"abc": "a9993e364706816aba3e25717850c26c9cd0d89d",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
		strings.Repeat("a", 1000000):                               "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
	} {
		if got := sha1Sum(in); hex.EncodeToString(got[:]) != want {
			t.Errorf("sha1 of %d bytes: %x, want %s", len(in), got, want)
		}
	}
	r := rand.New(rand.NewPCG(7, 8))
	for range 500 {
		b := make([]byte, r.IntN(4096))
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		if sha1Sum(string(b)) != sha1.Sum(b) {
			t.Fatalf("sha1Sum of %d random bytes differs", len(b))
		}
	}
}

func TestPutHeader(t *testing.T) {
	for _, n := range []int{0, 1, 125, 126, 127, 0xffff, 0x10000, 1 << 30} {
		for _, masked := range []bool{false, true} {
			var hb [maxHeaderLen]byte
			off := putHeader(&hb, finBit|opBinary, n, masked, 0x04030201)
			h := hb[off:]
			if len(h) != headerLen(n, masked) {
				t.Fatalf("n=%d masked=%v: header length %d, want %d", n, masked, len(h), headerLen(n, masked))
			}
			if h[0] != finBit|opBinary || (h[1]&maskBit != 0) != masked {
				t.Fatalf("n=%d: header % x", n, h)
			}
			var got int
			switch l := h[1] & 0x7f; l {
			case 126:
				got = int(binary.BigEndian.Uint16(h[2:]))
			case 127:
				got = int(binary.BigEndian.Uint64(h[2:]))
			default:
				got = int(l)
			}
			if got != n {
				t.Fatalf("length %d, want %d", got, n)
			}
			if masked && !bytes.Equal(h[len(h)-4:], []byte{1, 2, 3, 4}) {
				t.Fatalf("key % x", h[len(h)-4:])
			}
		}
	}
}

func naiveMask(b []byte, key [4]byte, pos int) {
	for i := range b {
		b[i] ^= key[(pos+i)&3]
	}
}

func TestMask(t *testing.T) {
	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	k := binary.LittleEndian.Uint32(key[:])
	for n := range 100 {
		for pos := range 4 {
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i * 7)
			}
			want := bytes.Clone(src)
			naiveMask(want, key, pos)
			got := bytes.Clone(src)
			if p := mask(got, k, pos); p != (pos+n)&3 || !bytes.Equal(got, want) {
				t.Fatalf("mask n=%d pos=%d: %d % x, want % x", n, pos, p, got, want)
			}
			dst := make([]byte, n)
			if p := maskCopy(dst, src, k, pos); p != (pos+n)&3 || !bytes.Equal(dst, want) {
				t.Fatalf("maskCopy n=%d pos=%d", n, pos)
			}
			// Masking in two pieces continues the key.
			got = bytes.Clone(src)
			p := mask(got[:n/3], k, pos)
			mask(got[n/3:], k, p)
			if !bytes.Equal(got, want) {
				t.Fatalf("split mask n=%d pos=%d", n, pos)
			}
		}
	}
}

func TestUTF8State(t *testing.T) {
	samples := []string{
		"", "hello", "héllo", "日本語", "🙂🙂", "a\xffb", "\xed\xa0\x80", "\xf4\x90\x80\x80",
		"\xe0\x80\xaf", "\xc0\xaf", "κόσμε", "\xce\xba\xe1\xbd", "\xf0\x9f\x99", "\x80", "abc\xe2\x82\xac",
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		var b []byte
		for range r.IntN(6) {
			b = append(b, samples[r.IntN(len(samples))]...)
		}
		want := utf8.Valid(b)
		var s utf8State
		ok := true
		for rest := b; len(rest) > 0 && ok; {
			k := r.IntN(len(rest) + 1)
			ok = s.write(rest[:k])
			rest = rest[k:]
		}
		ok = ok && s.done()
		if ok != want {
			t.Fatalf("% x: valid %v, want %v", b, ok, want)
		}
	}
}

func TestUTF8StateFailsFast(t *testing.T) {
	var s utf8State
	// 0xed 0xa0 starts a surrogate, which can never be completed.
	if s.write([]byte("ok\xed\xa0")) {
		t.Fatal("surrogate prefix accepted")
	}
	s = utf8State{}
	if !s.write([]byte("ok\xe2\x82")) || !s.write([]byte("\xac")) || !s.done() {
		t.Fatal("split euro sign refused")
	}
}

func TestStatusCodeSendable(t *testing.T) {
	for code, want := range map[StatusCode]bool{
		999: false, 1000: true, 1003: true, 1004: false, 1005: false, 1006: false,
		1007: true, 1011: true, 1014: true, 1015: false, 1016: false, 2999: false, 3000: true, 4999: true, 5000: false,
	} {
		if code.Sendable() != want {
			t.Errorf("%d.Sendable() = %v", code, !want)
		}
	}
	// The named codes: those that only report a state are never sent.
	for code, want := range map[StatusCode]bool{
		StatusNormalClosure: true, StatusGoingAway: true, StatusProtocolError: true,
		StatusUnsupportedData: true, StatusNoStatusReceived: false, StatusAbnormalClosure: false,
		StatusInvalidPayload: true, StatusPolicyViolation: true, StatusMessageTooBig: true,
		StatusMandatoryExtension: true, StatusInternalError: true, StatusServiceRestart: true,
		StatusTryAgainLater: true, StatusBadGateway: true, StatusTLSHandshake: false,
	} {
		if code.Sendable() != want {
			t.Errorf("%d.Sendable() = %v", code, !want)
		}
	}
}
