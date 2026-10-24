package wsconn

import (
	"encoding/base64"
	"encoding/binary"
	"math/bits"
)

// keyGUID is appended to a Sec-WebSocket-Key to compute the
// Sec-WebSocket-Accept of the response (RFC 6455, section 4.2.2).
const keyGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// AcceptKey returns the Sec-WebSocket-Accept value for the
// Sec-WebSocket-Key key: the base64 of the SHA-1 of key and the protocol's
// GUID.
func AcceptKey(key string) string {
	sum := sha1Sum(key + keyGUID)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// sha1Sum returns the SHA-1 digest of s (RFC 3174). The handshake needs it
// once per connection, and crypto/sha1 would add about 176 KB of FIPS
// machinery to a program (linux/amd64, stripped).
func sha1Sum(s string) [20]byte {
	h := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	n := len(s)
	// The message, a 0x80 byte, zeros and the bit length fill whole blocks.
	padded := make([]byte, (n+8)/64*64+64)
	copy(padded, s)
	padded[n] = 0x80
	binary.BigEndian.PutUint64(padded[len(padded)-8:], uint64(n)*8)
	var w [80]uint32
	for block := padded; len(block) > 0; block = block[64:] {
		for i := range 16 {
			w[i] = binary.BigEndian.Uint32(block[4*i:])
		}
		for i := 16; i < 80; i++ {
			w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}
		a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
		for i := range 80 {
			var f, k uint32
			switch {
			case i < 20:
				f, k = b&c|^b&d, 0x5a827999
			case i < 40:
				f, k = b^c^d, 0x6ed9eba1
			case i < 60:
				f, k = b&c|b&d|c&d, 0x8f1bbcdc
			default:
				f, k = b^c^d, 0xca62c1d6
			}
			t := bits.RotateLeft32(a, 5) + f + e + k + w[i]
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}
	var sum [20]byte
	for i, v := range h {
		binary.BigEndian.PutUint32(sum[4*i:], v)
	}
	return sum
}
