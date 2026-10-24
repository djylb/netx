package wsconn

import (
	"encoding/binary"
	"math/bits"
	"unicode/utf8"
)

// Opcodes (RFC 6455, section 5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xa
)

// Frame header bits.
const (
	finBit  = 0x80
	rsv1Bit = 0x40
	rsv2Bit = 0x20
	rsv3Bit = 0x10
	maskBit = 0x80
)

const (
	// maxHeaderLen is the longest frame header: 2 bytes, an 8-byte length
	// and a 4-byte masking key.
	maxHeaderLen = 14
	// maxControlPayload bounds the payload of control frames.
	maxControlPayload = 125
)

// putHeader encodes a frame header at the end of dst, which holds
// maxHeaderLen bytes, and returns its offset in dst.
func putHeader(dst *[maxHeaderLen]byte, first byte, n int, masked bool, key uint32) int {
	end := maxHeaderLen
	if masked {
		end -= 4
		binary.LittleEndian.PutUint32(dst[end:], key)
	}
	var b1 byte
	if masked {
		b1 = maskBit
	}
	switch {
	case n <= 125:
		end -= 2
		dst[end+1] = b1 | byte(n)
	case n <= 0xffff:
		end -= 4
		dst[end+1] = b1 | 126
		binary.BigEndian.PutUint16(dst[end+2:], uint16(n))
	default:
		end -= 10
		dst[end+1] = b1 | 127
		binary.BigEndian.PutUint64(dst[end+2:], uint64(n))
	}
	dst[end] = first
	return end
}

// headerLen returns the length of a frame header with an n-byte payload.
func headerLen(n int, masked bool) int {
	l := 2
	switch {
	case n > 0xffff:
		l += 8
	case n > 125:
		l += 2
	}
	if masked {
		l += 4
	}
	return l
}

// mask XORs b with the masking key, held as the little-endian uint32 of
// its four bytes, starting at key byte pos (0 to 3), and returns the key
// position after b.
func mask(b []byte, key uint32, pos int) int {
	n := len(b)
	k := bits.RotateLeft32(key, -8*pos)
	if len(b) >= 8 {
		k64 := uint64(k) | uint64(k)<<32
		for len(b) >= 32 {
			v0 := binary.LittleEndian.Uint64(b) ^ k64
			v1 := binary.LittleEndian.Uint64(b[8:]) ^ k64
			v2 := binary.LittleEndian.Uint64(b[16:]) ^ k64
			v3 := binary.LittleEndian.Uint64(b[24:]) ^ k64
			binary.LittleEndian.PutUint64(b, v0)
			binary.LittleEndian.PutUint64(b[8:], v1)
			binary.LittleEndian.PutUint64(b[16:], v2)
			binary.LittleEndian.PutUint64(b[24:], v3)
			b = b[32:]
		}
		for len(b) >= 8 {
			binary.LittleEndian.PutUint64(b, binary.LittleEndian.Uint64(b)^k64)
			b = b[8:]
		}
	}
	for i := range b {
		b[i] ^= byte(k)
		k = bits.RotateLeft32(k, -8)
	}
	return (pos + n) & 3
}

// maskCopy copies src into dst, of at least its length, masked as by mask,
// and returns the key position after it.
func maskCopy(dst, src []byte, key uint32, pos int) int {
	dst = dst[:len(src)]
	k := bits.RotateLeft32(key, -8*pos)
	n := len(src)
	if len(src) >= 8 {
		k64 := uint64(k) | uint64(k)<<32
		for len(src) >= 32 {
			binary.LittleEndian.PutUint64(dst, binary.LittleEndian.Uint64(src)^k64)
			binary.LittleEndian.PutUint64(dst[8:], binary.LittleEndian.Uint64(src[8:])^k64)
			binary.LittleEndian.PutUint64(dst[16:], binary.LittleEndian.Uint64(src[16:])^k64)
			binary.LittleEndian.PutUint64(dst[24:], binary.LittleEndian.Uint64(src[24:])^k64)
			src, dst = src[32:], dst[32:]
		}
		for len(src) >= 8 {
			binary.LittleEndian.PutUint64(dst, binary.LittleEndian.Uint64(src)^k64)
			src, dst = src[8:], dst[8:]
		}
	}
	for i := range src {
		dst[i] = src[i] ^ byte(k)
		k = bits.RotateLeft32(k, -8)
	}
	return (pos + n) & 3
}

// utf8State validates UTF-8 that arrives in pieces, failing as soon as a
// piece cannot be the start of valid text.
type utf8State struct {
	pend [utf8.UTFMax]byte
	n    int // bytes in pend, of an incomplete sequence
}

// write validates the next piece.
func (s *utf8State) write(p []byte) bool {
	if s.n > 0 {
		need := seqLen(s.pend[0])
		for s.n < need && len(p) > 0 {
			s.pend[s.n] = p[0]
			s.n++
			p = p[1:]
		}
		if s.n < need {
			return validPrefix(s.pend[:s.n])
		}
		if !utf8.Valid(s.pend[:need]) {
			return false
		}
		s.n = 0
	}
	// Find an incomplete sequence at the end, which starts in the last
	// three bytes.
	tail := len(p)
	for i := len(p) - 1; i >= 0 && i >= len(p)-3; i-- {
		c := p[i]
		if c < 0x80 {
			break
		}
		if c >= 0xc0 {
			if i+seqLen(c) > len(p) {
				tail = i
			}
			break
		}
	}
	if !utf8.Valid(p[:tail]) {
		return false
	}
	if tail < len(p) {
		s.n = copy(s.pend[:], p[tail:])
		return validPrefix(s.pend[:s.n])
	}
	return true
}

// done reports whether the text ended on a complete sequence, and resets s.
func (s *utf8State) done() bool {
	ok := s.n == 0
	s.n = 0
	return ok
}

// seqLen returns the length of the sequence that starts with c, or 1 for a
// byte that starts none.
func seqLen(c byte) int {
	switch {
	case c >= 0xc2 && c <= 0xdf:
		return 2
	case c >= 0xe0 && c <= 0xef:
		return 3
	case c >= 0xf0 && c <= 0xf4:
		return 4
	}
	return 1
}

// validPrefix reports whether b, shorter than the sequence that its first
// byte starts, can begin a valid sequence.
func validPrefix(b []byte) bool {
	if len(b) == 0 || seqLen(b[0]) <= len(b) {
		return false
	}
	if len(b) == 1 {
		return true
	}
	lo, hi := byte(0x80), byte(0xbf)
	switch b[0] {
	case 0xe0:
		lo = 0xa0
	case 0xed:
		hi = 0x9f
	case 0xf0:
		lo = 0x90
	case 0xf4:
		hi = 0x8f
	}
	if b[1] < lo || b[1] > hi {
		return false
	}
	for _, c := range b[2:] {
		if c < 0x80 || c > 0xbf {
			return false
		}
	}
	return true
}
