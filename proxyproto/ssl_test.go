package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

// crcHeader returns an encoded version 2 header with a CRC32C field between
// two others, and the offset of the checksum in it.
func crcHeader(t *testing.T) ([]byte, int) {
	t.Helper()
	h, err := NewHeader(V2, tcp("192.0.2.1", 1000), tcp("198.51.100.1", 443))
	if err != nil {
		t.Fatal(err)
	}
	h.TLVs, _ = h.TLVs.Append(TLVAuthority, []byte("example.com"))
	h.TLVs = h.TLVs.AppendCRC32C()
	h.TLVs, _ = h.TLVs.Append(TLVUniqueID, []byte("id"))
	wire, err := h.AppendBinary([]byte("prefix")) // the checksum covers the header alone
	if err != nil {
		t.Fatal(err)
	}
	wire = wire[len("prefix"):]
	off := bytes.Index(wire, []byte{byte(TLVCRC32C), 0, 4}) + 3
	return wire, off
}

func TestCRC32C(t *testing.T) {
	wire, off := crcHeader(t)
	// The checksum is CRC32c (Castagnoli) of the header with the field's
	// value zeroed, in network byte order.
	zeroed := bytes.Clone(wire)
	copy(zeroed[off:off+4], []byte{0, 0, 0, 0})
	if got, want := binary.BigEndian.Uint32(wire[off:]), crc32.Checksum(zeroed, crc32.MakeTable(crc32.Castagnoli)); got != want {
		t.Fatalf("checksum %#x, want %#x", got, want)
	}
	h, n, err := Decode(wire)
	if err != nil || n != len(wire) {
		t.Fatalf("Decode() = %d, %v", n, err)
	}
	// A decoded header re-encodes with a checksum of its own.
	again, err := h.AppendBinary(nil)
	if err != nil || !bytes.Equal(again, wire) {
		t.Fatalf("re-encoded header = %x, %v; want %x", again, err, wire)
	}
	for _, i := range []int{0x0d, off, off + 3, len(wire) - 1} {
		bad := bytes.Clone(wire)
		bad[i] ^= 1
		if _, _, err := Decode(bad); !errors.Is(err, ErrChecksum) || !errors.Is(err, ErrMalformed) {
			t.Fatalf("Decode() with byte %d flipped = %v, want ErrChecksum matching ErrMalformed", i, err)
		}
	}
	// A second CRC32C field, or one of another length, leaves the checksum
	// undefined.
	for _, tlvs := range []TLVs{
		TLVs(nil).AppendCRC32C().AppendCRC32C(),
		{byte(TLVCRC32C), 0, 2, 0, 0},
	} {
		h := &Header{Version: V2, Local: true, TLVs: tlvs}
		if _, err := h.AppendBinary(nil); err == nil {
			t.Fatalf("AppendBinary() with CRC32C fields %x succeeded", tlvs)
		}
		raw := v2Wire(0x20, 0x00, tlvs...)
		if _, _, err := Decode(raw); !errors.Is(err, ErrChecksum) {
			t.Fatalf("Decode() with CRC32C fields %x = %v, want ErrChecksum", tlvs, err)
		}
	}
}

func TestSSL(t *testing.T) {
	var sub TLVs
	sub, _ = sub.Append(TLVSSLVersion, []byte("TLSv1.3"))
	sub, _ = sub.Append(TLVSSLCN, []byte("client.example"))
	sub, _ = sub.Append(TLVSSLCipher, []byte("TLS_AES_128_GCM_SHA256"))
	sub, _ = sub.Append(TLVSSLSigAlg, []byte("SHA256"))
	sub, _ = sub.Append(TLVSSLKeyAlg, []byte("EC256"))
	want := SSL{Client: SSLClientSSL | SSLClientCertConn, TLVs: sub}
	tlvs, err := TLVs(nil).AppendSSL(want)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHeader(V2, tcp("192.0.2.1", 1000), tcp("198.51.100.1", 443))
	if err != nil {
		t.Fatal(err)
	}
	h.TLVs = tlvs
	wire, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := got.TLVs.SSL()
	if !ok || s.Client != want.Client || s.Verify != 0 || !bytes.Equal(s.TLVs, sub) || !s.Verified() {
		t.Fatalf("SSL() = %+v, %v; want %+v", s, ok, want)
	}
	if s.Version() != "TLSv1.3" || s.CommonName() != "client.example" || s.Cipher() != "TLS_AES_128_GCM_SHA256" || s.SigAlg() != "SHA256" || s.KeyAlg() != "EC256" {
		t.Fatalf("SSL sub-fields = %q %q %q %q %q", s.Version(), s.CommonName(), s.Cipher(), s.SigAlg(), s.KeyAlg())
	}
	for _, tt := range []SSL{
		{Client: SSLClientSSL},                                // no certificate
		{Client: SSLClientSSL | SSLClientCertSess, Verify: 1}, // not verified
		{Client: SSLClientCertConn},                           // not over TLS
	} {
		if tt.Verified() {
			t.Fatalf("%+v reports a verified certificate", tt)
		}
	}
	if _, ok := (TLVs{byte(TLVSSL), 0, 4, 1, 0, 0, 0}).SSL(); ok {
		t.Fatal("SSL() of a 4-byte value succeeded")
	}
	if _, err := TLVs(nil).AppendSSL(SSL{TLVs: TLVs{1, 0}}); err == nil {
		t.Fatal("AppendSSL() with cut-short sub-fields succeeded")
	}
}

func FuzzSSL(f *testing.F) {
	f.Add([]byte{0x01, 0, 0, 0, 0, byte(TLVSSLVersion), 0, 3, 'T', 'L', 'S'})
	f.Add([]byte{0x07, 0, 0, 0, 1})
	f.Add([]byte{0x01, 0, 0, 0})
	f.Fuzz(func(t *testing.T, v []byte) {
		if len(v) > 0xffff {
			return
		}
		tlvs, err := TLVs(nil).Append(TLVSSL, v)
		if err != nil {
			t.Fatal(err)
		}
		s, ok := tlvs.SSL()
		if ok != (len(v) >= 5) {
			t.Fatalf("SSL() of a %d-byte value reports %v", len(v), ok)
		}
		if !ok {
			return
		}
		_ = s.Version() + s.CommonName() + s.Cipher() + s.SigAlg() + s.KeyAlg()
		_ = s.Verified()
		out, err := TLVs(nil).AppendSSL(s)
		if s.TLVs.wellFormed() != (err == nil) {
			t.Fatalf("AppendSSL() = %v for sub-fields well formed %v", err, s.TLVs.wellFormed())
		}
		if err == nil && !bytes.Equal(out, tlvs) {
			t.Fatalf("AppendSSL() = %x, want %x", out, tlvs)
		}
	})
}
