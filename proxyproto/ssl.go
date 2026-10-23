package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// SSLClient holds the client flags of an SSL field (PP2_CLIENT_*).
type SSLClient uint8

// Client flags of an SSL field.
const (
	SSLClientSSL      SSLClient = 0x01 // the client connected over TLS
	SSLClientCertConn SSLClient = 0x02 // the client sent a certificate on this connection
	SSLClientCertSess SSLClient = 0x04 // the client sent a certificate in the TLS session it resumed
)

// SSL is the value of an SSL field (PP2_TYPE_SSL): what the proxy that ended
// the client's TLS connection tells of it. Read it with TLVs.SSL and send it
// with TLVs.AppendSSL. Like the addresses, it is to be believed only from
// trusted proxies.
type SSL struct {
	// Client holds the client flags.
	Client SSLClient
	// Verify is zero when the client sent a certificate that the proxy
	// verified, and otherwise not zero, such as an X.509 verification
	// result code.
	Verify uint32
	// TLVs holds the sub-fields, such as TLVSSLVersion and TLVSSLCN. Those
	// of a decoded field share the header's memory.
	TLVs TLVs
}

// SSL returns the value of the first SSL field of f. It reports false when
// there is none or its value is shorter than the client flags and the
// verify field. The sub-fields end at the first truncated one, as f's do.
func (f TLVs) SSL() (SSL, bool) {
	v, ok := f.Get(TLVSSL)
	if !ok || len(v) < 5 {
		return SSL{}, false
	}
	return SSL{Client: SSLClient(v[0]), Verify: binary.BigEndian.Uint32(v[1:5]), TLVs: v[5:]}, true
}

// AppendSSL appends an SSL field with the value s. It fails, leaving the
// fields unchanged, for sub-fields that are not a sequence of whole fields
// or a value longer than 65535 bytes.
func (f TLVs) AppendSSL(s SSL) (TLVs, error) {
	if !s.TLVs.wellFormed() {
		return f, errors.New("proxyproto: SSL sub-fields cut short")
	}
	if 5+len(s.TLVs) > 0xffff {
		return f, fmt.Errorf("proxyproto: SSL value of %d bytes", 5+len(s.TLVs))
	}
	out := append(f, byte(TLVSSL))
	out = binary.BigEndian.AppendUint16(out, uint16(5+len(s.TLVs)))
	out = append(out, byte(s.Client))
	out = binary.BigEndian.AppendUint32(out, s.Verify)
	return append(out, s.TLVs...), nil
}

// Verified reports whether the client sent a certificate, on this
// connection or in the session it resumed, that the proxy verified.
func (s SSL) Verified() bool {
	return s.Client&SSLClientSSL != 0 && s.Client&(SSLClientCertConn|SSLClientCertSess) != 0 && s.Verify == 0
}

// Version returns the TLS version that the client connected with, such as
// "TLSv1.3", or "" if the proxy did not tell it.
func (s SSL) Version() string { return s.sub(TLVSSLVersion) }

// CommonName returns the Common Name of the subject of the client's
// certificate, or "" if the proxy did not tell it.
func (s SSL) CommonName() string { return s.sub(TLVSSLCN) }

// Cipher returns the cipher suite of the client's connection, such as
// "ECDHE-RSA-AES128-GCM-SHA256", or "" if the proxy did not tell it.
func (s SSL) Cipher() string { return s.sub(TLVSSLCipher) }

// SigAlg returns the algorithm that signed the client's certificate, such
// as "SHA256", or "" if the proxy did not tell it.
func (s SSL) SigAlg() string { return s.sub(TLVSSLSigAlg) }

// KeyAlg returns the algorithm of the key of the client's certificate, such
// as "RSA2048", or "" if the proxy did not tell it.
func (s SSL) KeyAlg() string { return s.sub(TLVSSLKeyAlg) }

func (s SSL) sub(t TLVType) string {
	v, _ := s.TLVs.Get(t)
	return string(v)
}
