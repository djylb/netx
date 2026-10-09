package tlsconn

import (
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"sync"
)

// ErrNotPinned is returned when a peer's certificate is not in a PinSet.
var ErrNotPinned = errors.New("tlsconn: peer certificate is not pinned")

// PinSet is a set of certificate fingerprints, as returned by Fingerprint,
// that are trusted in place of certificate authorities, for peers with
// self-signed certificates. Its methods are safe for concurrent use, so pins
// can change while connections are made. The zero value is an empty set.
type PinSet struct {
	mu   sync.RWMutex
	pins map[[sha256.Size]byte]struct{}
}

// NewPinSet returns a set holding pins.
func NewPinSet(pins ...[sha256.Size]byte) *PinSet {
	s := &PinSet{}
	for _, pin := range pins {
		s.Add(pin)
	}
	return s
}

// Add trusts the certificate with fingerprint pin.
func (s *PinSet) Add(pin [sha256.Size]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pins == nil {
		s.pins = make(map[[sha256.Size]byte]struct{})
	}
	s.pins[pin] = struct{}{}
}

// Remove stops trusting the certificate with fingerprint pin. Connections
// resuming an earlier session are checked again, so they fail too.
func (s *PinSet) Remove(pin [sha256.Size]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pins, pin)
}

// Contains reports whether pin is trusted.
func (s *PinSet) Contains(pin [sha256.Size]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.pins[pin]
	return ok
}

// Len returns the number of pins.
func (s *PinSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pins)
}

// VerifyConnection accepts a connection whose peer presented a pinned leaf
// certificate. Use it as tls.Config.VerifyConnection, which unlike
// VerifyPeerCertificate also runs for resumed sessions, together with
// InsecureSkipVerify to turn off the certificate authority checks that the
// pins replace; ClientConfig sets both. A pin names one exact certificate, so
// its host names and validity dates are not checked: a pinned certificate is
// accepted for any server name and after it expires. On a server it pins
// client certificates, with ClientAuth set to RequireAnyClientCert.
func (s *PinSet) VerifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 || !s.Contains(Fingerprint(cs.PeerCertificates[0].Raw)) {
		return ErrNotPinned
	}
	return nil
}

// ClientConfig returns a copy of base, or a new Config if base is nil, that
// trusts exactly the certificates pinned in s. A VerifyConnection of base
// still runs, after the pin check.
func (s *PinSet) ClientConfig(base *tls.Config) *tls.Config {
	cfg := &tls.Config{}
	if base != nil {
		cfg = base.Clone()
	}
	cfg.InsecureSkipVerify = true
	next := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := s.VerifyConnection(cs); err != nil {
			return err
		}
		if next != nil {
			return next(cs)
		}
		return nil
	}
	return cfg
}
