package tlsconn

import (
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// storeEntry is what Load brought for a name: a certificate, or an error or
// none until retryAt, or a first load still running until ready is closed.
type storeEntry struct {
	name       string
	ready      chan struct{} // closed when the first load ends
	cert       *tls.Certificate
	notAfter   time.Time
	refreshAt  time.Time // of a certificate
	err        error
	retryAt    time.Time // of a failed load or of none
	lastUsed   time.Time
	refreshing bool
	// reloadNext asks the running load to leave its certificate due, as
	// Refresh during a load does.
	reloadNext bool
}

// Refresh makes the certificate loaded for name due, so that the next
// handshake for it loads it again in the background while it serves on, also
// when a load for it is running, whose certificate is then due, and forgets
// a failed load.
func (s *CertStore) Refresh(name string) {
	name = normalizeName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.entries[name]
	if !ok {
		return
	}
	e := el.Value.(*storeEntry)
	switch {
	case e.refreshing || !isClosed(e.ready):
		e.reloadNext = true
	case e.cert != nil:
		e.refreshAt = time.Time{}
	default:
		s.removeLocked(el)
	}
}

// Forget drops what Load brought for name, a Load still running included,
// whose result then goes only to the handshakes waiting for it, so that the
// next handshake for name waits for a new Load; use Refresh to replace a
// certificate that still serves.
func (s *CertStore) Forget(name string) {
	name = normalizeName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.entries[name]; ok {
		s.removeLocked(el)
	}
}

// loaded returns the certificate that Load brings for name, waiting for it
// until ctx is done, or nil and no error when there is none.
func (s *CertStore) loaded(ctx context.Context, name string, now time.Time) (*tls.Certificate, error) {
	s.mu.Lock()
	s.sweepLocked(now)
	var e *storeEntry
	if el, ok := s.entries[name]; ok {
		e = el.Value.(*storeEntry)
		if e.stale(now) {
			s.removeLocked(el)
			e = nil
		} else {
			s.lru.MoveToFront(el)
		}
	}
	if e == nil {
		e = &storeEntry{name: name, ready: make(chan struct{})}
		s.addLocked(e)
		go s.load(e, false)
	}
	e.lastUsed = now
	if !isClosed(e.ready) {
		s.mu.Unlock()
		select {
		case <-e.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		s.mu.Lock()
	}
	cert, err := e.cert, e.err
	// Not for an entry that Forget, Add or an eviction dropped meanwhile.
	if cert != nil && !e.refreshing && !now.Before(e.refreshAt) && s.current(e) {
		e.refreshing = true
		go s.load(e, true)
	}
	s.mu.Unlock()
	return cert, err
}

// current reports whether e is the entry for its name.
func (s *CertStore) current(e *storeEntry) bool {
	el, ok := s.entries[e.name]
	return ok && el.Value == e
}

// stale reports whether e is done with: a failure or none past retryAt, or
// a certificate past its expiry.
func (e *storeEntry) stale(now time.Time) bool {
	if !isClosed(e.ready) {
		return false
	}
	if e.cert == nil {
		return !now.Before(e.retryAt)
	}
	return !now.Before(e.notAfter)
}

// dropLoaded drops what Load brought for the names that an added
// certificate covers, so that, once it is removed, they are loaded anew.
func (s *CertStore) dropLoaded(names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 {
		return
	}
	for _, name := range names {
		if suffix, ok := strings.CutPrefix(name, "*"); ok {
			for loaded, el := range s.entries {
				if i := strings.IndexByte(loaded, '.'); i > 0 && loaded[i:] == suffix {
					s.removeLocked(el)
				}
			}
		} else if el, ok := s.entries[name]; ok {
			s.removeLocked(el)
		}
	}
}

// load runs Load for e: its first load, or a refresh of the certificate it
// holds, which a failure leaves serving and finding none removes.
func (s *CertStore) load(e *storeEntry, refresh bool) {
	cert, err := s.runLoad(e.name)
	now := s.clock()
	var notBefore, notAfter time.Time
	if err != nil {
		cert = nil
	} else if cert != nil {
		notBefore, notAfter, err = validity(cert)
		if err == nil && (!now.Before(notAfter) || now.Before(notBefore)) {
			// Expired, or not valid yet, as with a skewed issuer clock: a
			// first load fails, to be tried again after RetryAfter, and a
			// refresh leaves the old one serving.
			err = ErrNotValidNow
		}
		if err != nil {
			cert = nil
		}
	}
	s.mu.Lock()
	retryAt := now.Add(positive(s.RetryAfter, DefaultRetryAfter))
	switch {
	case cert != nil:
		same := refresh && e.cert != nil && bytes.Equal(e.cert.Certificate[0], cert.Certificate[0])
		s.setCertLocked(e, cert, notBefore, notAfter, now, same)
	case refresh && err != nil:
		// The certificate serves on until it expires; try again later.
		e.refreshAt = retryAt
	default:
		// A failed first load, or none, as when the name is no longer
		// served.
		e.cert, e.err, e.retryAt = nil, err, retryAt
	}
	if e.reloadNext {
		// Refresh came while this ran: what it loaded may be outdated.
		e.reloadNext = false
		e.refreshAt, e.retryAt = time.Time{}, now
	}
	e.refreshing = false
	if !refresh {
		close(e.ready)
	}
	s.mu.Unlock()
	if err != nil {
		s.report(&CertError{Name: e.name, Err: err})
	}
}

// runLoad calls Load for name, bounded by LoadTimeout also when Load ignores
// its context, and turns a panic into an error.
func (s *CertStore) runLoad(name string) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), positive(s.LoadTimeout, DefaultLoadTimeout))
	defer cancel()
	type result struct {
		cert *tls.Certificate
		err  error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("tlsconn: CertStore.Load panicked: %v", r)}
			}
		}()
		cert, err := s.Load(ctx, name)
		done <- result{cert, err}
	}()
	select {
	case r := <-done:
		return r.cert, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// setCertLocked makes e serve cert, refreshed RefreshBefore or a third of
// its lifetime before notAfter, whichever is shorter, but no sooner than
// RetryAfter from now, or a quarter of its remaining life when a refresh
// brought the same certificate again.
func (s *CertStore) setCertLocked(e *storeEntry, cert *tls.Certificate, notBefore, notAfter, now time.Time, same bool) {
	e.cert, e.notAfter, e.err = cert, notAfter, nil
	e.refreshAt = notAfter.Add(-min(positive(s.RefreshBefore, DefaultRefreshBefore), notAfter.Sub(notBefore)/3))
	wait := positive(s.RetryAfter, DefaultRetryAfter)
	if same {
		wait = max(wait, notAfter.Sub(now)/4)
	}
	if soonest := now.Add(wait); e.refreshAt.Before(soonest) {
		e.refreshAt = soonest
	}
}

func (s *CertStore) addLocked(e *storeEntry) {
	if s.entries == nil {
		s.entries = make(map[string]*list.Element)
	}
	s.entries[e.name] = s.lru.PushFront(e)
	for s.MaxEntries > 0 && s.lru.Len() > s.MaxEntries {
		s.removeLocked(s.lru.Back())
	}
}

func (s *CertStore) removeLocked(el *list.Element) {
	e := s.lru.Remove(el).(*storeEntry)
	delete(s.entries, e.name)
}

// sweepLocked drops entries idle for IdleTimeout, at most twice per
// IdleTimeout. The list is ordered by last use, so the sweep stops at the
// first entry still in use.
func (s *CertStore) sweepLocked(now time.Time) {
	if s.IdleTimeout <= 0 || now.Sub(s.lastSweep) < s.IdleTimeout/2 {
		return
	}
	s.lastSweep = now
	cutoff := now.Add(-s.IdleTimeout)
	for el := s.lru.Back(); el != nil && el.Value.(*storeEntry).lastUsed.Before(cutoff); el = s.lru.Back() {
		s.removeLocked(el)
	}
}

// validity returns the validity period of cert's leaf.
func validity(cert *tls.Certificate) (notBefore, notAfter time.Time, err error) {
	leaf, err := leafOf(cert)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return leaf.NotBefore, leaf.NotAfter, nil
}

// leafOf returns cert's leaf, parsing it if Leaf is not set.
func leafOf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errNoChain
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

// normalizeName lowercases name and drops a trailing dot.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func positive(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

var (
	// ErrNoCertificate is returned by a CertStore that has no certificate
	// for a name.
	ErrNoCertificate = errors.New("tlsconn: no certificate for the server name")
	// ErrNotValidNow is the error of a certificate past its NotAfter or
	// before its NotBefore, as Load or Select may bring or CertFiles may
	// hold.
	ErrNotValidNow = errors.New("tlsconn: certificate is not valid now")
	// ErrUnknownID is the error of a Select that names an ID the CertStore
	// does not hold.
	ErrUnknownID = errors.New("tlsconn: no certificate with that ID")
)
