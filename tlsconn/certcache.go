package tlsconn

import (
	"container/list"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"sync"
	"time"
)

// expiredRetry bounds how often the files of an expired certificate are read
// again when ReloadInterval does not ask for more.
const expiredRetry = time.Minute

// CertCache loads certificates from files or PEM data and keeps them for
// reuse, such as in a tls.Config.GetCertificate callback, which runs for every
// handshake. Its methods are safe for concurrent use, and concurrent first
// loads of one certificate share a single read. The zero value is ready to
// use; set the fields before first use.
type CertCache struct {
	// MaxEntries bounds the number of cached certificates; the least
	// recently used is dropped first. Zero means no bound.
	MaxEntries int
	// ReloadInterval is how long a certificate loaded from files is used
	// before the files are read again, so that renewed certificates are
	// picked up. Zero reads them again only once the certificate has
	// expired, at most once a minute.
	ReloadInterval time.Duration
	// IdleTimeout drops certificates that have not been loaded for this
	// long. Zero keeps them.
	IdleTimeout time.Duration

	mu        sync.Mutex
	entries   map[string]*list.Element
	lru       list.List // of *certEntry, most recently used first
	lastSweep time.Time
}

type certEntry struct {
	key       string
	load      func() (*tls.Certificate, error)
	files     bool
	ready     chan struct{} // closed when the first load ends
	cert      *tls.Certificate
	err       error // of the first load
	loadedAt  time.Time
	lastUsed  time.Time
	reloading bool
}

// LoadFiles returns the certificate in certFile and keyFile, as
// tls.LoadX509KeyPair reads them, from the cache when it is there. The files
// are read again as ReloadInterval says; a failed reload keeps the previous
// certificate. The returned certificate is shared and must not be modified.
func (c *CertCache) LoadFiles(certFile, keyFile string) (*tls.Certificate, error) {
	key := "file\x00" + certFile + "\x00" + keyFile
	return c.get(key, true, func() (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		return &cert, err
	})
}

// LoadPEM returns the certificate in certPEM and keyPEM, as tls.X509KeyPair
// parses them, from the cache when the same data was loaded before. The
// returned certificate is shared and must not be modified.
func (c *CertCache) LoadPEM(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	h := sha256.New()
	var n [8]byte
	h.Write(binary.BigEndian.AppendUint64(n[:0], uint64(len(certPEM))))
	h.Write(certPEM)
	h.Write(keyPEM)
	key := "pem\x00" + string(h.Sum(nil))
	return c.get(key, false, func() (*tls.Certificate, error) {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		return &cert, err
	})
}

// Len returns the number of cached certificates.
func (c *CertCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Clear drops every cached certificate.
func (c *CertCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
	c.lru.Init()
}

func (c *CertCache) get(key string, files bool, load func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	now := time.Now()
	c.mu.Lock()
	c.sweepLocked(now)
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*certEntry)
		c.lru.MoveToFront(el)
		e.lastUsed = now
		if e.cert == nil {
			// The first load is still running.
			c.mu.Unlock()
			<-e.ready
			c.mu.Lock()
			cert, err := e.cert, e.err
			c.mu.Unlock()
			return cert, err
		}
		if !e.files || e.reloading || !c.reloadDue(e, now) {
			cert := e.cert
			c.mu.Unlock()
			return cert, nil
		}
		e.reloading = true
		c.mu.Unlock()
		cert, err := e.load()
		c.mu.Lock()
		e.reloading = false
		e.loadedAt = now
		if err == nil {
			e.cert = cert
		}
		cert = e.cert
		c.mu.Unlock()
		return cert, nil
	}

	e := &certEntry{key: key, load: load, files: files, ready: make(chan struct{}), lastUsed: now}
	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}
	c.entries[key] = c.lru.PushFront(e)
	c.evictLocked()
	c.mu.Unlock()

	cert, err := load()
	c.mu.Lock()
	if err != nil {
		e.err = err
		// Drop the failed entry, unless Clear or eviction already did, so
		// that the next call tries again.
		if el, ok := c.entries[key]; ok && el.Value == e {
			c.lru.Remove(el)
			delete(c.entries, key)
		}
		cert = nil
	} else {
		e.cert, e.loadedAt = cert, now
	}
	close(e.ready)
	c.mu.Unlock()
	return cert, err
}

// reloadDue reports whether the files of e should be read again.
func (c *CertCache) reloadDue(e *certEntry, now time.Time) bool {
	age := now.Sub(e.loadedAt)
	if c.ReloadInterval > 0 && age >= c.ReloadInterval {
		return true
	}
	leaf := e.cert.Leaf
	return leaf != nil && now.After(leaf.NotAfter) && age >= expiredRetry
}

// evictLocked drops the least recently used entries beyond MaxEntries.
func (c *CertCache) evictLocked() {
	for c.MaxEntries > 0 && len(c.entries) > c.MaxEntries {
		c.removeLocked(c.lru.Back())
	}
}

// sweepLocked drops entries idle for IdleTimeout, at most twice per
// IdleTimeout. The list is ordered by last use, so the sweep stops at the
// first entry still in use.
func (c *CertCache) sweepLocked(now time.Time) {
	if c.IdleTimeout <= 0 || now.Sub(c.lastSweep) < c.IdleTimeout/2 {
		return
	}
	c.lastSweep = now
	cutoff := now.Add(-c.IdleTimeout)
	for el := c.lru.Back(); el != nil; el = c.lru.Back() {
		if !el.Value.(*certEntry).lastUsed.Before(cutoff) {
			return
		}
		c.removeLocked(el)
	}
}

func (c *CertCache) removeLocked(el *list.Element) {
	e := c.lru.Remove(el).(*certEntry)
	delete(c.entries, e.key)
}
