package tlsconn

import (
	"cmp"
	"container/list"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/djylb/timeshim"
)

// DefaultCheckInterval is how often certificate files are checked for
// changes when CheckInterval is zero.
const DefaultCheckInterval = 10 * time.Second

// expiredRetry bounds how often the files of an expired certificate are read
// again although they look unchanged.
const expiredRetry = time.Minute

// CertError is the error of a certificate that could not be used, as given
// to the OnError hooks of CertFiles and CertStore: a failed read of its
// files, a failed Load, or a Select that named a certificate that does not
// serve. The fields that do not apply are empty.
type CertError struct {
	Err      error
	ID       string // of the certificate in a CertStore
	Name     string // the server name of a Load or Select
	CertFile string
	KeyFile  string
}

func (e *CertError) Error() string {
	msg := "tlsconn: certificate"
	if e.ID != "" {
		msg += " " + e.ID
	}
	if e.Name != "" {
		msg += " for " + e.Name
	}
	if e.CertFile != "" {
		msg += " from " + e.CertFile
	}
	return msg + ": " + e.Err.Error()
}

func (e *CertError) Unwrap() error { return e.Err }

// CertFiles loads certificates from files or PEM data and keeps them for
// reuse, such as in a tls.Config.GetCertificate callback, which runs for every
// handshake. Files are kept in sync: a use at most every CheckInterval looks
// at both files and reads them again only if either changed, so that renewed
// certificates are picked up. Once a certificate has expired, its files are
// also read again when they look unchanged, at most once a minute, so that a
// renewal that kept their size, time and identity is picked up too. A
// certificate is not returned before its NotBefore or from its NotAfter on:
// the loads return ErrNotValidNow. Changed files whose certificate is not
// valid now, such as an old pair copied back, do not replace one that is:
// they are reported to OnError and read again at the next check. If the
// cached certificate is not valid either, they replace it, as they may
// become valid. Its methods are safe for concurrent use, and
// concurrent first loads of one certificate share a single read. The zero
// value is ready to use; set the fields before first use.
type CertFiles struct {
	lastSweep time.Time // under mu
	// Clock tells the time of CheckInterval, IdleTimeout and certificate
	// validity; the system clock if nil.
	Clock timeshim.Clock
	// OnError, if set, is called with each failed read of changed files, as
	// when a certificate was replaced before its key, after which the
	// previous certificate serves on and the next check tries again. It
	// runs in the call that read, which waits for it, and may call the
	// cache's methods. A failed first load is not reported: LoadFiles
	// returns its error.
	OnError func(err *CertError)
	entries map[string]*list.Element // under mu
	lru     list.List                // of *certEntry, most recently used first; under mu
	// MaxEntries bounds the number of cached certificates, the least
	// recently used dropped first; 0 means no bound, unlike other limits,
	// as the caller chooses the files and data, not the clients, and a
	// negative bound is an error.
	MaxEntries int
	// IdleTimeout drops certificates that have not been loaded for this
	// long; 0 means DefaultIdleTimeout (24h), and a negative value keeps
	// them. The cache checks for idle entries during loads.
	IdleTimeout time.Duration
	// CheckInterval is how often a use checks whether the files of a
	// certificate changed: their size, modification time or identity, with
	// symbolic links followed, so that a link swapped to a new pair counts.
	// 0 means DefaultCheckInterval (10s), and a negative value never
	// checks, as a negative net.Dialer.KeepAlive turns keep-alives off. The
	// files of an expired certificate are read again, changed or not, at
	// most once a minute either way.
	CheckInterval time.Duration
	loaded        int // entries with a certificate, which MaxEntries bounds; under mu
	mu            sync.Mutex
}

type certEntry struct {
	lastUsed  time.Time
	err       error         // of the first load
	files     *fileSource   // nil for PEM data
	ready     chan struct{} // closed when the first load ends
	cert      *tls.Certificate
	key       string
	reloading bool
}

func fileKey(certFile, keyFile string) string {
	return "file\x00" + certFile + "\x00" + keyFile
}

// LoadFiles returns the certificate in certFile and keyFile, as
// tls.LoadX509KeyPair reads them, from the cache when it is there and the
// files did not change, or ErrNotValidNow if it is not valid now; see
// CertFiles. A failed read of changed files keeps
// the previous certificate and is reported to OnError. The returned
// certificate is shared and must not be modified.
func (c *CertFiles) LoadFiles(certFile, keyFile string) (*tls.Certificate, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c.get(fileKey(certFile, keyFile), certFile, keyFile, nil)
}

// LoadPEM returns the certificate in certPEM and keyPEM, as tls.X509KeyPair
// parses them, from the cache when the same data was loaded before. The
// returned certificate is shared and must not be modified.
//
// Entries are keyed by the data, so renewed or edited PEM data gets a new
// entry while the old one, private key included, stays until MaxEntries or
// IdleTimeout drops it: set one of them when the data changes over time.
func (c *CertFiles) LoadPEM(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	h := sha256.New()
	var n [8]byte
	h.Write(binary.BigEndian.AppendUint64(n[:0], uint64(len(certPEM))))
	h.Write(certPEM)
	h.Write(keyPEM)
	key := "pem\x00" + string(h.Sum(nil))
	return c.get(key, "", "", func() (*tls.Certificate, error) {
		return parseKeyPair(certPEM, keyPEM)
	})
}

// Len returns the number of cached certificates.
func (c *CertFiles) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Forget drops the certificate cached for certFile and keyFile, so that the
// next LoadFiles reads them again. A load of them that is running still
// returns its result to its callers, but does not cache it.
func (c *CertFiles) Forget(certFile, keyFile string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[fileKey(certFile, keyFile)]; ok {
		c.removeLocked(el)
	}
}

// Clear drops every cached certificate. Loads that are running return their
// results to their callers, but do not cache them.
func (c *CertFiles) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
	c.lru.Init()
	c.loaded = 0
}

// get returns the certificate for key, loaded by load, or from certFile and
// keyFile if load is nil, if it is valid now.
func (c *CertFiles) get(key, certFile, keyFile string, load func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	now := c.now()
	cert, err := c.lookup(now, key, certFile, keyFile, load)
	if err != nil {
		return nil, err
	}
	return deliverCertificate(cert, cert.Leaf, c.now())
}

func (c *CertFiles) lookup(now time.Time, key, certFile, keyFile string, load func() (*tls.Certificate, error)) (*tls.Certificate, error) {
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
		if e.files == nil || e.reloading {
			cert := e.cert
			c.mu.Unlock()
			return cert, nil
		}
		check, force := e.files.due(now, c.CheckInterval, e.cert.Leaf)
		if !check {
			cert := e.cert
			c.mu.Unlock()
			return cert, nil
		}
		// One caller checks while the others use the certificate it has.
		e.reloading = true
		c.mu.Unlock()
		cert, err := e.files.sync(force, c.now, e.cert.Leaf)
		c.mu.Lock()
		e.reloading = false
		if cert != nil {
			e.cert = cert
		}
		cert = e.cert
		onErr := c.OnError
		c.mu.Unlock()
		if err != nil && onErr != nil {
			onErr(&CertError{CertFile: e.files.certFile, KeyFile: e.files.keyFile, Err: err})
		}
		return cert, nil
	}

	e := &certEntry{key: key, ready: make(chan struct{}), lastUsed: now}
	if load == nil {
		e.files = &fileSource{certFile: certFile, keyFile: keyFile, checkedAt: now, forcedAt: now}
		load = e.files.read
	}
	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}
	// Evicted only once the load succeeds, so that a load that fails, such
	// as one for an unknown name, does not push out certificates that work.
	c.entries[key] = c.lru.PushFront(e)
	c.mu.Unlock()

	// PEM data is never read again, so its loader, which holds the caller's
	// PEM, private key included, is not kept.
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
		e.cert = cert
		// Unless Clear or the idle sweep dropped it while it loaded.
		if el, ok := c.entries[key]; ok && el.Value == e {
			c.loaded++
			c.evictLocked()
		}
	}
	close(e.ready)
	c.mu.Unlock()
	return cert, err
}

// evictLocked drops the least recently used loaded entries beyond
// MaxEntries. Entries still loading do not count and are not dropped, so that
// loads that fail, such as for unknown names, push out no certificate.
func (c *CertFiles) evictLocked() {
	if c.MaxEntries <= 0 {
		return
	}
	for el := c.lru.Back(); el != nil && c.loaded > c.MaxEntries; {
		prev := el.Prev()
		if el.Value.(*certEntry).cert != nil {
			c.removeLocked(el)
		}
		el = prev
	}
}

// sweepLocked drops entries idle for IdleTimeout, at most twice per
// IdleTimeout. The list is ordered by last use, so the sweep stops at the
// first entry still in use.
func (c *CertFiles) sweepLocked(now time.Time) {
	idle := cmp.Or(c.IdleTimeout, DefaultIdleTimeout)
	if idle < 0 || now.Sub(c.lastSweep) < idle/2 {
		return
	}
	c.lastSweep = now
	cutoff := now.Add(-idle)
	for el := c.lru.Back(); el != nil; el = c.lru.Back() {
		if !el.Value.(*certEntry).lastUsed.Before(cutoff) {
			return
		}
		c.removeLocked(el)
	}
}

func (c *CertFiles) removeLocked(el *list.Element) {
	e := c.lru.Remove(el).(*certEntry)
	delete(c.entries, e.key)
	if e.cert != nil {
		c.loaded--
	}
}

func (c *CertFiles) now() time.Time { return timeshim.Or(c.Clock).Now() }

// fileSource is a certificate's pair of files and what they were when last
// read successfully. Its owner lets one goroutine at a time use it.
type fileSource struct {
	checkedAt         time.Time   // of the last check
	forcedAt          time.Time   // of the last read of an expired certificate
	cert, key         os.FileInfo // as of the last successful read
	certFile, keyFile string
}

// validate reports a negative setting, which LoadFiles and LoadPEM
// return.
func (c *CertFiles) validate() error {
	if c.MaxEntries < 0 {
		return fmt.Errorf("tlsconn: negative CertFiles.MaxEntries %v", c.MaxEntries)
	}
	return nil
}

// due reports whether the files should be checked now, every interval
// (DefaultCheckInterval if zero, never if negative), and whether they should
// be read even if they look unchanged, as for an expired leaf once a minute.
// It records the check as done.
func (f *fileSource) due(now time.Time, interval time.Duration, leaf *x509.Certificate) (check, force bool) {
	if interval == 0 {
		interval = DefaultCheckInterval
	}
	force = leaf != nil && !now.Before(leaf.NotAfter) && now.Sub(f.forcedAt) >= expiredRetry
	check = force || interval > 0 && now.Sub(f.checkedAt) >= interval
	if check {
		f.checkedAt = now
	}
	if force {
		f.forcedAt = now
	}
	return check, force
}

// sync reads the files when forced or when they changed since the last
// successful read. It returns the new certificate, or nil if it skipped the read.
// A certificate not valid now does not replace current if that is valid
// now, as when an old pair was copied back: it fails with ErrNotValidNow. A
// failed read records nothing, so that the next sync tries again.
func (f *fileSource) sync(force bool, clock func() time.Time, current *x509.Certificate) (*tls.Certificate, error) {
	certInfo, err := os.Stat(f.certFile)
	if err != nil {
		return nil, err
	}
	keyInfo, err := os.Stat(f.keyFile)
	if err != nil {
		return nil, err
	}
	if !force && sameFile(certInfo, f.cert) && sameFile(keyInfo, f.key) {
		return nil, nil
	}
	cert, err := readKeyPair(f.certFile, f.keyFile)
	if err != nil {
		return nil, err
	}
	now := clock()
	if !validAt(cert.Leaf, now) && current != nil && validAt(current, now) {
		return nil, ErrNotValidNow
	}
	// The files as they were before the read: a change during it is seen
	// by the next check.
	f.cert, f.key = certInfo, keyInfo
	return cert, nil
}

// read is the first read of the files.
func (f *fileSource) read() (*tls.Certificate, error) {
	certInfo, certErr := os.Stat(f.certFile)
	keyInfo, keyErr := os.Stat(f.keyFile)
	cert, err := readKeyPair(f.certFile, f.keyFile)
	if err != nil {
		return nil, err
	}
	if certErr == nil && keyErr == nil {
		f.cert, f.key = certInfo, keyInfo
	}
	return cert, nil
}

// sameFile reports whether a and b describe the same, unchanged file.
func sameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && os.SameFile(a, b)
}

// validAt reports whether leaf is valid at now.
func validAt(leaf *x509.Certificate, now time.Time) bool {
	return !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}

// readKeyPair reads a certificate and its key as tls.LoadX509KeyPair does,
// with the leaf parsed.
func readKeyPair(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return withLeaf(cert)
}

// parseKeyPair parses a certificate and its key as tls.X509KeyPair does,
// with the leaf parsed.
func parseKeyPair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return withLeaf(cert)
}

// withLeaf returns cert with its Leaf parsed if it is not set.
func withLeaf(cert tls.Certificate) (*tls.Certificate, error) {
	var err error
	if len(cert.Certificate) == 0 {
		return nil, errNoChain
	}
	if cert.Leaf == nil {
		// Left unset under GODEBUG x509keypairleaf=0.
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &cert, nil
}

var errNoChain = errors.New("tlsconn: certificate has no chain")
