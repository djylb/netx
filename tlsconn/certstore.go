package tlsconn

import (
	"cmp"
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultRetryAfter is how long a failed CertStore load is remembered
	// when RetryAfter is not positive.
	DefaultRetryAfter = 10 * time.Second
	// DefaultRefreshBefore is how long before expiry a loaded certificate is
	// loaded again when RefreshBefore is not positive.
	DefaultRefreshBefore = 24 * time.Hour
	// DefaultLoadTimeout bounds a CertStore load when LoadTimeout is not
	// positive.
	DefaultLoadTimeout = 30 * time.Second
)

// CertStore holds certificates by ID and picks one for each TLS handshake,
// for a tls.Config's GetCertificate.
//
// Certificates are added with Add, AddPEM or AddFiles, whose files are kept
// in sync as CertFiles does, under an ID of the caller's choosing, else, for
// AddFiles, the path of the certificate file, and for Add and AddPEM the
// leaf's fingerprint (CertID). A fingerprint names one exact certificate, so
// give a certificate that gets renewed a stable ID, such as the ID of the
// host configuration that names it, or its domain. Each serves the names of its leaf, DNS names
// (wildcards such as *.example.com included) and IP addresses, or the names
// given when it is added. One name can match several certificates, issued by
// an authority or self-signed, for the name exactly or by wildcard.
//
// A handshake gets, in this order:
//
//   - the certificate that Select names, as from the configuration of the
//     requested host, whatever names it has;
//   - else the best added certificate for the server name: one the client
//     can use (by its ClientHelloInfo.SupportsCertificate) over one it
//     cannot, then one that verifies against Roots (issued by an authority)
//     over one that does not, then one for the name exactly over a wildcard
//     for its parent, such as *.example.com for www.example.com, but not for
//     example.com or a.www.example.com; then the one valid longer, then the
//     one added last;
//   - else the certificate that Load brings for the name, if Load is set;
//   - else the one SetDefault names, which also serves clients that send no
//     name and connected to an address no certificate is for.
//
// No certificate serves before its NotBefore or past its NotAfter. Names are
// matched in their ASCII form, as SNI carries them (punycode for
// international names), without case and without a trailing dot. Match shows
// the candidates for a name in this order.
//
// Load fetches certificates on demand. Concurrent handshakes for a name share
// one Load, which runs on its own, so that a handshake that gives up does not
// end it for the others. A loaded certificate is loaded again in the
// background before it expires, RefreshBefore or a third of its lifetime
// ahead, whichever is shorter, while it serves on, also when that load fails,
// as when its source cannot be reached, or brings one that is not valid now.
// A failed Load, or one that found no certificate, is remembered for
// RetryAfter, so that a name without a certificate does not make every
// handshake wait. The names come from clients, so a public server should
// bound the loaded names with MaxEntries or IdleTimeout, and Load should turn
// names it does not serve away cheaply, as every new name makes a Load.
//
// Failures that no handshake sees, such as a renewed file that does not
// read, a background refresh that fails, or a Select that names a
// certificate that does not serve, go to OnError.
//
// Its methods are safe for concurrent use. The zero value is ready to use;
// set the fields before first use.
type CertStore struct {
	// Select, if set, names the certificate for a handshake by its ID, such
	// as the one the requested host's configuration names, or returns ""
	// to leave the choice to the order above. It is served even if it is
	// not for the requested name. An ID the store does not hold, or of a
	// certificate not valid now, is reported to OnError and the choice is
	// left to the order above. An error fails the handshake.
	Select func(hello *tls.ClientHelloInfo) (id string, err error)
	// Roots are the authorities that issued certificates are verified
	// against when added or read again, with their chain as intermediates;
	// nil means the system roots. Add a private authority here for its
	// certificates to rank as issued.
	Roots *x509.CertPool
	// CheckInterval is how often the files of AddFiles certificates are
	// checked for changes, as in CertFiles; DefaultCheckInterval if zero,
	// never if negative. The files of an expired certificate are read
	// again, changed or not, at most once a minute either way. The checks
	// run in the background, started by handshakes; CheckFiles runs one at
	// once.
	CheckInterval time.Duration

	// Load, if set, returns the certificate for a name that no added one is
	// for, such as from a central store or by issuing one, or nil and no
	// error when there is none; a refresh that finds none stops the name's
	// certificate serving. A certificate not valid now, past its NotAfter
	// or before its NotBefore, fails the Load, which is tried again after
	// RetryAfter; on a refresh the old one serves on.
	// ctx ends after LoadTimeout, and a Load that has not returned by then
	// fails, while its call goes on until it returns. A panic in Load fails
	// it too. Calls for one name may overlap, as after RetryAfter, Forget or
	// an eviction while an earlier call has not returned.
	Load func(ctx context.Context, name string) (*tls.Certificate, error)
	// LoadTimeout bounds a Load; DefaultLoadTimeout if not positive.
	LoadTimeout time.Duration
	// RetryAfter is how long a failed Load, or one that found no
	// certificate, is remembered before Load runs again for the name, and
	// the least time between the loads of a certificate due for refresh;
	// DefaultRetryAfter if not positive.
	RetryAfter time.Duration
	// RefreshBefore is how long before a loaded certificate expires that it
	// is loaded again, at most a third of its lifetime;
	// DefaultRefreshBefore if not positive.
	RefreshBefore time.Duration
	// MaxEntries bounds the loaded names, failed ones included; the least
	// recently used is dropped first. Zero means no bound.
	MaxEntries int
	// IdleTimeout drops loaded names that no handshake used for this long.
	// Zero keeps them.
	IdleTimeout time.Duration

	// OnError, if set, is called with each failure that no handshake may
	// see: a failed read of changed files, which leaves the previous
	// certificate serving; a failed Load, first or refresh; a Select that
	// names a certificate the store does not hold (ErrUnknownID) or that
	// is not valid now (ErrNotValidNow). It runs without locks held, in a
	// handshake or a background goroutine, and may call the store's
	// methods.
	OnError func(err *CertError)

	addMu     sync.RWMutex
	byID      map[string]*storeCert
	exact     map[string]*certList // by name
	wild      map[string]*certList // by the suffix of a wildcard, such as .example.com
	defaultID string
	seq       uint64
	nFiles    atomic.Int64 // added certificates with files
	nextCheck atomic.Int64 // when the files are next checked, in Unix nanoseconds
	checkMu   sync.Mutex   // held by a check of the files

	mu        sync.Mutex // of what Load brought
	entries   map[string]*list.Element
	lru       list.List // of *storeEntry, most recently used first
	lastSweep time.Time

	now func() time.Time // time.Now when nil; set by tests
}

// CertSource is how a certificate came into a CertStore.
type CertSource uint8

const (
	SourceAdd   CertSource = iota // Add
	SourcePEM                     // AddPEM
	SourceFiles                   // AddFiles
	SourceLoad                    // Load
)

func (s CertSource) String() string {
	switch s {
	case SourceAdd:
		return "add"
	case SourcePEM:
		return "pem"
	case SourceFiles:
		return "files"
	case SourceLoad:
		return "load"
	}
	return "unknown"
}

// CertRole is why Match lists a certificate.
type CertRole uint8

const (
	// RoleNone is the role of the certificates that List returns.
	RoleNone CertRole = iota
	// RoleCandidate is an added certificate for the name.
	RoleCandidate
	// RoleLoaded is the certificate that Load brought for the name.
	RoleLoaded
	// RoleDefault is the default, for when no certificate above serves.
	RoleDefault
)

func (r CertRole) String() string {
	switch r {
	case RoleNone:
		return "none"
	case RoleCandidate:
		return "candidate"
	case RoleLoaded:
		return "loaded"
	case RoleDefault:
		return "default"
	}
	return "unknown"
}

// CertInfo describes a certificate of a CertStore, as Match and List return.
type CertInfo struct {
	ID string // empty for one that Load brought
	// Names are the names it serves.
	Names               []string
	NotBefore, NotAfter time.Time
	// CertFile and KeyFile are the files of one added with AddFiles.
	CertFile, KeyFile string
	Leaf              *x509.Certificate
	Source            CertSource
	// Role is why Match lists it.
	Role CertRole
	// Authority reports whether it verifies against the store's Roots.
	Authority bool
	// Wildcard reports whether it matched the name of Match by a wildcard.
	Wildcard bool
	// Default reports whether it is the one SetDefault names, also when
	// Match lists it as a candidate.
	Default bool
	// Valid reports whether it is valid now, between NotBefore and
	// NotAfter; only valid certificates serve.
	Valid bool
}

// storeCert is an added certificate. It does not change: a read of changed
// files replaces it.
type storeCert struct {
	id                  string
	cert                *tls.Certificate // with Leaf set
	names               []string
	given               []string // the names given when added, if any
	notBefore, notAfter time.Time
	seq                 uint64      // of when it was added
	files               *fileSource // for SourceFiles; used under checkMu
	authority           bool
	source              CertSource
}

func (c *storeCert) valid(now time.Time) bool {
	return !now.Before(c.notBefore) && now.Before(c.notAfter)
}

// certList holds the certificates for a name, or for a wildcard, the nAuth
// issued by an authority first, each part by later NotAfter, then by later
// addition.
type certList struct {
	certs []*storeCert
	nAuth int
}

func (l *certList) issued() []*storeCert {
	if l == nil {
		return nil
	}
	return l.certs[:l.nAuth]
}

func (l *certList) others() []*storeCert {
	if l == nil {
		return nil
	}
	return l.certs[l.nAuth:]
}

// CertID returns the ID that CertStore.Add and AddPEM give cert when added
// without one: the lowercase hex SHA-256 fingerprint of its leaf, as
// Fingerprint returns it. AddFiles uses the certificate file's path instead.
// A fingerprint names one exact certificate, so a renewal gets another. It
// returns "" for a certificate without a chain.
func CertID(cert *tls.Certificate) string {
	if cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	fp := Fingerprint(cert.Certificate[0])
	return hex.EncodeToString(fp[:])
}

// Add adds cert under id, replacing what id held; an empty id means
// CertID(cert), the hex SHA-256 fingerprint of its leaf, which a renewal
// changes: give a certificate that gets renewed a stable ID, such as its
// domain, so that Select and SetDefault keep naming it. It serves names, if
// given, else the DNS names and IP addresses of its leaf. Add returns the ID.
// The certificate is shared and must not be modified; Add does not change
// it.
func (s *CertStore) Add(id string, cert *tls.Certificate, names ...string) (string, error) {
	c, err := s.newCert(id, cert, normalizeNames(names), SourceAdd, nil)
	if err != nil {
		return "", err
	}
	s.put(c, nil)
	return c.id, nil
}

// AddPEM is Add for the certificate in certPEM and keyPEM, as tls.X509KeyPair
// parses them.
func (s *CertStore) AddPEM(id string, certPEM, keyPEM []byte, names ...string) (string, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", err
	}
	c, err := s.newCert(id, &cert, normalizeNames(names), SourcePEM, nil)
	if err != nil {
		return "", err
	}
	s.put(c, nil)
	return c.id, nil
}

// AddFiles is Add for the certificate in certFile and keyFile, as
// tls.LoadX509KeyPair reads them, which are then kept in sync: see
// CheckInterval. An empty id means certFile as given, cleaned by
// filepath.Clean, so that the ID stays when the files are renewed. A failed
// read of changed files, or changed files whose certificate is not valid now
// while the previous one is, leaves the previous certificate serving and goes
// to OnError, and the next check reads them again.
func (s *CertStore) AddFiles(id, certFile, keyFile string, names ...string) (string, error) {
	if id == "" {
		id = filepath.Clean(certFile)
	}
	now := s.clock()
	src := &fileSource{certFile: certFile, keyFile: keyFile, checkedAt: now, forcedAt: now}
	cert, err := src.read()
	if err != nil {
		return "", err
	}
	c, err := s.newCert(id, cert, normalizeNames(names), SourceFiles, src)
	if err != nil {
		return "", err
	}
	s.put(c, nil)
	return c.id, nil
}

// Remove removes the certificate with id and reports whether there was one.
func (s *CertStore) Remove(id string) bool {
	s.addMu.Lock()
	defer s.addMu.Unlock()
	c, ok := s.byID[id]
	if ok {
		s.unindexLocked(c)
		delete(s.byID, id)
		if c.files != nil {
			s.nFiles.Add(-1)
		}
	}
	return ok
}

// Certificate returns the certificate with id, valid now or not.
func (s *CertStore) Certificate(id string) (*tls.Certificate, bool) {
	s.addMu.RLock()
	defer s.addMu.RUnlock()
	if c, ok := s.byID[id]; ok {
		return c.cert, true
	}
	return nil, false
}

// SetDefault names the certificate that serves when no other does; see
// CertStore. It serves while the store holds a valid certificate with id,
// which it need not hold yet. An empty id means none.
func (s *CertStore) SetDefault(id string) {
	s.addMu.Lock()
	defer s.addMu.Unlock()
	s.defaultID = id
}

// GetCertificate returns the certificate for hello; see CertStore. It has the
// signature of tls.Config.GetCertificate.
func (s *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ctx := hello.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return s.certificate(ctx, hello)
}

func (s *CertStore) certificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := s.clock()
	s.checkFilesIfDue(now)
	if s.Select != nil {
		id, err := s.Select(hello)
		if err != nil {
			return nil, err
		}
		if id != "" {
			cert, err := s.byIDNow(id, now)
			if err == nil {
				return cert, nil
			}
			s.report(&CertError{ID: id, Name: hello.ServerName, Err: err})
		}
	}
	name := normalizeName(hello.ServerName)
	if name == "" {
		if ip := localIP(hello); ip != "" {
			if c := s.best(hello, ip, false, now); c != nil {
				return c, nil
			}
		}
		return s.defaultCert(now)
	}
	if c := s.best(hello, name, true, now); c != nil {
		return c, nil
	}
	if s.Load != nil {
		if c, err := s.loaded(ctx, name, now); c != nil || err != nil {
			return c, err
		}
	}
	return s.defaultCert(now)
}

// byIDNow returns the certificate with id if it is valid now.
func (s *CertStore) byIDNow(id string, now time.Time) (*tls.Certificate, error) {
	s.addMu.RLock()
	defer s.addMu.RUnlock()
	c, ok := s.byID[id]
	switch {
	case !ok:
		return nil, ErrUnknownID
	case !c.valid(now):
		return nil, ErrNotValidNow
	}
	return c.cert, nil
}

// best returns the best added certificate for name that is valid now, or
// nil; see CertStore. Wildcards are not looked at for IP addresses.
func (s *CertStore) best(hello *tls.ClientHelloInfo, name string, wildcards bool, now time.Time) *tls.Certificate {
	s.addMu.RLock()
	defer s.addMu.RUnlock()
	exact := s.exact[name]
	var wild *certList
	if i := strings.IndexByte(name, '.'); wildcards && i > 0 {
		wild = s.wild[name[i:]]
	}
	if exact == nil && wild == nil {
		return nil
	}
	// The best valid one serves if the client can use none. The client's
	// support, which costs allocations, is asked only once there is a
	// choice.
	var first *tls.Certificate
	asked := false
	for _, part := range [...][]*storeCert{exact.issued(), wild.issued(), exact.others(), wild.others()} {
		for _, c := range part {
			if !c.valid(now) {
				continue
			}
			if first == nil {
				first = c.cert
				continue
			}
			if !asked {
				asked = true
				if hello.SupportsCertificate(first) == nil {
					return first
				}
			}
			if hello.SupportsCertificate(c.cert) == nil {
				return c.cert
			}
		}
	}
	return first
}

func (s *CertStore) defaultCert(now time.Time) (*tls.Certificate, error) {
	s.addMu.RLock()
	defer s.addMu.RUnlock()
	if c, ok := s.byID[s.defaultID]; ok && c.valid(now) {
		return c.cert, nil
	}
	return nil, ErrNoCertificate
}

// localIP returns the address that the client of hello connected to, for
// clients that send no server name.
func localIP(hello *tls.ClientHelloInfo) string {
	if hello.Conn == nil {
		return ""
	}
	switch a := hello.Conn.LocalAddr().(type) {
	case *net.TCPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	}
	return ""
}

// Match returns the certificates for name in the order of CertStore, without
// the client's support, which only a handshake knows, each once and with the
// Role of its first place: the added ones valid now, then those not valid
// now, as RoleCandidate, then the one Load brought, as RoleLoaded, then the
// default, as RoleDefault unless it is a candidate. Without a name, it
// returns the default.
func (s *CertStore) Match(name string) []CertInfo {
	name = normalizeName(name)
	now := s.clock()
	var infos []CertInfo
	if name != "" {
		s.addMu.RLock()
		exact := s.exact[name]
		var wild *certList
		if i := strings.IndexByte(name, '.'); i > 0 && net.ParseIP(name) == nil {
			wild = s.wild[name[i:]]
		}
		var invalid []CertInfo
		parts := [...]struct {
			certs    []*storeCert
			wildcard bool
		}{{exact.issued(), false}, {wild.issued(), true}, {exact.others(), false}, {wild.others(), true}}
		for _, part := range parts {
			for _, c := range part.certs {
				info := c.info(now, s.defaultID)
				info.Role, info.Wildcard = RoleCandidate, part.wildcard
				if info.Valid {
					infos = append(infos, info)
				} else {
					invalid = append(invalid, info)
				}
			}
		}
		s.addMu.RUnlock()
		infos = append(infos, invalid...)

		s.mu.Lock()
		if el, ok := s.entries[name]; ok {
			if e := el.Value.(*storeEntry); isClosed(e.ready) && e.cert != nil {
				info := loadedInfo(name, e.cert, now)
				info.Role = RoleLoaded
				infos = append(infos, info)
			}
		}
		s.mu.Unlock()
	}
	s.addMu.RLock()
	if c, ok := s.byID[s.defaultID]; ok && !slices.ContainsFunc(infos, func(i CertInfo) bool { return i.ID == c.id }) {
		info := c.info(now, s.defaultID)
		info.Role = RoleDefault
		infos = append(infos, info)
	}
	s.addMu.RUnlock()
	return infos
}

// List returns the added certificates, ordered by ID.
func (s *CertStore) List() []CertInfo {
	now := s.clock()
	s.addMu.RLock()
	infos := make([]CertInfo, 0, len(s.byID))
	for _, c := range s.byID {
		infos = append(infos, c.info(now, s.defaultID))
	}
	s.addMu.RUnlock()
	slices.SortFunc(infos, func(a, b CertInfo) int { return strings.Compare(a.ID, b.ID) })
	return infos
}

func (c *storeCert) info(now time.Time, defaultID string) CertInfo {
	info := CertInfo{
		ID:        c.id,
		Source:    c.source,
		Names:     slices.Clone(c.names),
		Authority: c.authority,
		Default:   defaultID != "" && c.id == defaultID,
		Valid:     c.valid(now),
		NotBefore: c.notBefore,
		NotAfter:  c.notAfter,
		Leaf:      c.cert.Leaf,
	}
	if c.files != nil {
		info.CertFile, info.KeyFile = c.files.certFile, c.files.keyFile
	}
	return info
}

func loadedInfo(name string, cert *tls.Certificate, now time.Time) CertInfo {
	info := CertInfo{Source: SourceLoad, Names: []string{name}}
	if leaf, err := leafOf(cert); err == nil {
		info.Names = leafNames(leaf)
		info.NotBefore, info.NotAfter, info.Leaf = leaf.NotBefore, leaf.NotAfter, leaf
		info.Valid = !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
	}
	return info
}

// CheckFiles checks the files of the certificates added with AddFiles now,
// reading those that changed, as the checks every CheckInterval do, and
// returns once done.
func (s *CertStore) CheckFiles() {
	s.checkMu.Lock()
	errs := s.syncFiles(s.clock(), true)
	s.checkMu.Unlock()
	s.reportAll(errs)
}

// checkFilesIfDue starts a check of the files in the background when one is
// due and none is running.
func (s *CertStore) checkFilesIfDue(now time.Time) {
	if s.nFiles.Load() == 0 || now.UnixNano() < s.nextCheck.Load() || !s.checkMu.TryLock() {
		return
	}
	every := expiredRetry // for the expired, also when changes are not checked
	if s.CheckInterval == 0 {
		every = min(every, DefaultCheckInterval)
	} else if s.CheckInterval > 0 {
		every = min(every, s.CheckInterval)
	}
	s.nextCheck.Store(now.Add(every).UnixNano())
	go func() {
		errs := s.syncFiles(now, false)
		s.checkMu.Unlock()
		s.reportAll(errs)
	}()
}

// syncFiles checks the files of the certificates that are due, or of all,
// and replaces those whose files changed. It runs under checkMu and returns
// the failures, for OnError once checkMu is released.
func (s *CertStore) syncFiles(now time.Time, all bool) []*CertError {
	var errs []*CertError
	s.addMu.RLock()
	var due []*storeCert
	for _, c := range s.byID {
		if c.files != nil {
			due = append(due, c)
		}
	}
	s.addMu.RUnlock()
	for _, c := range due {
		check, force := c.files.due(now, s.CheckInterval, c.cert.Leaf)
		if !check && !all {
			continue
		}
		cert, err := c.files.sync(force, now, c.cert.Leaf)
		if err == nil && cert != nil {
			var renewed *storeCert
			if renewed, err = s.newCert(c.id, cert, c.given, SourceFiles, c.files); err == nil {
				s.put(renewed, c)
			}
		}
		if err != nil {
			errs = append(errs, &CertError{ID: c.id, CertFile: c.files.certFile, KeyFile: c.files.keyFile, Err: err})
		}
	}
	return errs
}

func (s *CertStore) reportAll(errs []*CertError) {
	for _, err := range errs {
		s.report(err)
	}
}

// newCert makes the storeCert of cert, which it does not change, verifying
// it against Roots.
func (s *CertStore) newCert(id string, cert *tls.Certificate, given []string, source CertSource, files *fileSource) (*storeCert, error) {
	leaf, err := leafOf(cert)
	if err != nil {
		return nil, err
	}
	if cert.Leaf != leaf {
		cp := *cert
		cp.Leaf = leaf
		cert = &cp
	}
	if id == "" {
		id = CertID(cert)
	}
	names := given
	if len(names) == 0 {
		names = leafNames(leaf)
	}
	return &storeCert{
		id:        id,
		cert:      cert,
		names:     names,
		given:     given,
		notBefore: leaf.NotBefore,
		notAfter:  leaf.NotAfter,
		authority: s.issued(leaf, cert.Certificate[1:]),
		source:    source,
		files:     files,
	}, nil
}

// issued reports whether leaf, with the rest of its chain as intermediates,
// verifies against Roots for server authentication, at a time it is valid.
func (s *CertStore) issued(leaf *x509.Certificate, chain [][]byte) bool {
	intermediates := x509.NewCertPool()
	for _, der := range chain {
		if c, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(c)
		}
	}
	at := s.clock()
	if at.Before(leaf.NotBefore) || !at.Before(leaf.NotAfter) {
		at = leaf.NotBefore
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         s.Roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

// put makes c serve in place of what its ID held, or, for a read of changed
// files, in place of old only if old is still held.
func (s *CertStore) put(c, old *storeCert) {
	s.addMu.Lock()
	cur, ok := s.byID[c.id]
	if old != nil && cur != old {
		// Removed or replaced while its files were read.
		s.addMu.Unlock()
		return
	}
	if ok {
		s.unindexLocked(cur)
		if cur.files != nil {
			s.nFiles.Add(-1)
		}
	}
	if old != nil {
		c.seq = old.seq
	} else {
		s.seq++
		c.seq = s.seq
	}
	if s.byID == nil {
		s.byID = make(map[string]*storeCert)
	}
	s.byID[c.id] = c
	s.indexLocked(c)
	if c.files != nil {
		s.nFiles.Add(1)
	}
	s.addMu.Unlock()
	s.dropLoaded(c.names)
}

// indexOf returns the index that holds the certificates for name, exact or
// wildcard, and name's key in it.
func (s *CertStore) indexOf(name string) (*map[string]*certList, string) {
	if suffix, ok := strings.CutPrefix(name, "*"); ok && strings.HasPrefix(suffix, ".") {
		return &s.wild, suffix
	}
	return &s.exact, name
}

// listFor returns the list that holds the certificates for name, or nil.
func (s *CertStore) listFor(name string) *certList {
	m, key := s.indexOf(name)
	return (*m)[key]
}

// newListFor returns the list that holds the certificates for name,
// creating it if there is none.
func (s *CertStore) newListFor(name string) *certList {
	m, key := s.indexOf(name)
	if l := (*m)[key]; l != nil {
		return l
	}
	if *m == nil {
		*m = make(map[string]*certList)
	}
	l := &certList{}
	(*m)[key] = l
	return l
}

func (s *CertStore) indexLocked(c *storeCert) {
	for _, name := range c.names {
		l := s.newListFor(name)
		l.certs = append(l.certs, c)
		l.sort()
	}
}

func (s *CertStore) unindexLocked(c *storeCert) {
	for _, name := range c.names {
		l := s.listFor(name)
		if l == nil {
			continue
		}
		l.certs = slices.DeleteFunc(l.certs, func(x *storeCert) bool { return x == c })
		if len(l.certs) == 0 {
			m, key := s.exact, name
			if suffix, ok := strings.CutPrefix(name, "*"); ok && strings.HasPrefix(suffix, ".") {
				m, key = s.wild, suffix
			}
			delete(m, key)
			continue
		}
		l.sort()
	}
}

// sort orders l: issued first, then by later NotAfter, then by later
// addition.
func (l *certList) sort() {
	slices.SortFunc(l.certs, func(a, b *storeCert) int {
		if a.authority != b.authority {
			if a.authority {
				return -1
			}
			return 1
		}
		if c := b.notAfter.Compare(a.notAfter); c != 0 {
			return c
		}
		return cmp.Compare(b.seq, a.seq)
	})
	l.nAuth = 0
	for _, c := range l.certs {
		if !c.authority {
			break
		}
		l.nAuth++
	}
}

// leafNames returns the DNS names and IP addresses of leaf, normalized.
func leafNames(leaf *x509.Certificate) []string {
	names := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	for _, n := range leaf.DNSNames {
		names = append(names, normalizeName(n))
	}
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// normalizeNames normalizes names given to Add, in a new slice.
func normalizeNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			n = ip.String()
		}
		out = append(out, normalizeName(n))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (s *CertStore) report(err *CertError) {
	if s.OnError != nil {
		s.OnError(err)
	}
}

func (s *CertStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}
