package tlsconn

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/timeshim"
)

// setModTime sets the modification time of files, so that changes do not
// depend on the resolution of the file system's clock.
func setModTime(t *testing.T, when time.Time, files ...string) {
	t.Helper()
	for _, f := range files {
		if err := os.Chtimes(f, when, when); err != nil {
			t.Fatal(err)
		}
	}
}

func sameCert(a *tls.Certificate, b tls.Certificate) bool {
	return a != nil && Fingerprint(a.Certificate[0]) == Fingerprint(b.Certificate[0])
}

// Files are read again only when a check, at most every CheckInterval,
// finds them changed.
func TestCertFilesChangeDetection(t *testing.T) {
	first, _ := NewSelfSigned(SelfSignedOptions{})
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, first)
	base := time.Now().Add(-time.Hour)
	setModTime(t, base, certFile, keyFile)
	fake := timeshim.NewFake(time.Now())
	var reports []*CertError
	c := &CertFiles{Clock: fake, OnError: func(err *CertError) { reports = append(reports, err) }}
	got, err := c.LoadFiles(certFile, keyFile)
	if err != nil || !sameCert(got, first) {
		t.Fatalf("LoadFiles() = %v", err)
	}

	// Renewed files are not looked at before DefaultCheckInterval.
	second, _ := NewSelfSigned(SelfSignedOptions{})
	writeCert(t, dir, second)
	setModTime(t, base.Add(time.Second), certFile, keyFile)
	fake.Advance(DefaultCheckInterval - time.Second)
	if again, _ := c.LoadFiles(certFile, keyFile); again != got {
		t.Fatal("files checked before CheckInterval")
	}
	fake.Advance(time.Second)
	if got, _ = c.LoadFiles(certFile, keyFile); !sameCert(got, second) {
		t.Fatal("changed files not read again")
	}

	// Unchanged files are not read: one that cannot be read reports no
	// error.
	if err := os.Chmod(certFile, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(certFile); err == nil {
		t.Log("file permissions not enforced here; skipping the unread check")
	} else {
		fake.Advance(DefaultCheckInterval)
		if again, _ := c.LoadFiles(certFile, keyFile); again != got || len(reports) != 0 {
			t.Fatalf("unchanged files were read: %v", reports)
		}
	}
	if err := os.Chmod(certFile, 0o600); err != nil {
		t.Fatal(err)
	}

	// A negative CheckInterval never checks.
	c.CheckInterval = -1
	third, _ := NewSelfSigned(SelfSignedOptions{})
	writeCert(t, dir, third)
	setModTime(t, base.Add(2*time.Second), certFile, keyFile)
	fake.Advance(time.Hour)
	if again, _ := c.LoadFiles(certFile, keyFile); again != got {
		t.Fatal("files checked with a negative CheckInterval")
	}
	c.CheckInterval = time.Minute
	fake.Advance(time.Minute)
	if got, _ = c.LoadFiles(certFile, keyFile); !sameCert(got, third) {
		t.Fatal("changed files not read with CheckInterval set")
	}
}

// A pair that does not read, as when the certificate was replaced before its
// key, keeps the old certificate and is reported, and the next check tries
// again, also when the files do not change in between.
func TestCertFilesHalfWrittenPair(t *testing.T) {
	first, _ := NewSelfSigned(SelfSignedOptions{})
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, first)
	base := time.Now().Add(-time.Hour)
	setModTime(t, base, certFile, keyFile)
	fake := timeshim.NewFake(time.Now())
	var reports []*CertError
	c := &CertFiles{Clock: fake}
	c.OnError = func(err *CertError) {
		_ = c.Len() // the hook may call back into the cache
		reports = append(reports, err)
	}
	got, err := c.LoadFiles(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	second, _ := NewSelfSigned(SelfSignedOptions{})
	certPEM, keyPEM, _ := EncodePEM(second)
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	setModTime(t, base.Add(time.Second), certFile)
	fake.Advance(DefaultCheckInterval)
	if kept, err := c.LoadFiles(certFile, keyFile); err != nil || kept != got {
		t.Fatalf("half-written pair: LoadFiles() = %v, %v; want the old certificate", kept, err)
	}
	if len(reports) != 1 || reports[0].CertFile != certFile || reports[0].KeyFile != keyFile || reports[0].Err == nil {
		t.Fatalf("reports = %+v, want one for the pair", reports)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	setModTime(t, base.Add(time.Second), keyFile)
	fake.Advance(DefaultCheckInterval)
	if got, _ = c.LoadFiles(certFile, keyFile); !sameCert(got, second) {
		t.Fatal("completed pair not read")
	}

	// A read that fails records nothing: once the file reads again, the
	// change is picked up although its size and time stayed.
	third, _ := NewSelfSigned(SelfSignedOptions{})
	writeCert(t, dir, third)
	setModTime(t, base.Add(2*time.Second), certFile, keyFile)
	if err := os.Chmod(certFile, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(certFile); err == nil {
		t.Skip("file permissions not enforced here")
	}
	fake.Advance(DefaultCheckInterval)
	if kept, _ := c.LoadFiles(certFile, keyFile); kept != got || len(reports) != 2 {
		t.Fatalf("unreadable file: kept %v, %d reports; want the old certificate and a report", kept == got, len(reports))
	}
	if err := os.Chmod(certFile, 0o600); err != nil {
		t.Fatal(err)
	}
	fake.Advance(DefaultCheckInterval)
	if got, _ = c.LoadFiles(certFile, keyFile); !sameCert(got, third) {
		t.Fatal("files not read again after a failed read")
	}
}

// Swapping a symbolic link to another pair counts as a change, also when
// the new files have the size and time of the old.
func TestCertFilesSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	first, _ := NewSelfSigned(SelfSignedOptions{})
	firstCert, firstKey, _ := EncodePEM(first)
	var second tls.Certificate
	var secondCert, secondKey []byte
	for range 100 {
		second, _ = NewSelfSigned(SelfSignedOptions{})
		secondCert, secondKey, _ = EncodePEM(second)
		if len(secondCert) == len(firstCert) && len(secondKey) == len(firstKey) {
			break
		}
	}
	if len(secondCert) != len(firstCert) || len(secondKey) != len(firstKey) {
		t.Skip("no certificate of the same size")
	}
	when := time.Now().Add(-time.Hour)
	for _, v := range []struct {
		name      string
		cert, key []byte
	}{{"v1", firstCert, firstKey}, {"v2", secondCert, secondKey}} {
		sub := filepath.Join(dir, v.name)
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		for file, data := range map[string][]byte{"cert.pem": v.cert, "key.pem": v.key} {
			if err := os.WriteFile(filepath.Join(sub, file), data, 0o600); err != nil {
				t.Fatal(err)
			}
			setModTime(t, when, filepath.Join(sub, file))
		}
	}
	link := func(version string) {
		t.Helper()
		for _, file := range []string{"cert.pem", "key.pem"} {
			tmp := filepath.Join(dir, file+".tmp")
			if err := os.Symlink(filepath.Join(dir, version, file), tmp); err != nil {
				t.Skip("no symbolic links here:", err)
			}
			if err := os.Rename(tmp, filepath.Join(dir, file)); err != nil {
				t.Fatal(err)
			}
		}
	}
	link("v1")
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	fake := timeshim.NewFake(time.Now())
	c := &CertFiles{Clock: fake}
	if got, err := c.LoadFiles(certFile, keyFile); err != nil || !sameCert(got, first) {
		t.Fatalf("LoadFiles() = %v", err)
	}
	link("v2")
	fake.Advance(DefaultCheckInterval)
	if got, _ := c.LoadFiles(certFile, keyFile); !sameCert(got, second) {
		t.Fatal("swapped link not picked up")
	}
}

// The files of an expired certificate are read again at most once a minute,
// even when changes are not checked.
func TestCertFilesReloadsExpired(t *testing.T) {
	first, _ := NewSelfSigned(SelfSignedOptions{ValidFor: time.Hour})
	certFile, keyFile := writeCert(t, t.TempDir(), first)
	fake := timeshim.NewFake(time.Now())
	c := &CertFiles{CheckInterval: -1, Clock: fake}
	got, err := c.LoadFiles(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := NewSelfSigned(SelfSignedOptions{})
	writeCert(t, filepath.Dir(certFile), second)
	fake.Advance(30 * time.Minute)
	if again, _ := c.LoadFiles(certFile, keyFile); again != got {
		t.Fatal("valid certificate read again")
	}
	fake.Advance(time.Hour + time.Second) // past NotAfter
	if got, _ = c.LoadFiles(certFile, keyFile); !sameCert(got, second) {
		t.Fatal("expired certificate not read again")
	}
}

// Once expired, a certificate does not serve and its files are read again
// although they look unchanged, at most once a minute; also in a CertStore.
func TestCertFilesExpiredUnchangedStat(t *testing.T) {
	now := time.Now()
	fake := timeshim.NewFake(now)
	expired := makeCert(t, nil, nil, now.Add(-2*time.Hour), now.Add(time.Hour), "a.example")
	certPEM, keyPEM, _ := EncodePEM(*expired)
	// A renewal of the same size, written in place with the same time.
	var renewedCert, renewedKey []byte
	var renewed *tls.Certificate
	for range 100 {
		renewed = makeCert(t, nil, nil, now.Add(-2*time.Hour), now.Add(48*time.Hour), "a.example")
		renewedCert, renewedKey, _ = EncodePEM(*renewed)
		if len(renewedCert) == len(certPEM) && len(renewedKey) == len(keyPEM) {
			break
		}
	}
	if len(renewedCert) != len(certPEM) || len(renewedKey) != len(keyPEM) {
		t.Skip("no renewal of the same size")
	}
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, *expired)
	when := now.Add(-time.Hour)
	setModTime(t, when, certFile, keyFile)
	renew := func() {
		t.Helper()
		for file, data := range map[string][]byte{certFile: renewedCert, keyFile: renewedKey} {
			f, err := os.OpenFile(file, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.WriteAt(data, 0) // in place: the same file and size
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		setModTime(t, when, certFile, keyFile)
	}

	c := &CertFiles{Clock: fake}
	if _, err := c.LoadFiles(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	s := &CertStore{Clock: fake}
	id, err := s.AddFiles("a", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	syncStore := func() {
		s.checkMu.Lock() // also waits for a check that a handshake started
		defer s.checkMu.Unlock()
		s.syncFiles(fake.Now(), false)
	}
	storeCert := func() *tls.Certificate {
		got, _ := s.forName(context.Background(), "a.example")
		return got
	}

	fake.Advance(time.Hour + time.Second) // expired
	if got, err := c.LoadFiles(certFile, keyFile); got != nil || !errors.Is(err, ErrNotValidNow) {
		t.Fatalf("expired: LoadFiles() = %v, %v; want ErrNotValidNow", got, err)
	}
	syncStore() // the files hold the same: no change
	if got := storeCert(); got != nil {
		t.Fatal("an expired certificate served from the store")
	}
	renew()
	fake.Advance(30 * time.Second) // within a minute of the last read
	if got, err := c.LoadFiles(certFile, keyFile); got != nil || !errors.Is(err, ErrNotValidNow) {
		t.Fatalf("read again within a minute: %v, %v", got, err)
	}
	syncStore()
	if got := storeCert(); got != nil {
		t.Fatal("store read again within a minute")
	}
	fake.Advance(30 * time.Second)
	if got, err := c.LoadFiles(certFile, keyFile); err != nil || !sameLeaf(got, renewed) {
		t.Fatalf("a minute on: LoadFiles() = %v; want the renewal with unchanged stat", err)
	}
	syncStore()
	if got, _ := s.Certificate(id); !sameLeaf(got, renewed) {
		t.Fatal("store did not read the renewal with unchanged stat")
	}
}

// Callers check and use a certificate while its files change, for the race
// detector.
func TestCertFilesConcurrentChecks(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("one goroutine runs at a time, so the checks cannot race")
	}
	dir := t.TempDir()
	certs := make([][2][]byte, 2)
	for i := range certs {
		cert, _ := NewSelfSigned(SelfSignedOptions{})
		certs[i][0], certs[i][1], _ = EncodePEM(cert)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write := func(i int) {
		// Each file is replaced at once, so a read sees a whole file, if
		// perhaps not a matching pair.
		for file, data := range map[string][]byte{certFile: certs[i][0], keyFile: certs[i][1]} {
			if err := os.WriteFile(file+".tmp", data, 0o600); err != nil {
				t.Error(err)
				return
			}
			// Windows refuses to replace a file that a reader has open
			// for a moment; a renewal tool would retry too.
			var err error
			for range 100 {
				if err = os.Rename(file+".tmp", file); err == nil || runtime.GOOS != "windows" {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if err != nil {
				t.Error(err)
				return
			}
		}
	}
	write(0)
	c := &CertFiles{CheckInterval: time.Nanosecond, OnError: func(*CertError) {}}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				got, err := c.LoadFiles(certFile, keyFile)
				if err == nil && !bytes.Equal(got.Certificate[0], got.Leaf.Raw) {
					t.Error("leaf of another certificate")
				}
			}
		})
	}
	for i := range 50 {
		write(i % 2)
	}
	close(stop)
	wg.Wait()
}

// MaxEntries counts the loaded certificates, also across failed loads,
// Clear and the idle sweep.
func TestCertFilesCountsLoadedEntries(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	c := &CertFiles{MaxEntries: 2, IdleTimeout: time.Hour, Clock: fake}
	pems := make([][2][]byte, 4)
	for i := range pems {
		cert, _ := NewSelfSigned(SelfSignedOptions{})
		pems[i][0], pems[i][1], _ = EncodePEM(cert)
	}
	check := func(want int) {
		t.Helper()
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.loaded != want || len(c.entries) != want {
			t.Fatalf("loaded = %d, entries = %d, want %d", c.loaded, len(c.entries), want)
		}
	}
	for i := range pems {
		if _, err := c.LoadPEM(pems[i][0], pems[i][1]); err != nil {
			t.Fatal(err)
		}
		_, _ = c.LoadPEM([]byte("bad"), []byte("bad"))
	}
	check(2)
	c.Clear()
	check(0)
	_, _ = c.LoadPEM(pems[0][0], pems[0][1])
	fake.Advance(2 * time.Hour)
	_, _ = c.LoadPEM(pems[1][0], pems[1][1]) // the sweep drops the first
	check(1)
	_, _ = c.LoadPEM(pems[2][0], pems[2][1])
	_, _ = c.LoadPEM(pems[3][0], pems[3][1])
	check(2)
}

func TestCertFilesPEM(t *testing.T) {
	var c CertFiles
	certs := make([][2][]byte, 3)
	for i := range certs {
		cert, _ := NewSelfSigned(SelfSignedOptions{})
		certs[i][0], certs[i][1], _ = EncodePEM(cert)
	}

	// Concurrent first loads of one certificate share one result.
	var wg sync.WaitGroup
	results := make([]*tls.Certificate, 8)
	for i := range results {
		wg.Go(func() {
			results[i], _ = c.LoadPEM(certs[0][0], certs[0][1])
		})
	}
	wg.Wait()
	for _, r := range results {
		if r == nil || r != results[0] {
			t.Fatal("concurrent loads returned different certificates")
		}
	}
	if other, _ := c.LoadPEM(certs[1][0], certs[1][1]); other == results[0] {
		t.Fatal("different PEM data shared a cache entry")
	}
	if _, err := c.LoadPEM([]byte("x"), []byte("y")); err == nil {
		t.Fatal("invalid PEM loaded")
	}

	// MaxEntries drops the least recently used certificate.
	c.MaxEntries = 2
	_, _ = c.LoadPEM(certs[0][0], certs[0][1])
	_, _ = c.LoadPEM(certs[2][0], certs[2][1])
	if c.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", c.Len())
	}
	if again, _ := c.LoadPEM(certs[0][0], certs[0][1]); again != results[0] {
		t.Fatal("recently used certificate was evicted")
	}

	// IdleTimeout drops certificates nobody loads.
	c.IdleTimeout = 20 * time.Millisecond
	time.Sleep(30 * time.Millisecond)
	_, _ = c.LoadPEM(certs[2][0], certs[2][1])
	if c.Len() != 1 {
		t.Fatalf("Len() after idle = %d, want 1", c.Len())
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len() after Clear = %d", c.Len())
	}
}

// A certificate cached from PEM data does not keep that data, which holds
// the private key, reachable.
func TestCertFilesDoesNotKeepPEMInput(t *testing.T) {
	cert, err := NewSelfSigned(SelfSignedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := EncodePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	var c CertFiles
	released := make(chan struct{})
	func() {
		// The PEM blocks are slices of a larger buffer, such as a whole
		// configuration file.
		buf := new([1 << 20]byte)
		n := copy(buf[:], certPEM)
		m := copy(buf[n:], keyPEM)
		runtime.AddCleanup(buf, func(done chan struct{}) { close(done) }, released)
		if _, err := c.LoadPEM(buf[:n:n], buf[n:n+m:n+m]); err != nil {
			t.Fatal(err)
		}
	}()
	for range 10 {
		runtime.GC()
		select {
		case <-released:
			if c.Len() != 1 {
				t.Fatalf("Len() = %d, want 1", c.Len())
			}
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("the PEM input is still reachable from the cache")
}

// Forget drops one certificate loaded from files, so that the next load reads
// the files again, and leaves the others.
func TestCertFilesForget(t *testing.T) {
	dir := t.TempDir()
	var c CertFiles
	files := make([][2]string, 2)
	for i := range files {
		cert, _ := NewSelfSigned(SelfSignedOptions{})
		sub := filepath.Join(dir, string(rune('a'+i)))
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		files[i][0], files[i][1] = writeCert(t, sub, cert)
		if _, err := c.LoadFiles(files[i][0], files[i][1]); err != nil {
			t.Fatal(err)
		}
	}
	renewed, _ := NewSelfSigned(SelfSignedOptions{})
	writeCert(t, filepath.Dir(files[0][0]), renewed)
	c.Forget(files[0][0], files[0][1])
	c.Forget(files[0][0]+".unknown", files[0][1])
	if c.Len() != 1 {
		t.Fatalf("Len() after Forget = %d, want 1", c.Len())
	}
	got, err := c.LoadFiles(files[0][0], files[0][1])
	if err != nil || Fingerprint(got.Certificate[0]) != Fingerprint(renewed.Certificate[0]) {
		t.Fatalf("LoadFiles() after Forget = %v, want the renewed certificate", err)
	}
	c.mu.Lock()
	loaded := c.loaded
	c.mu.Unlock()
	if loaded != 2 {
		t.Fatalf("loaded = %d after Forget and a new load, want 2", loaded)
	}
}

// Forget during a first load lets the load's callers have its result, but
// the result is not cached nor counted.
func TestCertFilesForgetDuringLoad(t *testing.T) {
	cert, _ := NewSelfSigned(SelfSignedOptions{})
	var c CertFiles
	key := fileKey("c", "k")
	release := make(chan struct{})
	done := make(chan *tls.Certificate, 1)
	go func() {
		got, _ := c.get(key, "", "", func() (*tls.Certificate, error) {
			<-release
			return &cert, nil
		})
		done <- got
	}()
	for c.Len() == 0 {
		time.Sleep(time.Millisecond) // the load is in flight
	}
	c.Forget("c", "k")
	close(release)
	if got := <-done; got == nil {
		t.Fatal("caller of a forgotten load got no certificate")
	}
	c.mu.Lock()
	n, loaded := len(c.entries), c.loaded
	c.mu.Unlock()
	if n != 0 || loaded != 0 {
		t.Fatalf("entries = %d, loaded = %d after a forgotten load, want 0", n, loaded)
	}
}

// A load that fails, as one for a name without files does, pushes no
// working certificate out of a full cache.
func TestCertFilesFailedLoadKeepsEntries(t *testing.T) {
	dir := t.TempDir()
	c := &CertFiles{MaxEntries: 2}
	for _, name := range []string{"a", "b"} {
		cert, _ := NewSelfSigned(SelfSignedOptions{})
		sub := filepath.Join(dir, name)
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		certFile, keyFile := writeCert(t, sub, cert)
		if _, err := c.LoadFiles(certFile, keyFile); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.LoadFiles(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("LoadFiles() of missing files succeeded")
	}
	if n := c.Len(); n != 2 {
		t.Fatalf("Len() = %d after a failed load, want the 2 certificates kept", n)
	}
}

// Loads still in flight do not count toward MaxEntries, so one that fails
// after others succeeded pushes no certificate out.
func TestCertFilesInFlightLoadDoesNotEvict(t *testing.T) {
	c := &CertFiles{MaxEntries: 2}
	release := make(chan struct{})
	failed := make(chan struct{})
	go func() {
		_, _ = c.get("slow", "", "", func() (*tls.Certificate, error) {
			<-release
			return nil, errors.New("no such certificate")
		})
		close(failed)
	}()
	for c.Len() == 0 {
		time.Sleep(time.Millisecond) // the slow load is in flight
	}
	for _, key := range []string{"a", "b"} {
		if _, err := c.get(key, "", "", func() (*tls.Certificate, error) {
			cert, err := NewSelfSigned(SelfSignedOptions{})
			return &cert, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	<-failed
	if n := c.Len(); n != 2 {
		t.Fatalf("Len() = %d, want the 2 loaded certificates", n)
	}
}

// OnError runs without checkMu held, so it may check the files itself, in
// CheckFiles and in the background check that a handshake starts.
func TestCertStoreOnErrorChecksFiles(t *testing.T) {
	dir := t.TempDir()
	cert, _ := NewSelfSigned(SelfSignedOptions{Hosts: []string{"a.example"}})
	certFile, keyFile := writeCert(t, dir, cert)
	setModTime(t, time.Now().Add(-time.Hour), certFile, keyFile)
	fake := timeshim.NewFake(time.Now())
	reports := make(chan struct{}, 16)
	s := &CertStore{Clock: fake}
	var calls atomic.Int32
	s.OnError = func(*CertError) {
		reports <- struct{}{}
		if calls.Add(1) == 1 {
			s.CheckFiles()
		}
	}
	if _, err := s.AddFiles("a", certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte("broken, another size"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		s.CheckFiles()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CheckFiles from OnError deadlocked")
	}
	if n := len(reports); n != 2 {
		t.Fatalf("%d reports, want 2: the check's and the nested one's", n)
	}
	<-reports
	<-reports

	// The background check releases checkMu before it reports, so the hook
	// may call CheckFiles and later checks still run.
	calls.Store(0)
	s.OnError = func(*CertError) {
		if calls.Add(1) == 1 {
			s.CheckFiles() // which reports again, without calling CheckFiles
		}
		reports <- struct{}{}
	}
	fake.Advance(DefaultCheckInterval)
	_, _ = s.forName(context.Background(), "a.example")
	select {
	case <-reports:
	case <-time.After(5 * time.Second):
		t.Fatal("background check with CheckFiles in OnError deadlocked")
	}
}

// Changed files whose certificate is not valid now, such as an old pair
// copied back, do not replace a valid one, are reported, and are read again
// at the next check; they replace one that is not valid either.
func TestCertFilesRenewalNotValidNow(t *testing.T) {
	now := time.Now()
	good := makeCert(t, nil, nil, now.Add(-time.Hour), now.Add(48*time.Hour), "a.example")
	old := makeCert(t, nil, nil, now.Add(-72*time.Hour), now.Add(-24*time.Hour), "a.example")
	future := makeCert(t, nil, nil, now.Add(72*time.Hour), now.Add(96*time.Hour), "a.example")
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, *good)
	base := now.Add(-time.Hour)
	setModTime(t, base, certFile, keyFile)
	fake := timeshim.NewFake(now)

	var fileReports, storeReports []*CertError
	c := &CertFiles{Clock: fake, OnError: func(err *CertError) { fileReports = append(fileReports, err) }}
	s := &CertStore{Clock: fake, OnError: func(err *CertError) { storeReports = append(storeReports, err) }}
	if _, err := c.LoadFiles(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddFiles("a", certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	check := func(want *tls.Certificate, reports int) {
		t.Helper()
		fake.Advance(DefaultCheckInterval)
		s.CheckFiles()
		_, _ = c.LoadFiles(certFile, keyFile)
		c.mu.Lock()
		gotFiles := c.entries[fileKey(certFile, keyFile)].Value.(*certEntry).cert // held, served or not
		c.mu.Unlock()
		gotStore, _ := s.Certificate("a")
		if !sameLeaf(gotFiles, want) || !sameLeaf(gotStore, want) {
			t.Fatalf("CertFiles holds the wanted one: %v, CertStore: %v", sameLeaf(gotFiles, want), sameLeaf(gotStore, want))
		}
		if len(fileReports) != reports || len(storeReports) != reports {
			t.Fatalf("%d and %d reports, want %d", len(fileReports), len(storeReports), reports)
		}
		for _, r := range append(fileReports, storeReports...) {
			if !errors.Is(r.Err, ErrNotValidNow) {
				t.Fatalf("report %v, want ErrNotValidNow", r)
			}
		}
	}
	for i, bad := range []*tls.Certificate{old, future} {
		writeCert(t, dir, *bad)
		setModTime(t, base.Add(time.Duration(i+1)*time.Second), certFile, keyFile)
		check(good, 2*i+1)
		check(good, 2*i+2) // read and rejected again: its stat was not recorded
	}

	// Once the current one has expired too, the files replace it, here with
	// one that becomes valid later.
	fake.Advance(48 * time.Hour)
	check(future, 4)
	if got, _ := s.forName(context.Background(), "a.example"); got != nil {
		t.Fatal("a certificate not valid yet served")
	}
	if got, err := c.LoadFiles(certFile, keyFile); got != nil || !errors.Is(err, ErrNotValidNow) {
		t.Fatalf("CertFiles served a certificate not valid yet: %v", err)
	}
	fake.Advance(24 * time.Hour)
	if got, _ := s.forName(context.Background(), "a.example"); !sameLeaf(got, future) {
		t.Fatal("the renewal did not serve once valid")
	}
}

// The leaf is parsed when tls.X509KeyPair or tls.LoadX509KeyPair leaves it
// unset, as under GODEBUG x509keypairleaf=0 where the toolchain still has
// it, so that the validity of a certificate is always checked.
func TestCertFilesParsesMissingLeaf(t *testing.T) {
	now := time.Now()
	expired := makeCert(t, nil, nil, now.Add(-2*time.Hour), now.Add(-time.Hour), "a.example")
	got, err := withLeaf(*expired) // makeCert leaves Leaf unset
	if err != nil || got.Leaf == nil || !bytes.Equal(got.Leaf.Raw, expired.Certificate[0]) {
		t.Fatalf("withLeaf() = %v, %v; want the leaf parsed", got, err)
	}
	if _, err := withLeaf(tls.Certificate{}); err == nil {
		t.Fatal("withLeaf accepted a certificate without a chain")
	}

	t.Setenv("GODEBUG", "x509keypairleaf=0")
	certPEM, keyPEM, _ := EncodePEM(*expired)
	var c CertFiles
	if got, err := c.LoadPEM(certPEM, keyPEM); got != nil || !errors.Is(err, ErrNotValidNow) {
		t.Fatalf("expired PEM: LoadPEM() = %v, %v; want ErrNotValidNow", got, err)
	}
}
