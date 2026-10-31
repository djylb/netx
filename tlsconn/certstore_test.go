package tlsconn

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/timeshim"
)

func newCert(t *testing.T, validFor time.Duration, hosts ...string) *tls.Certificate {
	t.Helper()
	c, err := NewSelfSigned(SelfSignedOptions{Hosts: hosts, ValidFor: validFor})
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

// Added names win over wildcards, wildcards over Load, and the default
// serves the rest, without case or trailing dot.
func TestCertStoreMatching(t *testing.T) {
	exact, wild, def, loaded := newCert(t, 0), newCert(t, 0), newCert(t, 0), newCert(t, 0)
	s := &CertStore{Load: func(_ context.Context, name string) (*tls.Certificate, error) {
		if name == "load.example.org" {
			return loaded, nil
		}
		return nil, nil
	}}
	mustAdd(t, s, "exact", exact, "WWW.Example.com.")
	mustAdd(t, s, "wild", wild, "*.example.com")
	mustAdd(t, s, "default", def)
	s.SetDefault("default")
	for name, want := range map[string]*tls.Certificate{
		"www.example.com":   exact,
		"WWW.EXAMPLE.COM.":  exact,
		"api.example.com":   wild,
		"a.b.example.com":   def, // a wildcard covers one label
		"example.com":       def,
		"load.example.org":  loaded,
		"other.example.org": def,
		"":                  def,
	} {
		if got, err := s.forName(context.Background(), name); err != nil || !sameLeaf(got, want) {
			t.Errorf("certificate for %q = %p, %v; want %p", name, got, err, want)
		}
	}
	s.SetDefault("")
	if _, err := s.forName(context.Background(), "nothing.example"); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("without a default: error = %v, want ErrNoCertificate", err)
	}
}

// mustAdd adds cert to s under id.
func mustAdd(t *testing.T, s *CertStore, id string, cert *tls.Certificate, names ...string) string {
	t.Helper()
	id, err := s.Add(id, cert, names...)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// sameLeaf reports whether a and b are the same certificate, as the store
// serves a copy of an added one with its leaf set.
func sameLeaf(a, b *tls.Certificate) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Certificate[0], b.Certificate[0])
}

// forName returns the certificate for a handshake for name.
func (s *CertStore) forName(ctx context.Context, name string) (*tls.Certificate, error) {
	return s.certificate(ctx, &tls.ClientHelloInfo{ServerName: name})
}

// Concurrent handshakes for a name share one Load, and a waiter that gives
// up leaves it running for the others.
func TestCertStoreSharesLoads(t *testing.T) {
	cert := newCert(t, 0)
	release := make(chan struct{})
	var loads atomic.Int64
	s := &CertStore{Load: func(context.Context, string) (*tls.Certificate, error) {
		loads.Add(1)
		<-release
		return cert, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.forName(ctx, "a.example"); !errors.Is(err, context.Canceled) {
		t.Fatalf("given up waiter: error = %v, want context.Canceled", err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if got, err := s.forName(context.Background(), "a.example"); err != nil || got != cert {
				t.Errorf("Certificate() = %p, %v", got, err)
			}
		})
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := loads.Load(); n != 1 {
		t.Fatalf("%d loads, want 1", n)
	}
}

// A failed Load is remembered for RetryAfter, and LoadTimeout bounds one.
func TestCertStoreRemembersFailures(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	errDown := errors.New("source down")
	var loads atomic.Int64
	s := &CertStore{RetryAfter: time.Minute, LoadTimeout: 50 * time.Millisecond, Clock: fake,
		Load: func(ctx context.Context, name string) (*tls.Certificate, error) {
			loads.Add(1)
			if name == "slow.example" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, errDown
		}}
	for range 3 {
		if _, err := s.forName(context.Background(), "a.example"); !errors.Is(err, errDown) {
			t.Fatalf("error = %v, want the Load's", err)
		}
	}
	if n := loads.Load(); n != 1 {
		t.Fatalf("%d loads within RetryAfter, want 1", n)
	}
	fake.Advance(time.Minute)
	_, _ = s.forName(context.Background(), "a.example")
	if n := loads.Load(); n != 2 {
		t.Fatalf("%d loads after RetryAfter, want 2", n)
	}
	start := time.Now()
	if _, err := s.forName(context.Background(), "slow.example"); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("slow Load: error = %v after %v, want the LoadTimeout", err, time.Since(start))
	}
}

// A certificate due for refresh is loaded again in the background while it
// serves, also when that load fails, and not on every handshake.
func TestCertStoreRefreshes(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	old, renewed := newCert(t, 48*time.Hour), newCert(t, 90*24*time.Hour)
	var loads atomic.Int64
	fail := atomic.Bool{}
	refreshed := make(chan struct{}, 10)
	s := &CertStore{RetryAfter: time.Minute, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) {
			n := loads.Add(1)
			defer func() {
				if n > 1 {
					refreshed <- struct{}{}
				}
			}()
			if n == 1 {
				return old, nil
			}
			if fail.Load() {
				return nil, errors.New("source down")
			}
			return renewed, nil
		}}
	get := func() *tls.Certificate {
		t.Helper()
		c, err := s.forName(context.Background(), "a.example")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if get() != old {
		t.Fatal("first load not served")
	}
	// Not due: old expires in 48h and lives 49h, so refreshes start a third
	// of that, about 16h, before.
	fake.Advance(30 * time.Hour)
	_ = get()
	if n := loads.Load(); n != 1 {
		t.Fatalf("%d loads before the certificate was due, want 1", n)
	}
	// Due, but the source is down: old serves on.
	fake.Advance(3 * time.Hour)
	fail.Store(true)
	if get() != old {
		t.Fatal("the old certificate did not serve while due")
	}
	<-refreshed
	eventually(t, func() bool { // for the store to take the result
		s.mu.Lock()
		defer s.mu.Unlock()
		return !s.entries["a.example"].Value.(*storeEntry).refreshing
	})
	if get() != old {
		t.Fatal("a failed refresh dropped the old certificate")
	}
	if n := loads.Load(); n != 2 {
		t.Fatalf("%d loads right after a failed refresh, want 2", n)
	}
	// After RetryAfter the refresh succeeds.
	fake.Advance(time.Minute)
	fail.Store(false)
	_ = get()
	<-refreshed
	eventually(t, func() bool { return get() == renewed })
}

// Forget makes the next handshake load again, and IdleTimeout drops what
// no handshake uses.
func TestCertStoreForgetAndIdle(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	var loads atomic.Int64
	s := &CertStore{IdleTimeout: time.Hour, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) {
			loads.Add(1)
			return newCert(t, 0), nil
		}}
	_, _ = s.forName(context.Background(), "a.example")
	s.Forget("A.example.")
	_, _ = s.forName(context.Background(), "a.example")
	if n := loads.Load(); n != 2 {
		t.Fatalf("%d loads after Forget, want 2", n)
	}
	fake.Advance(2 * time.Hour)
	_, _ = s.forName(context.Background(), "b.example") // sweeps
	s.mu.Lock()
	_, kept := s.entries["a.example"]
	s.mu.Unlock()
	if kept {
		t.Fatal("an idle certificate was kept past IdleTimeout")
	}
}

// A TLS server picks certificates by SNI through GetCertificate.
func TestCertStoreServesHandshakes(t *testing.T) {
	s := &CertStore{Load: func(_ context.Context, name string) (*tls.Certificate, error) {
		return newCert(t, 0, name), nil
	}}
	mustAdd(t, s, "", newCert(t, 0, "*.example.com"))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: s.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	for _, name := range []string{"www.example.com", "loaded.example.net"} {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(),
			&tls.Config{ServerName: name, InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		leaf := c.ConnectionState().PeerCertificates[0]
		_ = c.Close()
		if err := leaf.VerifyHostname(name); err != nil {
			t.Fatalf("%s: served %v", name, leaf.DNSNames)
		}
	}
}

// A certificate that is due when it comes is not loaded again on every
// handshake.
func TestCertStoreSpacesRefreshesOfDueCertificates(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	due := newCert(t, 12*time.Hour) // inside the default 24h refresh window
	var loads atomic.Int64
	s := &CertStore{RetryAfter: time.Minute, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) {
			loads.Add(1)
			return due, nil
		}}
	for range 5 {
		if _, err := s.forName(context.Background(), "a.example"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond) // for a background refresh
	}
	if n := loads.Load(); n != 1 {
		t.Fatalf("%d loads within RetryAfter, want 1", n)
	}
}

// A Load that returns a certificate with an error fails, as does one that
// panics or ignores its context.
func TestCertStoreFailedLoads(t *testing.T) {
	valid := newCert(t, 0)
	block := make(chan struct{})
	defer close(block)
	s := &CertStore{LoadTimeout: 50 * time.Millisecond,
		Load: func(_ context.Context, name string) (*tls.Certificate, error) {
			switch name {
			case "both.example":
				return valid, errors.New("half done")
			case "panic.example":
				panic("boom")
			default:
				<-block // ignores ctx
				return nil, nil
			}
		}}
	for _, name := range []string{"both.example", "panic.example", "stuck.example"} {
		c, err := s.forName(context.Background(), name)
		if err == nil || c != nil {
			t.Fatalf("%s: Certificate() = %v, %v; want an error", name, c, err)
		}
	}
}

// Forget drops a Load still running, whose old result then serves only the
// handshakes that waited for it.
func TestCertStoreForgetDuringLoad(t *testing.T) {
	old, renewed := newCert(t, 0), newCert(t, 0)
	release := make(chan struct{})
	var loads atomic.Int64
	s := &CertStore{Load: func(context.Context, string) (*tls.Certificate, error) {
		if loads.Add(1) == 1 {
			<-release
			return old, nil
		}
		return renewed, nil
	}}
	first := make(chan *tls.Certificate, 1)
	go func() {
		c, _ := s.forName(context.Background(), "a.example")
		first <- c
	}()
	for loads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	s.Forget("a.example")
	close(release)
	if c := <-first; c != old {
		t.Fatal("the waiting handshake did not get its Load's certificate")
	}
	if c, _ := s.forName(context.Background(), "a.example"); c != renewed {
		t.Fatal("the Load from before Forget was kept")
	}
}

// Added certificates serve without Load, wildcards and the default
// included, until their NotAfter.
func TestCertStoreAddedCertificates(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	exact, wild, def := newCert(t, time.Hour), newCert(t, 0), newCert(t, 0)
	s := &CertStore{Clock: fake}
	mustAdd(t, s, "exact", exact, "a.example")
	mustAdd(t, s, "wild", wild, "*.example")
	s.SetDefault(mustAdd(t, s, "", def))
	for name, want := range map[string]*tls.Certificate{"a.example": exact, "b.example": wild, "other": def} {
		if c, _ := s.forName(context.Background(), name); !sameLeaf(c, want) {
			t.Fatalf("%s: wrong certificate", name)
		}
	}
	fake.Advance(2 * time.Hour) // exact has expired: the wildcard serves
	if c, _ := s.forName(context.Background(), "a.example"); !sameLeaf(c, wild) {
		t.Fatal("an expired added certificate served")
	}
}

// Load results that are not valid now fail: an expired first certificate is
// remembered as a failure, and a refresh that brings one keeps the old.
func TestCertStoreLoadsNotValidNow(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	expired := newCert(t, 0)
	fake.Advance(400 * 24 * time.Hour) // past its year
	var loads atomic.Int64
	s := &CertStore{RetryAfter: time.Minute, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) {
			loads.Add(1)
			return expired, nil
		}}
	for range 5 {
		if c, err := s.forName(context.Background(), "a.example"); c != nil || err == nil {
			t.Fatalf("an expired certificate from Load served: %v, %v", c, err)
		}
	}
	if n := loads.Load(); n != 1 {
		t.Fatalf("%d loads of an expired certificate within RetryAfter, want 1", n)
	}

	valid := newCert(t, 500*24*time.Hour) // valid on the advanced clock
	refreshed := make(chan struct{}, 4)
	var calls atomic.Int64
	r := &CertStore{RetryAfter: time.Minute, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) {
			if calls.Add(1) == 1 {
				return valid, nil
			}
			defer func() { refreshed <- struct{}{} }()
			return expired, nil
		}}
	_, _ = r.forName(context.Background(), "a.example")
	r.Refresh("a.example")
	_, _ = r.forName(context.Background(), "a.example")
	<-refreshed
	time.Sleep(20 * time.Millisecond)
	if c, _ := r.forName(context.Background(), "a.example"); c != valid {
		t.Fatal("a refresh that brought an expired certificate replaced a valid one")
	}
}

// Refresh during a load leaves what that load brings due, so that a
// renewal announced meanwhile is loaded.
func TestCertStoreRefreshDuringLoad(t *testing.T) {
	old, renewed := newCert(t, 0), newCert(t, 0)
	release, releaseRefresh := make(chan struct{}), make(chan struct{})
	reloaded := make(chan struct{}, 4)
	var loads atomic.Int64
	s := &CertStore{Load: func(context.Context, string) (*tls.Certificate, error) {
		switch loads.Add(1) {
		case 1:
			<-release
			return old, nil
		default:
			<-releaseRefresh
			defer func() { reloaded <- struct{}{} }()
			return renewed, nil
		}
	}}
	first := make(chan *tls.Certificate, 1)
	go func() {
		c, _ := s.forName(context.Background(), "a.example")
		first <- c
	}()
	for loads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	s.Refresh("a.example")
	close(release)
	if c := <-first; c != old {
		t.Fatal("the waiting handshake did not get its Load's certificate")
	}
	if c, _ := s.forName(context.Background(), "a.example"); c != old {
		t.Fatal("the old certificate did not serve while it was refreshed")
	}
	close(releaseRefresh)
	<-reloaded
	eventually(t, func() bool {
		c, _ := s.forName(context.Background(), "a.example")
		return c == renewed
	})
}

// A short-lived certificate is refreshed a third of its life ahead, not on
// every handshake; a refresh that finds none removes it; and an expired one
// does not serve.
func TestCertStoreLifetimes(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	short := newCert(t, 5*time.Hour) // valid from an hour ago: 6h in all
	var loads atomic.Int64
	none := atomic.Bool{}
	done := make(chan struct{}, 10)
	s := &CertStore{RetryAfter: time.Minute, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) {
			n := loads.Add(1)
			if n > 1 {
				defer func() { done <- struct{}{} }()
			}
			if none.Load() {
				return nil, nil
			}
			return short, nil
		}}
	get := func() (*tls.Certificate, error) { return s.forName(context.Background(), "a.example") }
	_, _ = get()
	fake.Advance(2 * time.Hour) // 3h left: not yet within a third of 6h
	_, _ = get()
	time.Sleep(20 * time.Millisecond) // for a refresh it would start
	if n := loads.Load(); n != 1 {
		t.Fatalf("%d loads before the certificate was due, want 1", n)
	}
	fake.Advance(90 * time.Minute) // 1.5h left: due
	none.Store(true)
	if c, _ := get(); c != short {
		t.Fatal("a due certificate did not serve")
	}
	<-done
	eventually(t, func() bool {
		c, err := get()
		return c == nil && errors.Is(err, ErrNoCertificate)
	})

	expired := &CertStore{RetryAfter: time.Minute, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) { return short, nil }}
	_, _ = expired.forName(context.Background(), "b.example")
	fake.Advance(24 * time.Hour)
	expired.Load = func(context.Context, string) (*tls.Certificate, error) { return nil, errors.New("down") }
	if c, err := expired.forName(context.Background(), "b.example"); c != nil || err == nil {
		t.Fatalf("an expired certificate served: %v, %v", c, err)
	}
}

// MaxEntries bounds the loaded names, failed ones included.
func TestCertStoreMaxEntries(t *testing.T) {
	s := &CertStore{MaxEntries: 10, Load: func(context.Context, string) (*tls.Certificate, error) { return nil, nil }}
	for i := range 1000 {
		_, _ = s.forName(context.Background(), fmt.Sprintf("n%d.example", i))
	}
	s.mu.Lock()
	n := s.lru.Len()
	s.mu.Unlock()
	if n != 10 {
		t.Fatalf("%d names kept, want 10", n)
	}
}

// eventually fails t unless cond holds within a few seconds.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
	}
}

// Adding a certificate drops what Load brought for the names it covers,
// also for a wildcard, so that once it is removed they are loaded anew.
func TestCertStoreAddDropsShadowedLoads(t *testing.T) {
	var loads atomic.Int64
	s := &CertStore{Load: func(_ context.Context, name string) (*tls.Certificate, error) {
		loads.Add(1)
		return newCert(t, 0, name), nil
	}}
	loaded, _ := s.forName(context.Background(), "a.example")
	sub, _ := s.forName(context.Background(), "x.d.example")
	s.Remove(mustAdd(t, s, "", newCert(t, 0), "a.example"))
	if c, _ := s.forName(context.Background(), "a.example"); c == loaded {
		t.Fatal("a certificate loaded before Add served after the added one was removed")
	}
	s.Remove(mustAdd(t, s, "", newCert(t, 0), "*.d.example"))
	if c, _ := s.forName(context.Background(), "x.d.example"); c == sub {
		t.Fatal("a certificate loaded before a wildcard Add served after it was removed")
	}
	if n := loads.Load(); n != 4 {
		t.Fatalf("%d loads, want 4", n)
	}
}

// A handshake whose entry Forget dropped while it waited starts no refresh
// on it.
func TestCertStoreNoRefreshOfDroppedEntry(t *testing.T) {
	release := make(chan struct{})
	var loads atomic.Int64
	s := &CertStore{Load: func(context.Context, string) (*tls.Certificate, error) {
		if loads.Add(1) == 1 {
			<-release
		}
		return newCert(t, 0), nil
	}}
	done := make(chan struct{})
	go func() {
		_, _ = s.forName(context.Background(), "a.example")
		close(done)
	}()
	for loads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	s.Refresh("a.example") // due once loaded
	s.Forget("a.example")
	close(release)
	<-done
	time.Sleep(20 * time.Millisecond) // for a refresh it would start
	if n := loads.Load(); n != 1 {
		t.Fatalf("%d loads, want 1: a dropped entry was refreshed", n)
	}
}

// OnError hears of failed first loads and of failed refreshes, which no
// handshake sees, but not of loads that found no certificate, and it may
// call back into the store.
func TestCertStoreLoadErrors(t *testing.T) {
	fake := timeshim.NewFake(time.Now())
	old := newCert(t, 48*time.Hour)
	errDown := errors.New("source down")
	var result atomic.Value // of func() (*tls.Certificate, error)
	type report struct {
		name string
		err  error
		got  *tls.Certificate
	}
	reports := make(chan report, 4)
	s := &CertStore{RetryAfter: time.Minute, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) {
			return result.Load().(func() (*tls.Certificate, error))()
		}}
	s.OnError = func(err *CertError) {
		got, _ := s.forName(context.Background(), err.Name)
		reports <- report{err.Name, err.Err, got}
	}
	// Runs the first load of name in this goroutine, so that its report, if
	// any, is in by the time it returns.
	firstLoad := func(name string, cert *tls.Certificate, err error) {
		result.Store(func() (*tls.Certificate, error) { return cert, err })
		e := &storeEntry{name: name, ready: make(chan struct{})}
		s.mu.Lock()
		s.addLocked(e)
		s.mu.Unlock()
		s.load(e, false)
	}

	firstLoad("none.example", nil, nil)
	if len(reports) != 0 {
		t.Fatalf("a load that found none was reported: %+v", <-reports)
	}
	firstLoad("down.example", nil, errDown)
	if r := <-reports; r.name != "down.example" || !errors.Is(r.err, errDown) || r.got != nil {
		t.Fatalf("first load report = %+v, want %v for down.example", r, errDown)
	}

	// A refresh that fails leaves the old certificate serving, and says so.
	firstLoad("a.example", old, nil)
	if len(reports) != 0 {
		t.Fatalf("a successful load was reported: %+v", <-reports)
	}
	result.Store(func() (*tls.Certificate, error) { return nil, errDown })
	fake.Advance(33 * time.Hour) // due, as in TestCertStoreRefreshes
	if got, err := s.forName(context.Background(), "a.example"); err != nil || got != old {
		t.Fatalf("Certificate() while due = %v, %v; want the old certificate", got, err)
	}
	if r := <-reports; r.name != "a.example" || !errors.Is(r.err, errDown) || !sameLeaf(r.got, old) {
		t.Fatalf("refresh report = %+v, want %v with the old certificate serving", r, errDown)
	}
}

// A first Load that brings a certificate not valid yet fails, is tried
// again after RetryAfter, and serves once valid; Match agrees.
func TestCertStoreLoadNotValidYet(t *testing.T) {
	cert := newCert(t, 0, "a.example")
	fake := timeshim.NewFake(cert.Leaf.NotBefore.Add(-30 * time.Second))
	var loads atomic.Int64
	s := &CertStore{RetryAfter: time.Minute, Clock: fake,
		Load: func(context.Context, string) (*tls.Certificate, error) {
			loads.Add(1)
			return cert, nil
		}}
	if got, err := s.forName(context.Background(), "a.example"); got != nil || !errors.Is(err, ErrNotValidNow) {
		t.Fatalf("not valid yet: %v, %v; want ErrNotValidNow", got, err)
	}
	if infos := s.Match("a.example"); len(infos) != 0 {
		t.Fatalf("Match() = %+v, want nothing that serves", infos)
	}
	fake.Advance(30 * time.Second) // valid now, but the failure is remembered
	if _, err := s.forName(context.Background(), "a.example"); !errors.Is(err, ErrNotValidNow) || loads.Load() != 1 {
		t.Fatalf("within RetryAfter: %v after %d loads", err, loads.Load())
	}
	fake.Advance(time.Minute)
	if got, err := s.forName(context.Background(), "a.example"); err != nil || got != cert {
		t.Fatalf("once valid: %v, %v", got, err)
	}
}
