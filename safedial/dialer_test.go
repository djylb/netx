package safedial

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx"
)

// fakeResolver answers each name with its answers in turn, the last one
// again once they run out, and counts the lookups.
type fakeResolver struct {
	answers map[string][][]netip.Addr
	calls   map[string]int
	block   chan struct{} // if not nil, lookups wait for it or the context
	mu      sync.Mutex
}

func newFakeResolver(answers map[string][]string) *fakeResolver {
	r := &fakeResolver{answers: make(map[string][][]netip.Addr), calls: make(map[string]int)}
	for name, list := range answers {
		r.add(name, list...)
	}
	return r
}

// add appends one answer for name, of addrs.
func (r *fakeResolver) add(name string, addrs ...string) {
	var answer []netip.Addr
	for _, a := range addrs {
		answer = append(answer, netip.MustParseAddr(a))
	}
	r.mu.Lock()
	r.answers[name] = append(r.answers[name], answer)
	r.mu.Unlock()
}

func (r *fakeResolver) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[name]
}

func (r *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if r.block != nil {
		select {
		case <-r.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	r.mu.Lock()
	n := r.calls[host]
	r.calls[host]++
	answers := r.answers[host]
	r.mu.Unlock()
	if len(answers) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, a := range answers[min(n, len(answers)-1)] {
		if network == "ip" || (network == "ip4") == a.Unmap().Is4() {
			out = append(out, a)
		}
	}
	return out, nil
}

// recordDialer records the addresses dialed and fails those in fail; it
// connects the others to one end of a pipe.
type recordDialer struct {
	fail   map[string]bool
	dialed []string
	mu     sync.Mutex
}

func (d *recordDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	if d.fail[address] {
		return nil, errors.New("refused by the test")
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func (d *recordDialer) addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dialed)
}

func assertDenied(t *testing.T, err error, reason error, target string) {
	t.Helper()
	var denied *DeniedError
	if !errors.Is(err, ErrDenied) || !errors.As(err, &denied) {
		t.Fatalf("err = %v; want a *DeniedError", err)
	}
	if reason != nil && !errors.Is(err, reason) {
		t.Errorf("err = %v; want reason %v", err, reason)
	}
	if target != "" && denied.Target.String() != target {
		t.Errorf("denied target %q; want %q", denied.Target, target)
	}
}

// A name that resolves to a public address first and a private one next,
// as a rebinding attack makes it, is resolved once per dial and never
// dialed at the private address.
func TestRebinding(t *testing.T) {
	r := newFakeResolver(nil)
	r.add("rebind.example", "93.184.216.34")
	r.add("rebind.example", "127.0.0.1")
	fwd := &recordDialer{}
	d := &Dialer{Forward: fwd, Resolver: r}
	ctx := context.Background()
	c, err := d.DialContext(ctx, "tcp", "rebind.example:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_, err = d.DialContext(ctx, "tcp", "rebind.example:80")
	assertDenied(t, err, ErrScope, "rebind.example:80 (127.0.0.1)")
	if got := fwd.addresses(); !slices.Equal(got, []string{"93.184.216.34:80"}) {
		t.Errorf("dialed %q", got)
	}
	if n := r.count("rebind.example"); n != 2 {
		t.Errorf("%d lookups for two dials", n)
	}
}

// Of mixed answers, only the allowed addresses are dialed, interleaved by
// family, falling through failures.
func TestMixedAnswers(t *testing.T) {
	r := newFakeResolver(map[string][]string{"mixed.example": {
		"10.0.0.1", "2606:2800:220:1::1", "93.184.216.34", "::1", "::ffff:8.8.8.8",
		"169.254.169.254", "93.184.216.34", "2606:2800:220:1::2", "fe80::1%eth0",
	}})
	fwd := &recordDialer{fail: map[string]bool{"[2606:2800:220:1::1]:443": true, "93.184.216.34:443": true}}
	d := &Dialer{Forward: fwd, Resolver: r, Stagger: time.Hour}
	c, err := d.DialContext(context.Background(), "tcp", "mixed.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	want := []string{"[2606:2800:220:1::1]:443", "93.184.216.34:443", "[2606:2800:220:1::2]:443"}
	if got := fwd.addresses(); !slices.Equal(got, want) {
		t.Errorf("dialed %q; want %q", got, want)
	}
	addrs, err := d.Lookup(context.Background(), "tcp", "mixed.example:443")
	if err != nil {
		t.Fatal(err)
	}
	wantAddrs := []string{"[2606:2800:220:1::1]:443", "93.184.216.34:443", "[2606:2800:220:1::2]:443", "8.8.8.8:443"}
	if got := apStrings(addrs); !slices.Equal(got, wantAddrs) {
		t.Errorf("Lookup = %q; want %q", got, wantAddrs)
	}
	// A family-bound network keeps that family alone.
	addrs, err = d.Lookup(context.Background(), "tcp4", "mixed.example:443")
	if err != nil || !slices.Equal(apStrings(addrs), []string{"93.184.216.34:443", "8.8.8.8:443"}) {
		t.Errorf("Lookup tcp4 = %q, %v", apStrings(addrs), err)
	}
	// Every attempt failing returns their errors.
	fwd.fail = map[string]bool{"93.184.216.34:443": true, "8.8.8.8:443": true}
	if _, err := d.DialContext(context.Background(), "tcp4", "mixed.example:443"); err == nil || errors.Is(err, ErrDenied) {
		t.Errorf("all failing: %v", err)
	}
}

func apStrings(aps []netip.AddrPort) []string {
	out := make([]string, len(aps))
	for i, ap := range aps {
		out[i] = ap.String()
	}
	return out
}

// IP addresses in every form, legacy IPv4 forms among them, are checked as
// addresses and never resolved.
func TestLiteralForms(t *testing.T) {
	r := newFakeResolver(nil)
	fwd := &recordDialer{}
	d := &Dialer{Forward: fwd, Resolver: r}
	for _, address := range []string{
		"127.0.0.1:80", "127.1:80", "2130706433:80", "0x7f.0.0.1:80", "0177.0.0.1:80",
		"127.0.0.1.:80", "[::ffff:127.0.0.1]:80", "[::1]:80", "0:80", "[::]:80",
		"0xa9fea9fe:80", "[fe80::1%eth0]:80", "[64:ff9b::7f00:1]:80", "10.1:80",
	} {
		_, err := d.DialContext(context.Background(), "tcp", address)
		assertDenied(t, err, ErrScope, "")
	}
	if got := fwd.addresses(); len(got) != 0 {
		t.Errorf("dialed %q", got)
	}
	if len(r.calls) != 0 {
		t.Errorf("resolved %v", r.calls)
	}
	// Names that a resolver might read in its own ways are refused.
	for _, address := range []string{"127.0.0.1 x:80", "1.2.3.256:80", ":80", "example.08:80"} {
		if _, err := d.DialContext(context.Background(), "tcp", address); err == nil || errors.Is(err, ErrDenied) {
			t.Errorf("%q: %v", address, err)
		}
	}
	// A link-local address that the policy allows is dialed with its zone.
	d.Policy = AllowScopes(netx.ScopeLinkLocal)
	c, err := d.DialContext(context.Background(), "tcp", "[fe80::1%eth0]:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got := fwd.addresses(); !slices.Equal(got, []string{"[fe80::1%eth0]:80"}) {
		t.Errorf("dialed %q", got)
	}
	if _, err := d.DialContext(context.Background(), "tcp4", "[fe80::1%eth0]:80"); err == nil {
		t.Error("tcp4 dialed an IPv6 address")
	}
}

// A name that the policy refuses is not resolved.
func TestNameRefusedBeforeLookup(t *testing.T) {
	r := newFakeResolver(map[string][]string{"blocked.example": {"93.184.216.34"}})
	d := &Dialer{Forward: &recordDialer{}, Resolver: r, Policy: All(DenyNames("blocked.example"), DefaultPolicy())}
	_, err := d.DialContext(context.Background(), "tcp", "www.blocked.example:443")
	assertDenied(t, err, ErrName, "www.blocked.example:443")
	_, err = d.DialContext(context.Background(), "udp", "blocked.example:53")
	assertDenied(t, err, ErrName, "blocked.example:53")
	if len(r.calls) != 0 {
		t.Errorf("resolved %v", r.calls)
	}
	var denied *DeniedError
	if errors.As(err, &denied) && denied.Error() != "safedial: udp blocked.example:53: host name not allowed" {
		t.Errorf("Error() = %q", denied.Error())
	}
	// A name without addresses fails as a lookup does.
	var dnsErr *net.DNSError
	if _, err := d.DialContext(context.Background(), "tcp", "missing.example:443"); !errors.As(err, &dnsErr) {
		t.Errorf("missing: %v", err)
	}
	r.add("v6only.example", "2606:2800:220:1::1")
	if _, err := d.DialContext(context.Background(), "tcp4", "v6only.example:443"); !errors.As(err, &dnsErr) {
		t.Errorf("v6only over tcp4: %v", err)
	}
}

// The lookup and the dials end with the context, and their goroutines
// with them.
func TestDialContextCancel(t *testing.T) {
	r := newFakeResolver(map[string][]string{"slow.example": {"93.184.216.34"}})
	r.block = make(chan struct{})
	d := &Dialer{Forward: &recordDialer{}, Resolver: r}
	before, _ := goroutines()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.DialContext(ctx, "tcp", "slow.example:80"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("lookup: %v", err)
	}
	// Dials of several addresses that hang.
	r2 := newFakeResolver(map[string][]string{"hang.example": {"93.184.216.34", "93.184.216.35", "2606:2800:220:1::1"}})
	d = &Dialer{Forward: hangDialer{}, Resolver: r2, Stagger: time.Millisecond}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := d.DialContext(ctx2, "tcp", "hang.example:80"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("dial: %v", err)
	}
	waitGoroutines(t, before)
}

type hangDialer struct{}

func (hangDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// goroutines counts the goroutines, without the one that js/wasm runs
// for events.
func goroutines() (int, string) {
	buf := make([]byte, 1<<20)
	stacks := string(buf[:runtime.Stack(buf, true)])
	n := 0
	for g := range strings.SplitSeq(stacks, "\n\n") {
		if !strings.Contains(g, "runtime.handleEvent") {
			n++
		}
	}
	return n, stacks
}

func waitGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n, stacks := goroutines()
		if n <= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines; want %d\n%s", n, want, stacks)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func listenTCP(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln, netip.MustParseAddrPort(ln.Addr().String()).Port()
}

var loopback = AllowPrefixes(netip.MustParsePrefix("127.0.0.0/8"))

// A real dial of an allowed name, and VerifyRemoteAddr catching a Forward
// that connects elsewhere.
func TestDialLoopback(t *testing.T) {
	ln, port := listenTCP(t)
	r := newFakeResolver(map[string][]string{"svc.example": {"127.0.0.1"}, "other.example": {"127.0.0.2"}})
	d := &Dialer{Resolver: r, Policy: loopback, VerifyRemoteAddr: true}
	c, err := d.DialContext(context.Background(), "tcp", "svc.example:"+strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q, %v", buf, err)
	}
	_ = c.Close()

	elsewhere := dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	})
	d.Forward = elsewhere
	_, err = d.DialContext(context.Background(), "tcp", "other.example:"+strconv.Itoa(int(port)))
	assertDenied(t, err, ErrRemoteMismatch, ln.Addr().String())
}

type dialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// An HTTP client follows a redirect through the Dialer again, which
// refuses a redirect to a refused address.
func TestHTTPRedirect(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("js/wasm HTTP clients use the fetch API")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	port := strconv.Itoa(int(netip.MustParseAddrPort(ln.Addr().String()).Port()))
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://127.0.0.1:"+port+"/", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	r := newFakeResolver(map[string][]string{"app.example": {"127.0.0.1"}})
	d := &Dialer{Resolver: r, Policy: Any(AllowNames("app.example"), DefaultPolicy())}
	tr := &http.Transport{DialContext: d.DialContext}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("http://app.example:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	_, err = client.Get("http://app.example:" + port + "/redirect")
	assertDenied(t, err, ErrScope, "127.0.0.1:"+port)
}

// Check does not allocate for an allowed address.
func TestCheckAllocs(t *testing.T) {
	var d *Dialer
	ap := netip.MustParseAddrPort("[2606:2800:220:1::1]:443")
	zoned := netip.MustParseAddrPort("[fe80::1%eth0]:443")
	allow := &Dialer{Policy: AllowScopes(netx.ScopeLinkLocal, netx.ScopeGlobal)}
	if n := testing.AllocsPerRun(100, func() {
		if d.Check("udp", ap) != nil || allow.Check("udp", zoned) != nil {
			t.Fatal("refused")
		}
	}); n != 0 {
		t.Errorf("%v allocations", n)
	}
}
