package proxyproto

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

// pipeWith returns the server end of a pipe whose client writes data and
// closes.
func pipeWith(t *testing.T, data []byte) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		_, _ = client.Write(data)
		_ = client.Close()
	}()
	return server
}

func TestNewConn(t *testing.T) {
	header := wireOf(V1, tcp("203.0.113.7", 40000), tcp("198.51.100.1", 443))
	for _, tt := range []struct {
		err     error
		name    string
		remote  string
		payload string
		data    []byte
		cfg     Config
	}{
		{name: "required", cfg: Config{}, data: append(header, "hello"...), remote: "203.0.113.7:40000", payload: "hello", err: nil},
		{name: "required without header", cfg: Config{}, data: []byte("hello"), remote: "pipe", payload: "", err: ErrNoHeader},
		{name: "optional", cfg: Config{Policy: Optional}, data: append(header, "hello"...), remote: "203.0.113.7:40000", payload: "hello", err: nil},
		{name: "optional without header", cfg: Config{Policy: Optional}, data: []byte("hello"), remote: "pipe", payload: "hello", err: nil},
		{name: "ignore", cfg: Config{Policy: Ignore}, data: append(header, "hello"...), remote: "pipe", payload: string(header) + "hello", err: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConn(pipeWith(t, tt.data), tt.cfg)
			got, err := io.ReadAll(c)
			if !errors.Is(err, tt.err) || string(got) != tt.payload {
				t.Fatalf("ReadAll() = %q, %v; want %q, %v", got, err, tt.payload, tt.err)
			}
			if got := c.RemoteAddr().String(); got != tt.remote {
				t.Fatalf("RemoteAddr() = %s, want %s", got, tt.remote)
			}
			h, err := HeaderOf(c)
			if wantHeader := tt.remote != "pipe"; (h != nil) != wantHeader || !errors.Is(err, tt.err) {
				t.Fatalf("HeaderOf() = %v, %v", h, err)
			}
		})
	}
}

func TestNewConnHeaderTimeout(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	c := NewConn(server, Config{HeaderTimeout: 50 * time.Millisecond})
	defer func() { _ = c.Close() }()
	if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("Read() error = %v, want the header timeout", err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, ErrNoHeader) || isTimeout(err) {
		t.Fatalf("Read() after the header timeout = %v, want ErrNoHeader and no timeout", err)
	}
	if c.timeout != 50*time.Millisecond || NewConn(server, Config{}).timeout != DefaultHeaderTimeout {
		t.Fatal("HeaderTimeout not applied")
	}
}

func TestNewConnDatagram(t *testing.T) {
	raw := &datagramScript{msgs: [][]byte{
		append(wireOf(V1, udp("203.0.113.7", 40000), udp("198.51.100.1", 53)), "q1"...),
		[]byte("q2"),
	}}
	c := NewConn(raw, Config{Datagram: true})
	buf := make([]byte, 16)
	for _, want := range []string{"q1", "q2"} {
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("Read() = %q, %v; want %q", buf[:n], err, want)
		}
	}
	if a, ok := c.RemoteAddr().(*net.UDPAddr); !ok || a.String() != "203.0.113.7:40000" {
		t.Fatalf("RemoteAddr() = %#v, want the UDP source", c.RemoteAddr())
	}
}

// datagramScript returns one message per Read, then io.EOF.
type datagramScript struct {
	net.Conn
	msgs [][]byte
}

func (c *datagramScript) Read(b []byte) (int, error) {
	if len(c.msgs) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.msgs[0])
	c.msgs = c.msgs[1:]
	return n, nil
}

func (*datagramScript) SetReadDeadline(time.Time) error { return nil }

// The Conn owns what it wraps, and writes and the write deadline reach it
// without waiting for the header.
func TestConnForwardsWriteCloseAndDeadline(t *testing.T) {
	server, client := net.Pipe()
	c := NewConn(server, Config{})
	done := make(chan []byte, 1)
	go func() {
		b := make([]byte, 2)
		n, _ := io.ReadFull(client, b)
		done <- b[:n]
	}()
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if got := <-done; string(got) != "hi" {
		t.Fatalf("peer read %q", got)
	}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("x")); !isTimeout(err) {
		t.Fatalf("Write() after a past write deadline = %v, want a timeout", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer Read() after Close = %v, want EOF", err)
	}
}

// Conn has no exported fields, so the connection beneath is reached only
// through NetConn.
func TestConnHasNoExportedFields(t *testing.T) {
	typ := reflect.TypeFor[Conn]()
	for f := range typ.Fields() {
		if f.IsExported() {
			t.Fatalf("Conn exports field %s", f.Name)
		}
	}
}

// wrapConn wraps a connection with a NetConn method, as *tls.Conn does.
type wrapConn struct {
	net.Conn
}

func (w *wrapConn) NetConn() net.Conn { return w.Conn }

// loopConn is a wrapper whose NetConn returns itself.
type loopConn struct{ net.Conn }

func (l *loopConn) NetConn() net.Conn { return l }

func TestHeaderOf(t *testing.T) {
	header := wireOf(V2, tcp("203.0.113.7", 40000), tcp("198.51.100.1", 443))
	c := NewConn(pipeWith(t, header), Config{})
	for _, tt := range []struct {
		c    net.Conn
		name string
		want bool
	}{
		{name: "conn", c: c, want: true},
		{name: "wrapped", c: &wrapConn{&wrapConn{c}}, want: true},
		{name: "tls", c: tls.Server(c, &tls.Config{}), want: true},
		{name: "plain", c: &wrapConn{pipeWith(t, nil)}, want: false},
		{name: "nil", c: nil, want: false},
		{name: "nil conn", c: (*Conn)(nil), want: false},
		{name: "nil tls", c: (*tls.Conn)(nil), want: false},
		{name: "wrapping nil", c: &wrapConn{}, want: false},
		{name: "loop", c: &loopConn{}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, err := HeaderOf(tt.c)
			if err != nil || (h != nil) != tt.want {
				t.Fatalf("HeaderOf() = %v, %v; want a header: %v", h, err, tt.want)
			}
			if tt.want && h.Source.String() != "203.0.113.7:40000" {
				t.Fatalf("HeaderOf() source = %v", h.Source)
			}
		})
	}
}

// The policy of TrustPrefixes asks for a header from peers in the prefixes
// only.
func TestTrustPrefixes(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")}
	policy := TrustPrefixes(prefixes...)
	prefixes[0] = netip.MustParsePrefix("0.0.0.0/0") // the policy keeps its own copy
	for _, tt := range []struct {
		peer net.Addr
		name string
		want Policy
	}{
		{name: "ipv4 inside", peer: tcp("10.1.2.3", 1), want: Required},
		{name: "ipv4 outside", peer: tcp("192.0.2.1", 1), want: Ignore},
		{name: "4-byte ipv4", peer: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1).To4(), Port: 1}, want: Required},
		{name: "ipv4-mapped", peer: tcp("::ffff:10.0.0.1", 1), want: Required},
		{name: "udp", peer: udp("10.0.0.1", 1), want: Required},
		{name: "ipv6 inside", peer: tcp("2001:db8::1", 1), want: Required},
		{name: "ipv6 with zone", peer: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1, Zone: "eth0"}, want: Required},
		{name: "ipv6 outside", peer: tcp("2001:db9::1", 1), want: Ignore},
		{name: "other type with port", peer: dummyAddr("10.0.0.1:80"), want: Required},
		{name: "other type ipv6 with zone", peer: dummyAddr("[2001:db8::1%eth0]:80"), want: Required},
		{name: "other type without port", peer: dummyAddr("10.0.0.1"), want: Required},
		{name: "other type outside", peer: dummyAddr("192.0.2.1:80"), want: Ignore},
		{name: "not an address", peer: dummyAddr("pipe"), want: Ignore},
		{name: "unix", peer: &net.UnixAddr{Name: "/run/lb.sock", Net: "unix"}, want: Ignore},
		{name: "tcp without ip", peer: &net.TCPAddr{Port: 1}, want: Ignore},
		{name: "nil", peer: nil, want: Ignore},
		{name: "nil tcp", peer: (*net.TCPAddr)(nil), want: Ignore},
		{name: "nil unix", peer: (*net.UnixAddr)(nil), want: Ignore},
	} {
		if got := policy(tt.peer); got != tt.want {
			t.Errorf("%s: policy(%v) = %d, want %d", tt.name, tt.peer, got, tt.want)
		}
	}
	if got := TrustPrefixes()(tcp("10.0.0.1", 1)); got != Ignore {
		t.Fatalf("TrustPrefixes() policy = %d, want Ignore", got)
	}
}

// A Listener with the policy of TrustPrefixes passes untrusted peers through
// unchanged.
func TestListenerTrustPrefixes(t *testing.T) {
	l := newTestListener(t)
	l.PolicyFor = TrustPrefixes(netip.MustParsePrefix("192.0.2.0/24"))
	header := wireOf(V1, tcp("203.0.113.7", 40000), tcp("198.51.100.1", 443))
	server, _ := acceptOne(t, l, header)
	if _, ok := server.(*Conn); ok {
		t.Fatal("Accept() wrapped an untrusted peer")
	}
	if h, err := HeaderOf(server); h != nil || err != nil {
		t.Fatalf("HeaderOf() = %v, %v; want none", h, err)
	}

	l.PolicyFor = TrustPrefixes(netip.MustParsePrefix("127.0.0.0/8"))
	server, _ = acceptOne(t, l, header)
	if h, err := HeaderOf(server); err != nil || h == nil || h.Source.String() != "203.0.113.7:40000" {
		t.Fatalf("HeaderOf() = %v, %v; want the header of a trusted peer", h, err)
	}
}

// A Conn over no connection fails like a closed one instead of panicking.
func TestNewConnNil(t *testing.T) {
	for _, inner := range []net.Conn{nil, (*net.TCPConn)(nil)} {
		for _, policy := range []Policy{Required, Optional, Ignore} {
			c := NewConn(inner, Config{Policy: policy, Datagram: policy == Optional})
			if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Read() = %v", err)
			}
			if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Write() = %v", err)
			}
			if _, err := c.WriteTo(io.Discard); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("WriteTo() = %v", err)
			}
			if _, err := c.ReadFrom(strings.NewReader("x")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ReadFrom() = %v", err)
			}
			if h, err := c.Header(); h != nil || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Header() = %v, %v", h, err)
			}
			if h, err := HeaderOf(c); h != nil || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("HeaderOf() = %v, %v", h, err)
			}
			now := time.Now()
			for name, err := range map[string]error{
				"SetDeadline": c.SetDeadline(now), "SetReadDeadline": c.SetReadDeadline(now),
				"SetWriteDeadline": c.SetWriteDeadline(now), "CloseWrite": c.CloseWrite(),
			} {
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("%s() = %v", name, err)
				}
			}
			if c.RemoteAddr() != nil || c.LocalAddr() != nil || c.NetConn() != nil {
				t.Fatal("addresses or NetConn of a nil connection are not nil")
			}
			if err := c.Close(); err != nil {
				t.Fatalf("Close() = %v", err)
			}
		}
	}
}

// IPv4-mapped prefixes match IPv4 peers in either form, and IPv6 prefixes
// match the IPv4-mapped form of IPv4 peers.
func TestTrustPrefixesMapped(t *testing.T) {
	for _, tt := range []struct {
		prefix string
		peer   string
		want   Policy
	}{
		{"::ffff:10.0.0.0/104", "10.1.2.3", Required},
		{"::ffff:10.0.0.0/104", "::ffff:10.1.2.3", Required},
		{"::ffff:10.0.0.0/104", "11.0.0.1", Ignore},
		{"::ffff:10.1.2.3/128", "10.1.2.3", Required},
		{"::ffff:10.9.9.9/104", "10.1.2.3", Required}, // masked
		{"10.9.9.9/8", "10.1.2.3", Required},          // masked
		{"::ffff:0.0.0.0/96", "192.0.2.1", Required},
		{"::ffff:0:0/80", "192.0.2.1", Required}, // holds every IPv4-mapped address
		{"2001:db8::/32", "192.0.2.1", Ignore},
		{"::/0", "192.0.2.1", Required},
		{"::/80", "192.0.2.1", Required},
		{"::/0", "2001:db8::1", Required},
		{"10.0.0.0/8", "2001:db8::1", Ignore},
	} {
		policy := TrustPrefixes(netip.MustParsePrefix(tt.prefix))
		if got := policy(tcp(tt.peer, 1)); got != tt.want {
			t.Errorf("TrustPrefixes(%s)(%s) = %d, want %d", tt.prefix, tt.peer, got, tt.want)
		}
	}
	if got := TrustPrefixes(netip.Prefix{})(tcp("10.0.0.1", 1)); got != Ignore {
		t.Fatalf("invalid prefix policy = %d, want Ignore", got)
	}
}
