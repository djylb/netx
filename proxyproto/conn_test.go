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
		name    string
		cfg     Config
		data    []byte
		remote  string
		payload string
		err     error
	}{
		{"required", Config{}, append(header, "hello"...), "203.0.113.7:40000", "hello", nil},
		{"required without header", Config{}, []byte("hello"), "pipe", "", ErrNoHeader},
		{"optional", Config{Policy: Optional}, append(header, "hello"...), "203.0.113.7:40000", "hello", nil},
		{"optional without header", Config{Policy: Optional}, []byte("hello"), "pipe", "hello", nil},
		{"ignore", Config{Policy: Ignore}, append(header, "hello"...), "pipe", string(header) + "hello", nil},
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
	for i := range typ.NumField() {
		if f := typ.Field(i); f.IsExported() {
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
		name string
		c    net.Conn
		want bool
	}{
		{"conn", c, true},
		{"wrapped", &wrapConn{&wrapConn{c}}, true},
		{"tls", tls.Server(c, &tls.Config{}), true},
		{"plain", &wrapConn{pipeWith(t, nil)}, false},
		{"nil", nil, false},
		{"nil conn", (*Conn)(nil), false},
		{"nil tls", (*tls.Conn)(nil), false},
		{"wrapping nil", &wrapConn{}, false},
		{"loop", &loopConn{}, false},
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
		name string
		peer net.Addr
		want Policy
	}{
		{"ipv4 inside", tcp("10.1.2.3", 1), Required},
		{"ipv4 outside", tcp("192.0.2.1", 1), Ignore},
		{"4-byte ipv4", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1).To4(), Port: 1}, Required},
		{"ipv4-mapped", tcp("::ffff:10.0.0.1", 1), Required},
		{"udp", udp("10.0.0.1", 1), Required},
		{"ipv6 inside", tcp("2001:db8::1", 1), Required},
		{"ipv6 with zone", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1, Zone: "eth0"}, Required},
		{"ipv6 outside", tcp("2001:db9::1", 1), Ignore},
		{"other type with port", dummyAddr("10.0.0.1:80"), Required},
		{"other type ipv6 with zone", dummyAddr("[2001:db8::1%eth0]:80"), Required},
		{"other type without port", dummyAddr("10.0.0.1"), Required},
		{"other type outside", dummyAddr("192.0.2.1:80"), Ignore},
		{"not an address", dummyAddr("pipe"), Ignore},
		{"unix", &net.UnixAddr{Name: "/run/lb.sock", Net: "unix"}, Ignore},
		{"tcp without ip", &net.TCPAddr{Port: 1}, Ignore},
		{"nil", nil, Ignore},
		{"nil tcp", (*net.TCPAddr)(nil), Ignore},
		{"nil unix", (*net.UnixAddr)(nil), Ignore},
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
