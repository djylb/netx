package safedial_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/safedial"
	"github.com/djylb/netx/socks5"
)

// staticResolver answers every name with its addresses.
type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if addrs, ok := r[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// The default policy refuses destinations that are not globally
// reachable, in whatever form a client names them.
func Example() {
	d := &safedial.Dialer{Resolver: staticResolver{
		"metadata.example": {netip.MustParseAddr("169.254.169.254")},
	}}
	for _, address := range []string{"127.1:6379", "[::ffff:10.0.0.1]:22", "metadata.example:80"} {
		_, err := d.DialContext(context.Background(), "tcp", address)
		var denied *safedial.DeniedError
		if errors.As(err, &denied) {
			fmt.Println(denied.Target, "->", errors.Is(err, safedial.ErrScope))
		}
		fmt.Println(err)
	}
	// Output:
	// 127.0.0.1:6379 -> true
	// safedial: tcp 127.0.0.1:6379: loopback address not allowed
	// 10.0.0.1:22 -> true
	// safedial: tcp 10.0.0.1:22: private address not allowed
	// metadata.example:80 (169.254.169.254) -> true
	// safedial: tcp metadata.example:80 (169.254.169.254): link-local address not allowed
}

// An HTTP client for webhooks to URLs that users give. Each redirect dials
// again and is checked; the Transport has no Proxy, which would resolve the
// names itself.
func Example_httpClient() {
	d := &safedial.Dialer{
		Policy: safedial.All(safedial.AllowPorts(80, 443), safedial.DefaultPolicy()),
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:         d.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
	_, err := client.Get("http://192.168.1.1/")
	fmt.Println(errors.Is(err, safedial.ErrDenied))
	// Output: true
}

// Policies combine: here a tunnel client may reach the private hosts of
// its own network by name, but not loopback or link-local ones such as a
// metadata service, and other destinations only when they are global,
// never on the SMTP port.
func ExampleAny() {
	policy := safedial.All(
		safedial.DenyPorts(25),
		safedial.Any(
			safedial.All(safedial.AllowNames("corp.example"), safedial.AllowScopes(netx.ScopePrivate, netx.ScopeGlobal)),
			safedial.AllowPrefixes(netip.MustParsePrefix("100.64.0.0/10")),
			safedial.DefaultPolicy(),
		),
	)
	d := &safedial.Dialer{Policy: policy, Resolver: staticResolver{
		"git.corp.example":  {netip.MustParseAddr("10.0.0.7")},
		"meta.corp.example": {netip.MustParseAddr("169.254.169.254")},
		"evil.example":      {netip.MustParseAddr("10.0.0.7")},
	}}
	for _, address := range []string{"git.corp.example:22", "meta.corp.example:80", "evil.example:22", "100.64.0.9:22", "8.8.8.8:25"} {
		addrs, err := d.Lookup(context.Background(), "tcp", address)
		fmt.Println(address, addrs, err)
	}
	// Output:
	// git.corp.example:22 [10.0.0.7:22] <nil>
	// meta.corp.example:80 [] safedial: tcp meta.corp.example:80 (169.254.169.254): link-local address not allowed
	// evil.example:22 [] safedial: tcp evil.example:22 (10.0.0.7): private address not allowed
	// 100.64.0.9:22 [100.64.0.9:22] <nil>
	// 8.8.8.8:25 [] safedial: tcp 8.8.8.8:25: port not allowed
}

func ExampleParseTarget() {
	for _, address := range []string{"0x7f.1:80", "[fe80::1%eth0]:80", "Example.COM:443", "127.0.0.1 x:80"} {
		t, err := safedial.ParseTarget("tcp", address)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Printf("%q %q\n", t.Addr, t.Name)
	}
	// Output:
	// "127.0.0.1" ""
	// "fe80::1" ""
	// "invalid IP" "example.com"
	// safedial: netx: invalid address: host name "127.0.0.1 x"
}

// A SOCKS5 server for less trusted clients: CONNECT dials through the
// Dialer, and every datagram of a UDP association is checked, also those
// to names, which the wrapper resolves itself, while replies come from any
// source.
func ExampleDialer_WrapAddrPacketConn() {
	d := &safedial.Dialer{}
	s := &socks5.Server{
		Dial: func(ctx context.Context, req *socks5.Request) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", req.Dst.String())
		},
		ListenUDP: socks5.ListenAssociationUDP,
		DialPacket: func(ctx context.Context, _ *socks5.Request) (socks5.PacketConn, error) {
			c, err := netx.ListenEphemeralUDP(ctx, nil)
			if err != nil {
				return nil, err
			}
			return d.WrapAddrPacketConn(socks5.NewPacketConn(c)), nil
		},
	}
	_ = s
}
