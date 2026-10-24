package forwarded_test

import (
	"fmt"
	"net/http"
	"net/netip"

	"github.com/djylb/netx/forwarded"
)

// Find the client behind a load balancer on the private network, ignoring
// the address that the client itself put in front.
func ExampleResolver() {
	trusted, err := forwarded.ParsePrefixSet("10.0.0.0/8", "fd00::/8")
	if err != nil {
		panic(err)
	}
	r := &forwarded.Resolver{Trusted: trusted}

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:41000"
	req.Header.Add("X-Forwarded-For", "127.0.0.1, 198.51.100.17")
	req.Header.Set("X-Forwarded-Proto", "https")

	peer, _ := forwarded.ParseNode(req.RemoteAddr)
	c := r.Resolve(peer, req.Header)
	fmt.Println(c.Addr.Addr(), c.Hops, c.Proto)
	// Output: 198.51.100.17 1 https
}

// Read the RFC 7239 Forwarded field, which carries the scheme and host per
// hop.
func ExampleHeaderForwarded() {
	r := &forwarded.Resolver{
		Trusted: forwarded.NewPrefixSet(netip.MustParsePrefix("192.0.2.0/24")),
		Header:  forwarded.HeaderForwarded,
	}
	h := http.Header{"Forwarded": {`for="[2001:db8:cafe::17]:4711";proto=https;host=example.com, for=192.0.2.43`}}
	c := r.Resolve(netip.MustParseAddrPort("192.0.2.1:8000"), h)
	fmt.Println(c.Addr, c.Hops, c.Proto, c.Host)
	// Output: [2001:db8:cafe::17]:4711 2 https example.com
}

// Pass the request on, recording this hop in both forwarding fields.
func ExampleAppendForwarded() {
	in := http.Header{"X-Forwarded-For": {"198.51.100.17"}, "Forwarded": {"for=198.51.100.17"}}
	client := netip.MustParseAddrPort("[2001:db8::5]:51000")

	out := http.Header{}
	out.Set("X-Forwarded-For", string(forwarded.AppendXForwardedFor(nil, in["X-Forwarded-For"], client.Addr())))
	out.Set("Forwarded", string(forwarded.AppendForwarded(nil, in["Forwarded"], forwarded.Element{For: client, Proto: "https"})))
	fmt.Println(out.Get("X-Forwarded-For"))
	fmt.Println(out.Get("Forwarded"))
	// Output:
	// 198.51.100.17, 2001:db8::5
	// for=198.51.100.17, for="[2001:db8::5]:51000";proto=https
}
