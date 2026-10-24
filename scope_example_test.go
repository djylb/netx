package netx_test

import (
	"fmt"
	"net/netip"

	"github.com/djylb/netx"
)

// Classify addresses before offering them to peers on the Internet.
func ExampleScopeOf() {
	for _, s := range []string{"203.0.113.7", "100.72.1.2", "::ffff:192.168.1.10", "2002:808:808::1", "2606:4700::1111"} {
		a := netip.MustParseAddr(s)
		fmt.Println(s, netx.ScopeOf(a), netx.IsGlobal(a))
	}
	// Output:
	// 203.0.113.7 documentation false
	// 100.72.1.2 shared false
	// ::ffff:192.168.1.10 private false
	// 2002:808:808::1 global true
	// 2606:4700::1111 global true
}
