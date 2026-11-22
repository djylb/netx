package flowtable

import (
	"hash/maphash"
	"net/netip"
	"testing"
)

type allocKey struct {
	peer netip.AddrPort
	dst  string
}

type allocFlow struct {
	member Membership[allocKey, netip.AddrPort]
}

func hashTestPeer(seed maphash.Seed, peer netip.AddrPort) uint64 {
	var h maphash.Hash
	h.SetSeed(seed)
	WriteAddrPort(&h, peer)
	return h.Sum64()
}

func TestTableShardOperationsDoNotAllocate(t *testing.T) {
	const runs = 64
	for _, indexed := range []bool{false, true} {
		name := "key"
		if indexed {
			name = "peer"
		}
		t.Run(name, func(t *testing.T) {
			var table Table[allocKey, netip.AddrPort, *allocFlow]
			opts := TableOptions[allocKey, netip.AddrPort, *allocFlow]{
				Membership: func(f *allocFlow) *Membership[allocKey, netip.AddrPort] { return &f.member },
				HashKey: func(seed maphash.Seed, k allocKey) uint64 {
					var h maphash.Hash
					h.SetSeed(seed)
					WriteAddrPort(&h, k.peer)
					_, _ = h.WriteString(k.dst)
					return h.Sum64()
				},
				Shutdown: func(f *allocFlow, _ error) { table.Remove(f) },
			}
			if indexed {
				opts.Peer = func(k allocKey) netip.AddrPort { return k.peer }
				opts.HashPeer = hashTestPeer
			}
			table.Init(opts)
			defer table.Close(nil)
			addr := netip.IPv6Loopback().WithZone("test-zone")
			key := allocKey{peer: netip.AddrPortFrom(addr, 1), dst: "existing"}
			absent := allocKey{peer: key.peer, dst: "absent"}
			var flow allocFlow
			table.Add(key, &flow, false)

			// Existing-key operations and a failed resolution do not publish
			// an entry in sync.Map, so any allocation here is extraneous.
			if n := testing.AllocsPerRun(runs, func() {
				_, result := table.Add(key, &flow, false)
				if result != Exists || table.Resolve(key, nil) != &flow || table.Resolve(absent, nil) != nil {
					t.Fatal("unexpected Add or Resolve result")
				}
			}); n != 0 {
				t.Fatalf("Add hit and Resolve hit/miss allocated %.2f times per run", n)
			}

			// Publish distinct keys before measuring successful removals.
			var flows [runs + 1]allocFlow
			for i := range flows {
				k := allocKey{peer: netip.AddrPortFrom(addr, uint16(i+2)), dst: key.dst}
				table.Add(k, &flows[i], false)
			}
			i := 0
			if n := testing.AllocsPerRun(runs, func() {
				table.Remove(&flows[i])
				i++
			}); n != 0 || table.Len() != 1 {
				t.Fatalf("Remove allocated %.2f times per run, len = %d", n, table.Len())
			}
			if indexed {
				var dial allocFlow
				peer := netip.AddrPortFrom(addr, 0)
				if n := testing.AllocsPerRun(runs, func() {
					if _, result := table.AddUnbound(peer, &dial); result != Added {
						t.Fatalf("AddUnbound = %v, want Added", result)
					}
					table.Remove(&dial)
				}); n != 0 {
					t.Fatalf("AddUnbound and Remove allocated %.2f times per run", n)
				}
			}
		})
	}
}
