package udpflow

import (
	"net"
	"net/netip"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/djylb/netx/internal/nettest"
)

// replyTargets returns local addresses of family v6 other than the
// loopback address that a peer bound to the loopback address reaches
// through a wildcard socket: routing then picks the loopback address as
// the source of a reply, unless the listener sends from the destination.
func replyTargets(t *testing.T, v6 bool) (loop netip.Addr, dsts []netip.Addr) {
	t.Helper()
	loop = netip.MustParseAddr("127.0.0.1")
	if v6 {
		loop = netip.IPv6Loopback()
	}
	// Use only assigned source addresses on Windows: a loopback alias can
	// receive packets even when the kernel refuses it as a sendmsg source.
	if runtime.GOOS == "windows" {
		dsts = append(dsts, loop)
	}
	if !v6 && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
		dsts = append(dsts, netip.MustParseAddr("127.0.0.2")) // all of 127/8 is local
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		// Tunnel endpoints can have local addresses that loopback traffic
		// cannot reach. Their availability is unrelated to packet info.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr()
			if ip.Is4() == v6 || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() {
				continue
			}
			dsts = append(dsts, ip)
		}
	}
	slices.SortFunc(dsts, netip.Addr.Compare)
	return loop, slices.Compact(dsts)
}

// TestPacketListenerReplySource: on a socket bound to a wildcard address,
// a connection replies from the address its peer sent to, and reports it
// as its LocalAddr; one datagram at a time and in batches, on IPv4 and
// dual-stack sockets.
func TestPacketListenerReplySource(t *testing.T) {
	for _, tc := range []struct {
		name, network, addr string
		v6                  bool
		batch               int
	}{
		{"udp4", "udp4", "0.0.0.0:0", false, 0},
		{"udp4-batch", "udp4", "0.0.0.0:0", false, 4},
		{"dual-v4", "udp", ":0", false, 0},
		{"dual-v4-batch", "udp", ":0", false, 4},
		{"udp6", "udp6", "[::]:0", true, 0},
		{"dual-v6", "udp", ":0", true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loop, dsts := replyTargets(t, tc.v6)
			if len(dsts) == 0 {
				t.Skip("no second local address of the family")
			}
			pc, err := net.ListenPacket(tc.network, tc.addr)
			if err != nil {
				t.Skip(err)
			}
			l := NewPacketListener(pc, WithPacketReadBatch(tc.batch))
			t.Cleanup(func() { _ = l.Close() })
			if !l.sock.pktinfo {
				t.Fatal("packet information not enabled on a wildcard socket")
			}
			port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
			for _, dst := range dsts {
				source := loop
				if runtime.GOOS == "windows" {
					// A host need not route loopback traffic across adapters.
					source = dst
				}
				checkReplySource(t, l, source, netip.AddrPortFrom(dst, port))
			}
		})
	}
}

func checkReplySource(t *testing.T, l *PacketListener, source netip.Addr, target netip.AddrPort) {
	t.Helper()
	client, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	if err = client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err = client.WriteToUDPAddrPort([]byte{1}, target); err != nil {
		t.Fatal(err)
	}
	flow := nettest.AcceptWithin(t, l)
	defer func() { _ = flow.Close() }()
	if err = flow.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if got := flow.LocalAddr().(*net.UDPAddr).AddrPort(); got != target {
		t.Fatalf("LocalAddr = %v, want %v", got, target)
	}
	var payload [2]byte
	if n, readErr := flow.Read(payload[:]); readErr != nil || n != 1 || payload[0] != 1 {
		t.Fatalf("read = %v, %v", payload[:n], readErr)
	}
	if n, writeErr := flow.Write(payload[:1]); writeErr != nil || n != 1 {
		t.Fatalf("write = %d, %v", n, writeErr)
	}
	n, from, err := client.ReadFromUDPAddrPort(payload[:])
	if err != nil || n != 1 || payload[0] != 1 || from != target {
		t.Fatalf("reply = %v from %v, %v; want %v", payload[:n], from, err, target)
	}
}

// A socket bound to one address needs no packet information.
func TestPacketListenerBoundNoPktinfo(t *testing.T) {
	l := newUDPListener(t)
	if l.sock.pktinfo {
		t.Fatal("packet information enabled on a bound socket")
	}
}

func TestPacketListenerWildcardDelayedReplies(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "android", "darwin", "ios":
	default:
		t.Skip("requires a loopback client that can reach two local destinations")
	}
	loop, dsts := replyTargets(t, false)
	if len(dsts) == 0 {
		t.Skip("no second local IPv4 destination")
	}
	for _, tc := range []struct {
		name  string
		batch int
	}{{"single", 0}, {"batch", 4}} {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			l := NewPacketListener(pc, WithPacketReadBatch(tc.batch))
			t.Cleanup(func() { _ = l.Close() })
			client, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loop, 0)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			deadline := time.Now().Add(5 * time.Second)
			_ = client.SetDeadline(deadline)
			port := l.Addr().(*net.UDPAddr).AddrPort().Port()
			destinations := [...]netip.AddrPort{netip.AddrPortFrom(loop, port), netip.AddrPortFrom(dsts[0], port)}
			var flows [len(destinations)]net.Conn
			var buf [8]byte
			for i, dst := range destinations {
				if _, err := client.WriteToUDPAddrPort([]byte{byte(i)}, dst); err != nil {
					t.Fatal(err)
				}
				flows[i] = nettest.AcceptWithin(t, l)
				_ = flows[i].SetReadDeadline(deadline)
				if n, err := flows[i].Read(buf[:]); err != nil || n != 1 || buf[0] != byte(i) {
					t.Fatalf("read at %v: %v, %v", dst, buf[:n], err)
				}
			}
			// Both datagrams were read before either reply is sent.
			for i, flow := range flows {
				if got := flow.LocalAddr().(*net.UDPAddr).AddrPort(); got != destinations[i] {
					t.Fatalf("flow LocalAddr = %v, want %v", got, destinations[i])
				}
				if n, err := flow.Write([]byte{byte(i)}); err != nil || n != 1 {
					t.Fatalf("write from %v: %d, %v", destinations[i], n, err)
				}
				n, from, err := client.ReadFromUDPAddrPort(buf[:])
				if err != nil || from != destinations[i] || n != 1 || buf[0] != byte(i) {
					t.Fatalf("reply from %v: %v, %v, want from %v", from, buf[:n], err, destinations[i])
				}
			}
		})
	}
}
