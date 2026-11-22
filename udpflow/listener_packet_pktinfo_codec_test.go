//go:build linux || darwin || windows

package udpflow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/netx/internal/nettest"
	"github.com/djylb/netx/internal/netutil"
)

type packetTestWriter struct {
	err   error
	calls []string
}

func (w *packetTestWriter) WriteMsgUDPAddrPort(p, _ []byte, _ netip.AddrPort) (int, int, error) {
	w.calls = append(w.calls, "fixed")
	if w.err != nil {
		err := w.err
		w.err = nil
		return 0, 0, &net.OpError{Op: "write", Err: os.NewSyscallError("sendmsg", err)}
	}
	return len(p), 0, nil
}

func (w *packetTestWriter) WriteToUDPAddrPort(p []byte, _ netip.AddrPort) (int, error) {
	w.calls = append(w.calls, "routed")
	return len(p), nil
}

func TestPacketListenerReplySourceErrorRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, ip  string
		in, want  error
		calls     []string
		permanent bool
	}{
		{"temporary address error", "2001:db8::1", netutil.AddrNotAvailableErrnos[0], nil, []string{"fixed", "routed", "fixed"}, false},
		{"ambiguous invalid argument", "198.51.100.2", errPktinfoInvalidArgument, errPktinfoInvalidArgument, []string{"fixed", "fixed"}, false},
		{"broadcast invalid argument", "255.255.255.255", errPktinfoInvalidArgument, nil, []string{"fixed", "routed", "routed"}, true},
		{"multicast address error", "ff02::1", netutil.AddrNotAvailableErrnos[0], nil, []string{"fixed", "routed", "routed"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := newFeedPacketConn()
			l := NewPacketListener(pc)
			t.Cleanup(func() { _ = l.Close() })
			peer := netip.MustParseAddrPort("192.0.2.8:1234")
			local := netip.AddrPortFrom(netip.MustParseAddr(tc.ip), 9)
			k := packetFlow{peer: peerKey{ap: peer}, local: packetDestination{ap: local}}
			c := l.makeConn(k, net.UDPAddrFromAddrPort(peer), &l.sock)
			t.Cleanup(func() { _ = c.Close() })
			w := &packetTestWriter{err: tc.in}
			p := []byte{1}
			if n, err := c.writeUDP(w, p, peer); !errors.Is(err, tc.want) || (err == nil && n != len(p)) {
				t.Errorf("first write = %d, %v, want error %v", n, err, tc.want)
			}
			if n, err := c.writeUDP(w, p, peer); err != nil || n != len(p) {
				t.Fatalf("second write = %d, %v", n, err)
			}
			if !slices.Equal(w.calls, tc.calls) || c.routedReplies.Load() != tc.permanent {
				t.Errorf("writes = %v, permanent fallback = %v, want %v, %v", w.calls, c.routedReplies.Load(), tc.calls, tc.permanent)
			}
			wantLocal := local.String()
			if tc.permanent {
				wantLocal = pc.LocalAddr().String()
			}
			if got := c.LocalAddr().String(); got != wantLocal {
				t.Errorf("LocalAddr = %s, want %s", got, wantLocal)
			}
		})
	}
}

func packetTestDst4(dst netip.Addr, ifindex uint32) []byte {
	var info [sizeofInet4Pktinfo]byte
	a := dst.As4()
	copy(info[inet4PktinfoAddr:], a[:])
	binary.NativeEndian.PutUint32(info[inet4PktinfoIfindex:], ifindex)
	return putCmsg(syscall.IPPROTO_IP, ipPktinfoRecv, info[:])
}

func TestPacketListenerEstablishedFlowSkipsBroadcastSnapshot(t *testing.T) {
	pc := newFeedPacketConn()
	l := NewPacketListener(pc)
	t.Cleanup(func() { _ = l.Close() })
	sock := packetSocket{pc: pc, pktinfo: true, port: 9}
	peer := netip.MustParseAddrPort("192.0.2.8:1234")
	oob := packetTestDst4(netip.MustParseAddr("198.51.100.1"), 1)
	l.deliver([]byte("first"), peer, nil, &sock, oob)
	c := nettest.AcceptWithin(t, l).(*packetConn)
	// Observe refresh requests without running the worker.
	refresh := make(chan struct{}, 1)
	l.broadcasts = &packetBroadcasts{refresh: refresh}
	l.broadcasts.snapshot.Store(&packetBroadcastSnapshot{expires: time.Now().Add(time.Hour)})
	newPeer := netip.MustParseAddrPort("192.0.2.8:1235")
	l.deliver([]byte("new before expiry"), newPeer, nil, &sock, oob)
	if len(refresh) != 0 {
		t.Fatal("a flow miss requested refresh before expiry")
	}
	snapshot := &packetBroadcastSnapshot{} // already expired
	l.broadcasts.snapshot.Store(snapshot)
	l.deliver([]byte("second"), peer, nil, &sock, oob)
	if len(refresh) != 0 || l.broadcasts.snapshot.Load() != snapshot || c.q.Len() != 2 {
		t.Fatal("an established flow consulted the expired broadcast snapshot")
	}
	newPeer = netip.MustParseAddrPort("192.0.2.8:1236")
	l.deliver([]byte("new after expiry"), newPeer, nil, &sock, oob)
	if len(refresh) != 1 || l.broadcasts.snapshot.Load() != snapshot {
		t.Fatal("a flow miss should request refresh and keep using the stale snapshot")
	}
}

func TestPacketListenerDirectedBroadcastIgnoresInterface(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var broadcast netip.Addr
	for _, addr := range addrs {
		if n, ok := addr.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsLoopback() {
			ones, bits := n.Mask.Size()
			if bits == 32 && ones > 0 && ones < 31 {
				ip := [4]byte(n.IP.To4())
				for i := range ip {
					ip[i] |= ^n.Mask[i]
				}
				broadcast = netip.AddrFrom4(ip)
				break
			}
		}
	}
	if !broadcast.IsValid() {
		t.Skip("IPv4 loopback has no subnet broadcast address")
	}
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(pc)
	t.Cleanup(func() { _ = l.Close() })
	peer := netip.MustParseAddrPort("192.0.2.8:1234")
	l.deliver([]byte("group"), peer, nil, &l.sock, packetTestDst4(broadcast, ^uint32(0)))
	c := nettest.AcceptWithin(t, l).(*packetConn)
	if c.from.Load() != nil || c.LocalAddr().String() != pc.LocalAddr().String() {
		t.Fatalf("broadcast flow has unicast LocalAddr %v", c.LocalAddr())
	}
}

func TestPacketListenerInvalidReplySourceFallsBack(t *testing.T) {
	pc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(pc)
	t.Cleanup(func() { _ = l.Close() })
	loop := netip.MustParseAddr("127.0.0.1")
	client, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loop, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	peer := peerKeyOf(client.LocalAddr())
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	// Model a stale snapshot that admitted a broadcast as a unicast flow.
	local := packetDestination{ap: netip.AddrPortFrom(netip.MustParseAddr("255.255.255.255"), port)}
	c := l.makeConn(packetFlow{peer: peer, local: local}, client.LocalAddr(), &l.sock)
	t.Cleanup(func() { _ = c.Close() })
	for i := range 2 {
		if n, err := c.Write([]byte{byte(i)}); err != nil || n != 1 {
			t.Fatalf("Write #%d = %d, %v, want a routed reply", i, n, err)
		}
		var p [8]byte
		n, from, err := client.ReadFromUDPAddrPort(p[:])
		if n != 1 || p[0] != byte(i) || from != netip.AddrPortFrom(loop, port) || err != nil {
			t.Fatalf("reply #%d: %v bytes from %v, %v", i, n, from, err)
		}
	}
	if c.LocalAddr().String() != pc.LocalAddr().String() {
		t.Fatalf("LocalAddr after fallback = %v, want socket address", c.LocalAddr())
	}
}

func TestPacketInfoDualStackIPv4Loopback(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Skipf("dual-stack UDP unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if !pc.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Is6() {
		t.Skip("UDP socket uses an IPv4-only stack")
	}
	if !enablePacketInfo(pc) {
		t.Fatal("could not enable packet information on dual-stack UDP")
	}
	loop := netip.MustParseAddr("127.0.0.1")
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(loop, port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	var p [8]byte
	var oob [pktinfoOOB]byte
	n, oobn, _, _, err := pc.ReadMsgUDPAddrPort(p[:], oob[:])
	if n != 1 || p[0] != 1 || err != nil {
		t.Fatalf("read IPv4 loopback datagram on dual-stack socket: %d, %v", n, err)
	}
	if dst, _ := packetDst(oob[:oobn]); dst != loop {
		t.Fatalf("dual-stack IPv4 destination = %v, want %v", dst, loop)
	}
}

func TestPacketListenerSeparatesDestinations(t *testing.T) {
	pc := newFeedPacketConn()
	l := NewPacketListener(pc)
	t.Cleanup(func() { _ = l.Close() })
	sock := packetSocket{pc: pc, pktinfo: true, port: 9}
	peer := netip.MustParseAddrPort("192.0.2.8:1234")
	a := netip.MustParseAddr("198.51.100.1")
	b := netip.MustParseAddr("198.51.100.2")
	local := netip.MustParseAddr("169.254.10.1")
	for _, d := range []struct {
		dst     netip.Addr
		payload string
		ifindex uint32
	}{
		{a, "a", 1}, {b, "b", 1}, {a, "c", 2}, {local, "d", 1}, {local, "e", 2},
	} {
		l.deliver([]byte(d.payload), peer, nil, &sock, packetTestDst4(d.dst, d.ifindex))
	}
	l.deliver([]byte("no destination"), peer, nil, &sock, nil)
	if pending := l.conns.Pending(); pending != 4 {
		t.Fatalf("%d pending flows, want two global destinations and two link-local interfaces", pending)
	}
	for _, want := range []struct {
		dst      netip.Addr
		payloads []string
	}{
		{a, []string{"a", "c"}}, {b, []string{"b"}}, {local, []string{"d"}}, {local, []string{"e"}},
	} {
		c := nettest.AcceptWithin(t, l)
		if got, address := c.LocalAddr().(*net.UDPAddr).AddrPort(), netip.AddrPortFrom(want.dst, sock.port); got != address {
			t.Fatalf("LocalAddr = %v, want %v", got, address)
		}
		if queued := c.(*packetConn).q.Len(); queued != len(want.payloads) {
			t.Fatalf("%d queued datagrams, want %d", queued, len(want.payloads))
		}
		buf := make([]byte, 8)
		for _, payload := range want.payloads {
			if n, err := c.Read(buf); err != nil || string(buf[:n]) != payload {
				t.Fatalf("Read = %q, %v, want %q", buf[:n], err, payload)
			}
		}
	}
}

func TestPacketListenerGroupDestinations(t *testing.T) {
	pc := newFeedPacketConn()
	l := NewPacketListener(pc)
	t.Cleanup(func() { _ = l.Close() })
	sock := packetSocket{pc: pc, pktinfo: true, port: 9}
	peer := netip.MustParseAddrPort("192.0.2.8:1234")
	for i, addr := range []string{"255.255.255.255", "224.0.0.1", "239.1.2.3"} {
		l.deliver([]byte{byte(i)}, peer, nil, &sock, packetTestDst4(netip.MustParseAddr(addr), uint32(i+1)))
	}
	if pending := l.conns.Pending(); pending != 1 {
		t.Fatalf("%d pending flows, want one for the group's peer", pending)
	}
	c := nettest.AcceptWithin(t, l).(*packetConn)
	if c.q.Len() != 3 || c.from.Load() != nil || c.LocalAddr().String() != pc.LocalAddr().String() {
		t.Fatalf("group flow has %d datagrams and LocalAddr %v, want three datagrams and the socket address", c.q.Len(), c.LocalAddr())
	}
}

func TestPacketListenerMixedPacketInfoDial(t *testing.T) {
	for _, primaryWildcard := range []bool{true, false} {
		name := "wildcard additional"
		if primaryWildcard {
			name = "wildcard primary"
		}
		t.Run(name, func(t *testing.T) {
			wildcard, err := net.ListenPacket("udp4", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			var primary, extra net.PacketConn = wildcard, newFeedPacketConn()
			if !primaryWildcard {
				primary, extra = extra, primary
			}
			l := NewPacketListener(primary, WithPacketConns(extra), WithPacketMaxConns(2))
			t.Cleanup(func() { _ = l.Close() })
			peer := netip.MustParseAddrPort("192.0.2.8:1234")
			conn, err := l.Dial(net.UDPAddrFromAddrPort(peer))
			if err != nil {
				t.Fatal(err)
			}
			oob := packetTestDst4(netip.MustParseAddr("198.51.100.1"), 1)
			l.deliver([]byte("first"), peer, nil, &l.more[0], oob)
			l.deliver([]byte("second"), peer, nil, &l.sock, oob)
			c := conn.(*packetConn)
			if got, pending := c.q.Len(), l.conns.Pending(); got != 2 || pending != 0 {
				t.Fatalf("Dial got %d packets, %d flows pending, want 2 packets and no new flow", got, pending)
			}
			if l.DestinationAware() || l.sock.pktinfo || l.more[0].pktinfo || c.from.Load() != nil {
				t.Fatal("listener did not fall back on both sockets")
			}
		})
	}
}

func TestPacketListenerSharedBroadcastCache(t *testing.T) {
	listen := func() *PacketListener {
		t.Helper()
		pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		l := NewPacketListener(pc)
		t.Cleanup(func() { _ = l.Close() })
		if !l.DestinationAware() {
			t.Fatal("packet information not enabled on a wildcard socket")
		}
		return l
	}
	first, second := listen(), listen()
	b := first.broadcasts
	if b == nil || second.broadcasts != b {
		t.Fatal("destination-aware listeners must share a broadcast cache")
	}
	_ = first.Close()
	select {
	case <-b.stopped:
		t.Fatal("shared worker stopped with a listener still open")
	default:
	}
	_ = second.Close()
	select {
	case <-b.stopped:
	default:
		t.Fatal("shared worker did not stop on the final listener's Close")
	}
	if third := listen(); third.broadcasts == b {
		t.Fatal("new listener acquired the stopped worker")
	}
}

func TestPacketListenerBindsDialAtLimit(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(pc, WithPacketMaxConns(1))
	t.Cleanup(func() { _ = l.Close() })
	if !l.DestinationAware() {
		t.Fatal("packet information not enabled on a wildcard socket")
	}
	if _, err := l.Dial(&net.IPAddr{IP: net.IPv4(192, 0, 2, 8)}); err == nil {
		t.Fatal("destination-aware Dial accepted a non-UDP address")
	}
	if l.conns.Len() != 0 {
		t.Fatal("invalid peer took a connection slot")
	}
	peer := netip.MustParseAddrPort("192.0.2.8:1234")
	c, err := l.Dial(net.UDPAddrFromAddrPort(peer))
	if err != nil {
		t.Fatal(err)
	}
	l.deliver([]byte("group"), peer, nil, &l.sock, packetTestDst4(netip.MustParseAddr("255.255.255.255"), 1))
	dst := netip.MustParseAddr("198.51.100.2")
	l.deliver([]byte("unicast"), peer, nil, &l.sock, packetTestDst4(dst, 1))
	if got := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr(); got != dst {
		t.Fatalf("LocalAddr = %v, want the unicast destination %v", got, dst)
	}
	if n, pending, queued := l.conns.Len(), l.conns.Pending(), c.(*packetConn).q.Len(); n != 1 || pending != 0 || queued != 1 {
		t.Fatalf("connections = %d, backlog = %d, datagrams = %d, want 1, 0, 1", n, pending, queued)
	}
}

func TestPacketListenerDialRefusesPeerWithGroupFlow(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(pc)
	t.Cleanup(func() { _ = l.Close() })
	if !l.DestinationAware() {
		t.Fatal("packet information not enabled on a wildcard socket")
	}
	peer := netip.MustParseAddrPort("192.0.2.8:1234")
	l.deliver([]byte("group"), peer, nil, &l.sock, packetTestDst4(netip.MustParseAddr("255.255.255.255"), 1))
	if _, err := l.Dial(net.UDPAddrFromAddrPort(peer)); !errors.Is(err, ErrPacketPeerConnected) {
		t.Fatalf("Dial after receiving a group datagram = %v", err)
	}
}

func TestPacketListenerWildcardDialPinsDestination(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(pc, WithPacketMaxConns(2))
	t.Cleanup(func() { _ = l.Close() })
	if !l.DestinationAware() {
		t.Fatal("packet information not enabled on a wildcard socket")
	}

	peer := netip.MustParseAddrPort("192.0.2.8:1234")
	a := netip.MustParseAddr("198.51.100.1")
	b := netip.MustParseAddr("198.51.100.2")
	addr := net.UDPAddrFromAddrPort(peer)
	c, err := l.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr(); !got.IsUnspecified() {
		t.Fatalf("LocalAddr before first datagram = %v, want wildcard", got)
	}
	l.deliver([]byte("a"), peer, nil, &l.sock, packetTestDst4(a, 1))
	key := packetFlow{peer: peerKeyOf(addr), local: packetDestination{ap: netip.AddrPortFrom(a, l.sock.port)}}
	if got, ok := l.conns.Get(key); !ok || got != c || l.conns.Len() != 1 {
		t.Fatal("binding must publish the formal flow key without counting another connection")
	}
	l.deliver([]byte("b"), peer, nil, &l.sock, packetTestDst4(b, 1))
	l.deliver([]byte("c"), peer, nil, &l.sock, packetTestDst4(a, 1))
	if pending := l.conns.Pending(); pending != 1 {
		t.Fatalf("%d pending connections, want only the second destination", pending)
	}
	other := nettest.AcceptWithin(t, l)
	for _, want := range []struct {
		c        net.Conn
		dst      netip.Addr
		payloads []string
	}{
		{c, a, []string{"a", "c"}}, {other, b, []string{"b"}},
	} {
		if got := want.c.LocalAddr().(*net.UDPAddr).AddrPort().Addr(); got != want.dst {
			t.Fatalf("LocalAddr = %v, want %v", got, want.dst)
		}
		if queued := want.c.(*packetConn).q.Len(); queued != len(want.payloads) {
			t.Fatalf("%d queued datagrams, want %d", queued, len(want.payloads))
		}
		buf := make([]byte, 8)
		for _, payload := range want.payloads {
			if n, err := want.c.Read(buf); err != nil || string(buf[:n]) != payload {
				t.Fatalf("Read = %q, %v, want %q", buf[:n], err, payload)
			}
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.conns.Get(key); ok || l.conns.Len() != 1 {
		t.Fatal("closing a bound Dial must remove its formal key and free its connection slot")
	}
	if dup, err := l.Dial(addr); !errors.Is(err, ErrPacketPeerConnected) {
		if dup != nil {
			_ = dup.Close()
		}
		t.Fatalf("Dial = %v, want ErrPacketPeerConnected for the remaining flow", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := l.Dial(addr); err != nil {
		t.Fatalf("Dial after closing both flows = %v", err)
	} else {
		_ = c.Close()
	}
}

// A received packet information message is read as its destination, on
// every platform's layout.
func TestPacketInfoRead(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.7")
	var info4 [sizeofInet4Pktinfo]byte
	a4 := v4.As4()
	copy(info4[inet4PktinfoAddr:], a4[:])
	binary.NativeEndian.PutUint32(info4[inet4PktinfoIfindex:], 3)
	v6 := netip.MustParseAddr("2001:db8::7")
	var info6 [sizeofInet6Pktinfo]byte
	a6 := v6.As16()
	copy(info6[:16], a6[:])
	binary.NativeEndian.PutUint32(info6[16:], 4)
	mapped := netip.AddrFrom16(v4.As16())
	var infoMapped [sizeofInet6Pktinfo]byte
	am := mapped.As16()
	copy(infoMapped[:16], am[:])
	for _, tc := range []struct {
		want    netip.Addr
		name    string
		oob     []byte
		ifindex uint32
	}{
		{oob: putCmsg(syscall.IPPROTO_IP, ipPktinfoRecv, info4[:]), name: "ipv4", want: v4, ifindex: 3},
		{oob: putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, info6[:]), name: "ipv6", want: v6, ifindex: 4},
		{oob: putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, infoMapped[:]), name: "ipv4-mapped", want: v4},
		{oob: append(putCmsg(syscall.IPPROTO_IP, 999, []byte{1, 2, 3}), putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, info6[:])...), name: "after another message", want: v6, ifindex: 4},
	} {
		got, ifindex := packetDst(tc.oob)
		if got != tc.want || ifindex != tc.ifindex {
			t.Errorf("%s: read %v ifindex %d, want %v %d", tc.name, got, ifindex, tc.want, tc.ifindex)
		}
	}
	if got, _ := packetDst(nil); got.IsValid() {
		t.Errorf("no message: read %v", got)
	}
	short := putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, info6[:])
	if got, _ := packetDst(short[:len(short)-8]); got.IsValid() {
		t.Errorf("truncated message: read %v", got)
	}
}

// The message that a reply carries names its source where the platform
// reads it: IPv4 sources in an IPv4 message, IPv6 ones with the interface
// of a link-local address.
func TestPacketInfoSource(t *testing.T) {
	hl := cmsgHdrLen()
	v4 := netip.MustParseAddr("192.0.2.7")
	oob := sourceOOB(v4, 5)
	h := readCmsghdr(oob)
	a4 := v4.As4()
	if h.Level != syscall.IPPROTO_IP || h.Type != ipPktinfoSend || int(h.Len) != hl+sizeofInet4Pktinfo ||
		!bytes.Equal(oob[hl+inet4PktinfoSrc:hl+inet4PktinfoSrc+4], a4[:]) {
		t.Errorf("ipv4 source: header %+v, message % x", h, oob)
	}
	ll := netip.MustParseAddr("fe80::7")
	oob = sourceOOB(ll, 5)
	if got, ifindex := packetDst(oob); got != ll || ifindex != 5 {
		t.Errorf("link-local source: read back %v ifindex %d", got, ifindex)
	}
	g := netip.MustParseAddr("2001:db8::7")
	oob = sourceOOB(g, 5)
	if got, ifindex := packetDst(oob); got != g || ifindex != 0 {
		t.Errorf("global source: read back %v ifindex %d", got, ifindex)
	}
}
