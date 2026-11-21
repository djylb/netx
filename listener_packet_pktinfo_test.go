package netx

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"
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
	if !v6 && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
		dsts = append(dsts, netip.MustParseAddr("127.0.0.2")) // all of 127/8 is local
	}
	addrs, err := net.InterfaceAddrs()
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
	return loop, dsts
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
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					go func() {
						defer func() { _ = c.Close() }()
						buf := make([]byte, 64)
						for {
							n, err := c.Read(buf)
							if err != nil {
								return
							}
							// echo with the address the conn reports; a
							// datagram is written whole (Windows reports 0
							// bytes for a WSASendMsg that completes at once)
							out := append(buf[:n:n], []byte(" "+c.LocalAddr().String())...)
							if w, err := c.Write(out); err == nil && w != len(out) {
								t.Errorf("Write reported %d of %d bytes", w, len(out))
							}
						}
					}()
				}
			}()
			tested := 0
			for i, dst := range dsts {
				srcs := []netip.Addr{loop}
				if runtime.GOOS == "windows" {
					// Windows routes neither from the loopback address to
					// another local one nor between every pair of local
					// addresses (virtual adapters): the peer takes the
					// first other local address that reaches dst
					srcs = nil
					for j := range len(dsts) - 1 {
						srcs = append(srcs, dsts[(i+1+j)%len(dsts)])
					}
				}
				got, from, ok := replyVia(t, srcs, netip.AddrPortFrom(dst, port))
				if runtime.GOOS == "windows" && got == nil {
					// the firewall of a virtual adapter may drop it
					t.Logf("%v: unreachable or filtered from %v", dst, srcs)
					continue
				}
				if !ok {
					t.Fatalf("%v: unreachable from %v", dst, srcs)
				}
				tested++
				if got == nil {
					t.Fatalf("%v: no reply", dst)
				}
				if from.Addr().Unmap() != dst || from.Port() != port {
					t.Errorf("reply to %v came from %v", dst, from)
				}
				if want := " " + netip.AddrPortFrom(dst, port).String(); !bytes.HasSuffix(got, []byte(want)) {
					t.Errorf("LocalAddr: %q, want suffix %q", got, want)
				}
			}
			if tested == 0 {
				t.Skip("no pair of local addresses that reach each other")
			}
		})
	}
}

// A socket bound to one address needs no packet information.
func TestPacketListenerBoundNoPktinfo(t *testing.T) {
	l := newUDPListener(t)
	if l.sock.pktinfo {
		t.Fatal("packet information enabled on a bound socket")
	}
}

// replyVia sends to dst from the first of srcs that can send to it (on
// Windows: that gets a reply) and returns the reply and its source (nil
// reply: none came); ok is false when none of srcs can send to dst.
func replyVia(t *testing.T, srcs []netip.Addr, dst netip.AddrPort) (got []byte, from netip.AddrPort, ok bool) {
	t.Helper()
	for _, src := range srcs {
		cl, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 0)))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 128)
		sent := false
		for range 5 { // a loopback datagram can be lost on a busy host
			if _, err := cl.WriteToUDPAddrPort([]byte("hi"), dst); err != nil {
				break // this source does not reach dst
			}
			sent = true
			_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
			if n, ap, err := cl.ReadFromUDPAddrPort(buf); err == nil {
				got, from = buf[:n], ap
				break
			}
		}
		_ = cl.Close()
		if sent && (got != nil || runtime.GOOS != "windows") {
			return got, from, true
		}
	}
	return nil, netip.AddrPort{}, false
}
