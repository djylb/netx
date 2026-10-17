//go:build linux

package transparent

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// controlMessage encodes one control message with the given payload.
func controlMessage(level, typ int32, data []byte) []byte {
	b := make([]byte, syscall.CmsgSpace(len(data)))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = level, typ
	h.SetLen(syscall.CmsgLen(len(data)))
	copy(b[syscall.CmsgLen(0):], data)
	return b
}

func TestOrigDstFromControl(t *testing.T) {
	sin := make([]byte, 16) // struct sockaddr_in
	binary.LittleEndian.PutUint16(sin[0:2], syscall.AF_INET)
	binary.BigEndian.PutUint16(sin[2:4], 53)
	copy(sin[4:8], []byte{203, 0, 113, 9})
	sin6 := make([]byte, 28) // struct sockaddr_in6
	binary.LittleEndian.PutUint16(sin6[0:2], syscall.AF_INET6)
	binary.BigEndian.PutUint16(sin6[2:4], 443)
	ip6 := netip.MustParseAddr("2001:db8::7").As16()
	copy(sin6[8:24], ip6[:])
	mapped := append([]byte(nil), sin6...)
	v4in6 := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	copy(mapped[8:24], v4in6[:])

	// A link-local destination carries the receiving interface's index.
	ifName, ifIndex := testInterface(t)
	linkLocal := append([]byte(nil), sin6...)
	ll := netip.MustParseAddr("fe80::7").As16()
	copy(linkLocal[8:24], ll[:])
	binary.NativeEndian.PutUint32(linkLocal[24:28], ifIndex)
	unknownIf := append([]byte(nil), linkLocal...)
	binary.NativeEndian.PutUint32(unknownIf[24:28], 0x7ffffff0)
	globalScoped := append([]byte(nil), sin6...)
	binary.NativeEndian.PutUint32(globalScoped[24:28], ifIndex)

	other := controlMessage(solIP, 8 /* IP_TTL */, []byte{64, 0, 0, 0})
	tests := []struct {
		name string
		oob  []byte
		want string
	}{
		{"ipv4", append(other, controlMessage(solIP, ipRecvOrigDstAddr, sin)...), "203.0.113.9:53"},
		{"ipv6", controlMessage(solIPv6, ipv6RecvOrigDstAddr, sin6), "[2001:db8::7]:443"},
		{"ipv4-mapped", controlMessage(solIPv6, ipv6RecvOrigDstAddr, mapped), "192.0.2.1:443"},
		{"link-local", controlMessage(solIPv6, ipv6RecvOrigDstAddr, linkLocal), "[fe80::7%" + ifName + "]:443"},
		{"link-local unknown interface", controlMessage(solIPv6, ipv6RecvOrigDstAddr, unknownIf), "[fe80::7%2147483632]:443"},
		{"global with scope", controlMessage(solIPv6, ipv6RecvOrigDstAddr, globalScoped), "[2001:db8::7]:443"},
		{"missing", other, ""},
		{"short", controlMessage(solIP, ipRecvOrigDstAddr, sin[:6]), ""},
		{"garbage", []byte{1, 2, 3}, ""},
		{"unaligned", append([]byte{0}, append(other, controlMessage(solIP, ipRecvOrigDstAddr, sin)...)...)[1:], "203.0.113.9:53"},
		{"length past the buffer", controlMessage(solIP, ipRecvOrigDstAddr, sin)[:cmsgHeaderLen+8], ""},
	}
	for _, tt := range tests {
		got, ok := origDstFromControl(tt.oob)
		if (tt.want == "") == ok || ok && got.String() != tt.want {
			t.Errorf("%s: origDstFromControl() = %v, %v; want %q", tt.name, got, ok, tt.want)
		}
	}
}

// Reading a datagram's original destination does not allocate.
func TestReadFromUDPDoesNotAllocate(t *testing.T) {
	sin := make([]byte, 16)
	binary.LittleEndian.PutUint16(sin[0:2], syscall.AF_INET)
	oob := append(controlMessage(solIP, 8, []byte{64, 0, 0, 0}), controlMessage(solIP, ipRecvOrigDstAddr, sin)...)
	if n := testing.AllocsPerRun(100, func() { _, _ = origDstFromControl(oob) }); n != 0 {
		t.Fatalf("origDstFromControl() = %v allocations, want 0", n)
	}

	ln, err := ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	skipWithoutPrivilege(t, err)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer func() { _ = ln.Close() }()
	client, err := net.DialUDP("udp4", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	// AllocsPerRun reads one datagram more than the runs it counts.
	const runs = 50
	for range runs + 1 {
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	_ = ln.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n := testing.AllocsPerRun(runs, func() {
		if _, _, err := ReadFromUDP(ln, buf); err != nil {
			t.Fatal(err)
		}
	})
	if n != 0 {
		t.Fatalf("ReadFromUDP() = %v allocations per datagram, want 0", n)
	}
}

func skipWithoutPrivilege(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("transparent sockets need CAP_NET_ADMIN: %v", err)
	}
}

func TestListenPacketAndDialUDP(t *testing.T) {
	ln, err := ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	skipWithoutPrivilege(t, err)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer func() { _ = ln.Close() }()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.WriteToUDP([]byte("query"), ln.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, info, err := ReadFromUDP(ln, buf)
	if err != nil || string(buf[:n]) != "query" || info.Redirected {
		t.Fatalf("ReadFromUDP() = %q, redirected %v, %v; want query, false", buf[:n], info.Redirected, err)
	}
	if info.Src.String() != client.LocalAddr().String() || info.Dst.String() != ln.LocalAddr().String() {
		t.Fatalf("ReadFromUDP() src %v dst %v, want %v and %v", info.Src, info.Dst, client.LocalAddr(), ln.LocalAddr())
	}
	src := info.Src

	// Answer from an address that is not local, as for a redirected datagram.
	spoofed := netip.MustParseAddrPort("198.51.100.1:5353")
	reply, err := DialUDP(context.Background(), spoofed, src)
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer func() { _ = reply.Close() }()
	// A second socket can share the local address.
	other, err := DialUDP(context.Background(), spoofed, netip.MustParseAddrPort("127.0.0.1:9"))
	if err != nil {
		t.Fatalf("second DialUDP() error = %v", err)
	}
	_ = other.Close()
	if _, err := reply.Write([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := client.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "answer" || from != spoofed {
		t.Fatalf("client got %q from %v, %v; want answer from %v", buf[:n], from, err, spoofed)
	}
}

// Other control messages the socket asks for do not push the original
// destination out of the buffer.
func TestReadFromUDPWithOtherControlMessages(t *testing.T) {
	ln, err := ListenPacket(context.Background(), "udp", "0.0.0.0:0")
	skipWithoutPrivilege(t, err)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer func() { _ = ln.Close() }()
	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optErr error
	_ = raw.Control(func(fd uintptr) {
		for _, opt := range [][2]int{
			{syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS},
			{syscall.SOL_IP, syscall.IP_PKTINFO},
			{syscall.SOL_IP, syscall.IP_RECVTTL},
			{syscall.SOL_IP, syscall.IP_RECVTOS},
		} {
			if err := syscall.SetsockoptInt(int(fd), opt[0], opt[1], 1); err != nil && optErr == nil {
				optErr = err
			}
		}
	})
	if optErr != nil {
		t.Skipf("setsockopt: %v", optErr)
	}
	port := uint16(ln.LocalAddr().(*net.UDPAddr).Port)
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	// The wildcard socket asks whether 127.0.0.1 is local: it is, so the
	// datagram was sent to the socket directly.
	_, info, err := ReadFromUDP(ln, make([]byte, 16))
	if want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port); err != nil || info.Dst != want || info.Redirected {
		t.Fatalf("ReadFromUDP() dst = %v, redirected %v, %v; want %v, false", info.Dst, info.Redirected, err, want)
	}
}

func TestDatagramRedirected(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for _, tt := range []struct {
		dst, bound string
		redirected bool
	}{
		{"127.0.0.1:53", "127.0.0.1:53", false},
		{"127.0.0.1:54", "127.0.0.1:53", true},
		{"198.51.100.1:53", "127.0.0.1:53", true},
		{"127.0.0.2:53", "127.0.0.1:53", true}, // only a redirect delivers it
		{"127.0.0.1:53", "0.0.0.0:53", false},
		{"127.0.0.9:53", "0.0.0.0:53", false},
		{"198.51.100.1:53", "0.0.0.0:53", true},
		{"198.51.100.1:54", "0.0.0.0:53", true},
		// Broadcast and multicast reach the socket directly.
		{"255.255.255.255:53", "0.0.0.0:53", false},
		{"255.255.255.255:54", "0.0.0.0:53", false},
		{"224.0.0.251:5353", "0.0.0.0:53", false},
		{"[ff02::fb]:5353", "[::]:53", false},
	} {
		got, err := datagramRedirected(c, netip.MustParseAddrPort(tt.dst), netip.MustParseAddrPort(tt.bound))
		if err != nil || got != tt.redirected {
			t.Errorf("datagramRedirected(%s, bound %s) = %v, %v; want %v", tt.dst, tt.bound, got, err, tt.redirected)
		}
	}
}

// Only local answers are remembered, so that an address added later is not
// taken for another host's.
func TestIsLocalAddrCached(t *testing.T) {
	local, remote := netip.MustParseAddr("127.0.0.7"), netip.MustParseAddr("198.51.100.7")
	for range 2 {
		if got, err := isLocalAddrCached(nil, local); err != nil || !got {
			t.Fatalf("isLocalAddrCached(%v) = %v, %v; want true", local, got, err)
		}
		if got, err := isLocalAddrCached(nil, remote); err != nil || got {
			t.Fatalf("isLocalAddrCached(%v) = %v, %v; want false", remote, got, err)
		}
	}
	localAddrs.Lock()
	_, cachedLocal := localAddrs.set[localAddrKey{ip: local}]
	_, cachedRemote := localAddrs.set[localAddrKey{ip: remote}]
	localAddrs.Unlock()
	if !cachedLocal || cachedRemote {
		t.Fatalf("cached local %v remote %v; want true, false", cachedLocal, cachedRemote)
	}
}
