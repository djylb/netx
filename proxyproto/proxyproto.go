// Package proxyproto builds and parses PROXY protocol v1 and v2 headers, as
// specified by HAProxy, which carry the original client and destination
// addresses of a proxied connection to the backend, and provides a Listener
// that reports those addresses for the connections it accepts. The Listener
// serves streams and UDP flows whose first datagram carries the header.
//
// Parsing is lenient towards non-standard senders wherever that cannot change
// who a connection is attributed to: version 1 lines may end in a bare LF,
// use runs of spaces, any letter case, UDP4 and UDP6 tokens, address families
// that differ from the token, and padded ports; version 2 headers may carry
// any version nibble. Unknown commands, protocols and families, short address
// blocks and truncated TLVs make the connection's own addresses, or the whole
// TLVs, apply instead of failing. The package depends only on the standard
// library.
package proxyproto

import (
	"net"
	"net/netip"
)

// Version selects the PROXY protocol header version.
type Version int

const (
	// None sends no header.
	None Version = iota
	// V1 is the text header format.
	V1
	// V2 is the binary header format.
	V2
)

// V1Header returns a PROXY protocol v1 header for client and target addresses.
//
// Both addresses must be *net.TCPAddr or both *net.UDPAddr. v1 has no UDP
// token, so UDP pairs are emitted with the TCP4/TCP6 tokens (historical nps
// behavior); use v2 to signal UDP. As in HAProxy, an IPv4 and an IPv6 address
// are sent as TCP6 with the IPv4 side in its IPv4-mapped form (::ffff:a.b.c.d).
// Anything else yields "PROXY UNKNOWN\r\n".
func V1Header(clientAddr, targetAddr net.Addr) []byte {
	return appendV1(make([]byte, 0, maxV1Len), clientAddr, targetAddr)
}

// V2Header returns a PROXY protocol v2 header for client and target addresses.
//
// The address rules match V1Header, except that UDP pairs are sent as DGRAM,
// mixed families as AF_INET6, and *net.UnixAddr pairs as AF_UNIX. Unsupported
// addresses yield a LOCAL header.
func V2Header(clientAddr, targetAddr net.Addr) []byte {
	h := Header{Version: V2, Source: clientAddr, Destination: targetAddr}
	b, _ := appendV2(make([]byte, 0, v2HeadLen+2*unixPathLen), &h) // cannot fail without TLVs
	return b
}

// HeaderFromConn builds a PROXY protocol header from a connection's remote
// and local addresses, as HeaderFromAddrs does.
func HeaderFromConn(c net.Conn, version Version) []byte {
	if c == nil || version == None {
		return nil
	}
	return HeaderFromAddrs(c.RemoteAddr(), c.LocalAddr(), version)
}

// HeaderFromAddrs builds a PROXY protocol header from explicit addresses.
//
// A target that is nil, unspecified or not of the client's address type is sent
// as the zero address of the client's family (0.0.0.0 or ::). Otherwise the
// rules of V1Header and V2Header apply. It returns
// nil for None and for unknown versions.
func HeaderFromAddrs(clientAddr, targetAddr net.Addr, version Version) []byte {
	if version == None {
		return nil
	}

	targetAddr = normalizeTarget(clientAddr, targetAddr)

	switch version {
	case V2:
		return V2Header(clientAddr, targetAddr)
	case V1:
		return V1Header(clientAddr, targetAddr)
	default:
		return nil
	}
}

func normalizeTarget(src, dst net.Addr) net.Addr {
	switch s := src.(type) {
	case *net.TCPAddr:
		if s == nil {
			return dst
		}
		d := cloneTCPAddr(dst)
		if d == nil {
			d = &net.TCPAddr{Port: 0}
		}
		d.IP = normalizeTargetIP(s.IP, d.IP)
		return d
	case *net.UDPAddr:
		if s == nil {
			return dst
		}
		d := cloneUDPAddr(dst)
		if d == nil {
			d = &net.UDPAddr{Port: 0}
		}
		d.IP = normalizeTargetIP(s.IP, d.IP)
		return d
	default:
		return dst
	}
}

func cloneTCPAddr(addr net.Addr) *net.TCPAddr {
	tcpAddr, _ := addr.(*net.TCPAddr)
	if tcpAddr == nil {
		return nil
	}
	return &net.TCPAddr{
		IP:   append(net.IP(nil), tcpAddr.IP...),
		Port: tcpAddr.Port,
		Zone: tcpAddr.Zone,
	}
}

func cloneUDPAddr(addr net.Addr) *net.UDPAddr {
	udpAddr, _ := addr.(*net.UDPAddr)
	if udpAddr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), udpAddr.IP...),
		Port: udpAddr.Port,
		Zone: udpAddr.Zone,
	}
}

func normalizeTargetIP(srcIP, dstIP net.IP) net.IP {
	if dstIP != nil && !dstIP.IsUnspecified() {
		return dstIP
	}
	if srcIP.To4() != nil {
		return net.IPv4zero
	}
	return net.IPv6zero
}

type proxyAddrMeta struct {
	v1Protocol string
	srcIP      net.IP
	dstIP      net.IP
	addrBytes  uint16
	srcPort    uint16
	dstPort    uint16
	famProto   byte
}

func buildProxyAddrMeta(clientAddr, targetAddr net.Addr) (proxyAddrMeta, bool) {
	switch c := clientAddr.(type) {
	case *net.TCPAddr:
		t, ok := targetAddr.(*net.TCPAddr)
		if !ok || c == nil || t == nil {
			return proxyAddrMeta{}, false
		}
		return proxyAddrMetaFromIPs(c.IP, t.IP, c.Port, t.Port, true)
	case *net.UDPAddr:
		u, ok := targetAddr.(*net.UDPAddr)
		if !ok || c == nil || u == nil {
			return proxyAddrMeta{}, false
		}
		return proxyAddrMetaFromIPs(c.IP, u.IP, c.Port, u.Port, false)
	default:
		return proxyAddrMeta{}, false
	}
}

func proxyAddrMetaFromIPs(srcIP, dstIP net.IP, srcPort, dstPort int, tcp bool) (proxyAddrMeta, bool) {
	if !validTCPPort(srcPort) || !validTCPPort(dstPort) {
		return proxyAddrMeta{}, false
	}
	// As in HAProxy, the header is IPv4 only when both sides are IPv4.
	// Otherwise both IPs are sent as 16 bytes, and To16 turns an IPv4 side
	// into its IPv4-mapped form ::ffff:a.b.c.d.
	src4, dst4 := srcIP.To4(), dstIP.To4()
	ipv4 := src4 != nil && dst4 != nil
	if ipv4 {
		srcIP, dstIP = src4, dst4
	} else {
		srcIP, dstIP = srcIP.To16(), dstIP.To16()
		if srcIP == nil || dstIP == nil {
			return proxyAddrMeta{}, false
		}
	}
	meta := proxyAddrMeta{
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: uint16(srcPort),
		dstPort: uint16(dstPort),
	}
	if tcp {
		if ipv4 {
			meta.v1Protocol = "TCP4"
			meta.famProto = 0x11
			meta.addrBytes = 12
		} else {
			meta.v1Protocol = "TCP6"
			meta.famProto = 0x21
			meta.addrBytes = 36
		}
		return meta, true
	}

	if ipv4 {
		meta.v1Protocol = "TCP4"
		meta.famProto = 0x12
		meta.addrBytes = 12
	} else {
		meta.v1Protocol = "TCP6"
		meta.famProto = 0x22
		meta.addrBytes = 36
	}
	return meta, true
}

func validTCPPort(port int) bool {
	return port >= 0 && port <= 65535
}

// appendIPText formats ip in the family given by its length, so a 16-byte
// IPv4-mapped address prints as ::ffff:a.b.c.d.
func appendIPText(dst []byte, ip net.IP) []byte {
	switch len(ip) {
	case net.IPv4len:
		return netip.AddrFrom4([4]byte(ip)).AppendTo(dst)
	case net.IPv6len:
		return netip.AddrFrom16([16]byte(ip)).AppendTo(dst)
	default:
		return dst
	}
}
