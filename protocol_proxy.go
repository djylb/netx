package netx

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
)

// ProxyProtocolVersion selects the Proxy Protocol header version.
type ProxyProtocolVersion int

const (
	// ProxyProtocolNone sends no header.
	ProxyProtocolNone ProxyProtocolVersion = iota
	// ProxyProtocolV1 is the text header format.
	ProxyProtocolV1
	// ProxyProtocolV2 is the binary header format.
	ProxyProtocolV2
)

// ProxyProtocolV1Header returns a Proxy Protocol v1 header for client and target addresses.
//
// Both addresses must be *net.TCPAddr or both *net.UDPAddr. v1 has no UDP
// token, so UDP pairs are emitted with the TCP4/TCP6 tokens (historical nps
// behavior); use v2 to signal UDP. As in HAProxy, an IPv4 and an IPv6 address
// are sent as TCP6 with the IPv4 side in its IPv4-mapped form (::ffff:a.b.c.d).
// Anything else yields "PROXY UNKNOWN\r\n".
func ProxyProtocolV1Header(clientAddr, targetAddr net.Addr) []byte {
	meta, ok := buildProxyAddrMeta(clientAddr, targetAddr)
	if !ok {
		return []byte("PROXY UNKNOWN\r\n")
	}
	header := make([]byte, 0, proxyProtocolV1HeaderLen(meta))
	header = append(header, "PROXY "...)
	header = append(header, meta.v1Protocol...)
	header = append(header, ' ')
	header = appendIPText(header, meta.srcIP)
	header = append(header, ' ')
	header = appendIPText(header, meta.dstIP)
	header = append(header, ' ')
	header = strconv.AppendUint(header, uint64(meta.srcPort), 10)
	header = append(header, ' ')
	header = strconv.AppendUint(header, uint64(meta.dstPort), 10)
	header = append(header, '\r', '\n')
	return header
}

// ProxyProtocolV2Header returns a Proxy Protocol v2 header for client and target addresses.
//
// The address rules match ProxyProtocolV1Header, except that UDP pairs are
// sent as DGRAM and mixed families as AF_INET6. Unsupported addresses yield a
// LOCAL header.
func ProxyProtocolV2Header(clientAddr, targetAddr net.Addr) []byte {
	const sig = "\r\n\r\n\000\r\nQUIT\n"
	meta, ok := buildProxyAddrMeta(clientAddr, targetAddr)
	if !ok {
		header := make([]byte, 16)
		copy(header[:12], sig)
		header[12] = 0x20
		return header
	}

	header := make([]byte, 16+meta.addrBytes)
	copy(header[:12], sig)
	header[12] = 0x21
	header[13] = meta.famProto
	binary.BigEndian.PutUint16(header[14:16], meta.addrBytes)

	if meta.addrBytes == 12 {
		copy(header[16:20], meta.srcIP.To4())
		copy(header[20:24], meta.dstIP.To4())
		binary.BigEndian.PutUint16(header[24:26], meta.srcPort)
		binary.BigEndian.PutUint16(header[26:28], meta.dstPort)
	} else {
		copy(header[16:32], meta.srcIP.To16())
		copy(header[32:48], meta.dstIP.To16())
		binary.BigEndian.PutUint16(header[48:50], meta.srcPort)
		binary.BigEndian.PutUint16(header[50:52], meta.dstPort)
	}
	return header
}

// ProxyProtocolHeader builds a Proxy Protocol header from a connection's remote
// and local addresses, as ProxyProtocolHeaderFromAddrs does.
func ProxyProtocolHeader(c net.Conn, version ProxyProtocolVersion) []byte {
	if c == nil || version == ProxyProtocolNone {
		return nil
	}
	return ProxyProtocolHeaderFromAddrs(c.RemoteAddr(), c.LocalAddr(), version)
}

// ProxyProtocolHeaderFromAddrs builds a Proxy Protocol header from explicit addresses.
//
// A target that is nil, unspecified or not of the client's address type is sent
// as the zero address of the client's family (0.0.0.0 or ::). Otherwise the
// rules of ProxyProtocolV1Header and ProxyProtocolV2Header apply. It returns
// nil for ProxyProtocolNone and for unknown versions.
func ProxyProtocolHeaderFromAddrs(clientAddr, targetAddr net.Addr, version ProxyProtocolVersion) []byte {
	if version == ProxyProtocolNone {
		return nil
	}

	targetAddr = normalizeTarget(clientAddr, targetAddr)

	switch version {
	case ProxyProtocolV2:
		return ProxyProtocolV2Header(clientAddr, targetAddr)
	case ProxyProtocolV1:
		return ProxyProtocolV1Header(clientAddr, targetAddr)
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
	famProto   byte
	addrBytes  uint16
	srcIP      net.IP
	dstIP      net.IP
	srcPort    uint16
	dstPort    uint16
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

func proxyProtocolV1HeaderLen(meta proxyAddrMeta) int {
	return len("PROXY ") + len(meta.v1Protocol) + 1 +
		maxIPTextLen(meta.srcIP) + 1 +
		maxIPTextLen(meta.dstIP) + 1 +
		decimalLenUint16(meta.srcPort) + 1 +
		decimalLenUint16(meta.dstPort) + len("\r\n")
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

func maxIPTextLen(ip net.IP) int {
	if len(ip) == net.IPv4len {
		return len("255.255.255.255")
	}
	return len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
}

func decimalLenUint16(v uint16) int {
	switch {
	case v >= 10000:
		return 5
	case v >= 1000:
		return 4
	case v >= 100:
		return 3
	case v >= 10:
		return 2
	default:
		return 1
	}
}
