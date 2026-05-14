package netx

import (
	"encoding/binary"
	"net"
	"strconv"
)

// ParseAddr converts host:port text into a TCP address, defaulting bad ports to 0.
func ParseAddr(addr string) net.Addr {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return &net.TCPAddr{IP: net.ParseIP(addr), Port: 0}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 0
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

// BuildProxyProtocolV1Header returns a Proxy Protocol v1 header for client and target addresses.
func BuildProxyProtocolV1Header(clientAddr, targetAddr net.Addr) []byte {
	meta, ok := buildProxyAddrMeta(clientAddr, targetAddr)
	if !ok {
		return []byte("PROXY UNKNOWN\r\n")
	}

	header := "PROXY " + meta.v1Protocol + " " + meta.clientIP + " " + meta.targetIP + " " +
		strconv.Itoa(int(meta.srcPort)) + " " + strconv.Itoa(int(meta.dstPort)) + "\r\n"
	return []byte(header)
}

// BuildProxyProtocolV2Header returns a Proxy Protocol v2 header for client and target addresses.
func BuildProxyProtocolV2Header(clientAddr, targetAddr net.Addr) []byte {
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

// BuildProxyProtocolHeader builds a Proxy Protocol header from a connection's remote and local addresses.
func BuildProxyProtocolHeader(c net.Conn, proxyProtocol int) []byte {
	if c == nil || proxyProtocol == 0 {
		return nil
	}
	return BuildProxyProtocolHeaderByAddr(c.RemoteAddr(), c.LocalAddr(), proxyProtocol)
}

// BuildProxyProtocolHeaderByAddr builds a Proxy Protocol header from explicit addresses.
func BuildProxyProtocolHeaderByAddr(clientAddr, targetAddr net.Addr, proxyProtocol int) []byte {
	if proxyProtocol == 0 {
		return nil
	}

	targetAddr = normalizeTarget(clientAddr, targetAddr)

	switch proxyProtocol {
	case 2:
		return BuildProxyProtocolV2Header(clientAddr, targetAddr)
	case 1:
		return BuildProxyProtocolV1Header(clientAddr, targetAddr)
	default:
		return nil
	}
}

func normalizeTarget(src, dst net.Addr) net.Addr {
	switch s := src.(type) {
	case *net.TCPAddr:
		d, _ := dst.(*net.TCPAddr)
		if d == nil {
			d = &net.TCPAddr{Port: 0}
		}
		d.IP = normalizeTargetIP(s.IP, d.IP)
		return d
	case *net.UDPAddr:
		d, _ := dst.(*net.UDPAddr)
		if d == nil {
			d = &net.UDPAddr{Port: 0}
		}
		d.IP = normalizeTargetIP(s.IP, d.IP)
		return d
	default:
		return dst
	}
}

func normalizeTargetIP(srcIP, dstIP net.IP) net.IP {
	srcIsV4 := srcIP.To4() != nil
	dstIsV4 := dstIP != nil && dstIP.To4() != nil

	switch {
	case srcIsV4 && !dstIsV4:
		return net.IPv4zero
	case !srcIsV4 && dstIsV4:
		return ipv4MappedIPv6(dstIP)
	case dstIP == nil || dstIP.IsUnspecified():
		if srcIsV4 {
			return net.IPv4zero
		}
		return net.IPv6zero
	default:
		return dstIP
	}
}

func ipv4MappedIPv6(ip net.IP) net.IP {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	mapped := make(net.IP, net.IPv6len)
	copy(mapped[12:], v4)
	return mapped
}

type proxyAddrMeta struct {
	v1Protocol string
	famProto   byte
	addrBytes  uint16
	srcIP      net.IP
	dstIP      net.IP
	clientIP   string
	targetIP   string
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
		return proxyAddrMetaFromIPs(c.IP, t.IP, uint16(c.Port), uint16(t.Port), true)
	case *net.UDPAddr:
		u, ok := targetAddr.(*net.UDPAddr)
		if !ok || c == nil || u == nil {
			return proxyAddrMeta{}, false
		}
		return proxyAddrMetaFromIPs(c.IP, u.IP, uint16(c.Port), uint16(u.Port), false)
	default:
		return proxyAddrMeta{}, false
	}
}

func proxyAddrMetaFromIPs(srcIP, dstIP net.IP, srcPort, dstPort uint16, tcp bool) (proxyAddrMeta, bool) {
	srcIsV4 := srcIP.To4() != nil
	dstIsV4 := dstIP.To4() != nil
	if srcIsV4 != dstIsV4 {
		return proxyAddrMeta{}, false
	}
	if !srcIsV4 && (srcIP.To16() == nil || dstIP.To16() == nil) {
		return proxyAddrMeta{}, false
	}
	meta := proxyAddrMeta{
		srcIP:    srcIP,
		dstIP:    dstIP,
		clientIP: srcIP.String(),
		targetIP: dstIP.String(),
		srcPort:  srcPort,
		dstPort:  dstPort,
	}
	if tcp {
		if srcIsV4 {
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

	if srcIsV4 {
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
