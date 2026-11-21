package memnet

import "net"

// LoopbackUDP returns a UDP socket on an ephemeral 127.0.0.1 port, for a
// test's client. A socket bound to the dual-stack wildcard instead may get,
// on some systems, a port that another socket holds for the IPv4 wildcard;
// replies to 127.0.0.1 on that port then reach the other socket. An
// address-specific IPv4 bind never shares a port with such a socket.
func LoopbackUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}
