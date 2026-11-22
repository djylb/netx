package udpflow

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
)

// ErrReusePortUnsupported is returned by ListenUDPReusePort for more than one
// socket where the system does not spread datagrams over sockets that share
// a port.
var ErrReusePortUnsupported = errors.New("udpflow: SO_REUSEPORT load balancing is not supported on this system")

// ListenUDPReusePort opens n UDP sockets on address with SO_REUSEPORT, among
// which the kernel spreads the datagrams by their source, for a
// PacketListener that reads them with WithPacketConns. A port of 0 is chosen
// by the first socket and shared by the rest. lc, nil meaning a zero
// net.ListenConfig, may set other socket options with its Control. A
// non-positive n opens one socket without the option. More than one is
// supported on Linux and Android; elsewhere it returns
// ErrReusePortUnsupported. A network other than "udp", "udp4", or "udp6"
// returns net.UnknownNetworkError.
func ListenUDPReusePort(ctx context.Context, lc *net.ListenConfig, network, address string, n int) ([]*net.UDPConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, net.UnknownNetworkError(network)
	}
	var cfg net.ListenConfig
	if lc != nil {
		cfg = *lc
	}
	if n <= 1 {
		pc, err := cfg.ListenPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return []*net.UDPConn{pc.(*net.UDPConn)}, nil
	}
	if err := reusePortSupport(); err != nil {
		return nil, err
	}
	control := cfg.Control
	cfg.Control = func(network, address string, c syscall.RawConn) error {
		if control != nil {
			if err := control(network, address, c); err != nil {
				return err
			}
		}
		return setReusePort(c)
	}
	conns := make([]*net.UDPConn, 0, n)
	fail := func(err error) ([]*net.UDPConn, error) {
		for _, c := range conns {
			_ = c.Close()
		}
		return nil, err
	}
	for range n {
		pc, err := cfg.ListenPacket(ctx, network, address)
		if err != nil {
			return fail(err)
		}
		c := pc.(*net.UDPConn)
		conns = append(conns, c)
		if len(conns) == 1 {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fail(err)
			}
			address = net.JoinHostPort(host, strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port))
		}
	}
	return conns, nil
}
