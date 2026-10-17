//go:build linux || freebsd || darwin

package transparent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// errNotRedirected marks a lookup that found no translation for a
// connection, which reached the address it was sent to.
var errNotRedirected = errors.New("not a translated connection")

// originalDestination asks lookupRedirect for the translation of conn, the
// accepted socket. Without one the destination is conn's local address.
func originalDestination(conn net.Conn) (netip.AddrPort, bool, error) {
	raw, err := socketOf(conn)
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("transparent: original destination: %w", err)
	}
	local, err := destinationFromLocalAddr(conn.LocalAddr())
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("transparent: original destination: %w", err)
	}
	dst, err := lookupRedirect(conn, raw, local)
	if errors.Is(err, errNotRedirected) {
		dst = local
	} else if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("transparent: original destination: %w", err)
	}
	redirected, err := isRedirected(dst, local, func(ip netip.Addr) (bool, error) {
		return isLocalAddr(raw, ip)
	})
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("transparent: original destination: is %v local: %w", dst.Addr(), err)
	}
	return dst, redirected, nil
}

// isRedirected reports whether a connection or datagram that arrived at
// local, originally addressed to dst, was redirected. A destination on
// another port was. One on the same port, whether delivered as addressed, as
// by TPROXY or IP_BINDANY, or translated to local, as by a NAT that maps an
// address of this host to the listener, was redirected unless isLocal finds
// it is an address of this host: forwarding it there would reach local again.
func isRedirected(dst, local netip.AddrPort, isLocal func(netip.Addr) (bool, error)) (bool, error) {
	if dst.Port() != local.Port() {
		return true, nil
	}
	ok, err := isLocal(dst.Addr())
	if err != nil {
		return false, err
	}
	return !ok, nil
}

// socketOf returns the socket beneath conn, an innermost connection, and
// fails for one that is closed or is not a socket: its addresses, which a
// wrapper may have replaced, cannot be trusted as the socket's.
func socketOf(conn net.Conn) (syscall.RawConn, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("cannot inspect the socket beneath %T", conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	if err := raw.Control(func(uintptr) {}); err != nil {
		return nil, err
	}
	return raw, nil
}
