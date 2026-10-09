package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
)

// Version4 is the version byte of SOCKS4 and SOCKS4a requests.
const Version4 = 4

// SOCKS4 replies. They share the Reply type with SOCKS5, whose codes they do
// not overlap.
const (
	Reply4Granted         Reply = 90
	Reply4Rejected        Reply = 91
	Reply4IdentdUnreached Reply = 92
	Reply4IdentdMismatch  Reply = 93
)

// Limits of the NUL-terminated strings of a SOCKS4 request, terminator
// excluded.
const (
	maxUserID4 = 1023
	maxHost4   = 255
)

// ReadRequest4 reads a SOCKS4 or SOCKS4a request and returns its command,
// destination and user ID. A SOCKS4a destination, signaled by an address of
// 0.0.0.x with x not zero, is returned by name, or by IP address when the
// name is an IP literal, as DecodeAddr does. The user ID is not
// authentication: SOCKS4 has none.
func ReadRequest4(r io.Reader) (cmd Command, dst Addr, userID string, err error) {
	var hdr [8]byte // version, command, port, IPv4 address
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, Addr{}, "", err
	}
	if hdr[0] != Version4 {
		return 0, Addr{}, "", ErrVersion
	}
	if userID, err = readNULString(r, maxUserID4); err != nil {
		return 0, Addr{}, "", err
	}
	if socks4aMarker([4]byte(hdr[4:8])) {
		name, err := readNULString(r, maxHost4)
		if err != nil {
			return 0, Addr{}, "", err
		}
		if name == "" {
			return 0, Addr{}, "", ErrMalformed
		}
		dst = nameAddr(name)
	} else {
		dst.IP = netip.AddrFrom4([4]byte(hdr[4:8]))
	}
	dst.Port = binary.BigEndian.Uint16(hdr[2:4])
	return Command(hdr[1]), dst, userID, nil
}

// WriteRequest4 writes a SOCKS4 request for cmd to dst, or a SOCKS4a request
// when dst is a domain name or an address of 0.0.0.x, which SOCKS4 reserves
// for SOCKS4a, with x not zero. It returns an error wrapping ErrAddrType for an
// IPv6 destination and ErrMalformed for a user ID or name that is too long or
// contains a NUL byte.
func WriteRequest4(w io.Writer, cmd Command, dst Addr, userID string) error {
	msg := make([]byte, 8, 8+len(userID)+1+len(dst.Name)+1)
	msg[0], msg[1] = Version4, byte(cmd)
	binary.BigEndian.PutUint16(msg[2:4], dst.Port)
	if !validNULString(userID, maxUserID4) {
		return ErrMalformed
	}
	var name string
	switch ip := dst.IP.Unmap(); {
	case ip.Is4() && !socks4aMarker(ip.As4()):
		v4 := ip.As4()
		copy(msg[4:], v4[:])
	case ip.Is4():
		msg[7] = 1 // 0.0.0.x itself would announce a name
		name = ip.String()
	case ip.IsValid():
		return fmt.Errorf("%w: SOCKS4 cannot carry IPv6 address %v", ErrAddrType, ip)
	default:
		if dst.Name == "" || !validNULString(dst.Name, maxHost4) {
			return ErrMalformed
		}
		msg[7] = 1 // 0.0.0.1 asks the server to resolve the name
		name = dst.Name
	}
	msg = append(append(msg, userID...), 0)
	if name != "" {
		msg = append(append(msg, name...), 0)
	}
	return write(w, msg)
}

// WriteReply4 writes a SOCKS4 reply carrying the bound address, which is sent
// as 0.0.0.0 unless it is IPv4. rep may be a SOCKS4 reply or, for servers that
// share code with SOCKS5, a SOCKS5 one: ReplySucceeded is sent as
// Reply4Granted and other SOCKS5 replies as Reply4Rejected.
func WriteReply4(w io.Writer, rep Reply, bound Addr) error {
	switch {
	case rep == ReplySucceeded:
		rep = Reply4Granted
	case rep < Reply4Granted:
		rep = Reply4Rejected
	}
	msg := [8]byte{0, byte(rep)}
	binary.BigEndian.PutUint16(msg[2:4], bound.Port)
	if ip := bound.IP.Unmap(); ip.Is4() {
		v4 := ip.As4()
		copy(msg[4:], v4[:])
	}
	return write(w, msg[:])
}

// ReadReply4 reads a SOCKS4 reply and returns the bound address. A reply
// other than Reply4Granted is returned as a *ReplyError. The version byte,
// which should be 0, is not checked, since some servers send 4.
func ReadReply4(r io.Reader) (Addr, error) {
	var msg [8]byte
	if _, err := io.ReadFull(r, msg[:]); err != nil {
		return Addr{}, err
	}
	bound := Addr{IP: netip.AddrFrom4([4]byte(msg[4:8])), Port: binary.BigEndian.Uint16(msg[2:4])}
	if rep := Reply(msg[1]); rep != Reply4Granted {
		return bound, &ReplyError{Reply: rep}
	}
	return bound, nil
}

// socks4aMarker reports whether a SOCKS4 destination address of 0.0.0.x, with
// x not zero, announces a SOCKS4a name.
func socks4aMarker(v4 [4]byte) bool {
	return v4[0] == 0 && v4[1] == 0 && v4[2] == 0 && v4[3] != 0
}

// readNULString reads a NUL-terminated string of at most limit bytes before
// the terminator. It reads one byte at a time so that nothing after the
// terminator is consumed.
func readNULString(r io.Reader, limit int) (string, error) {
	buf := make([]byte, limit+1)
	for i := range buf {
		if _, err := io.ReadFull(r, buf[i:i+1]); err != nil {
			return "", unexpectedEOF(err)
		}
		if buf[i] == 0 {
			return string(buf[:i]), nil
		}
	}
	return "", ErrMalformed
}

func validNULString(s string, limit int) bool {
	if len(s) > limit {
		return false
	}
	for i := range len(s) {
		if s[i] == 0 {
			return false
		}
	}
	return true
}
