package netx

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// mmsghdr is the struct mmsghdr of recvmmsg.
type mmsghdr struct {
	hdr syscall.Msghdr
	n   uint32
}

// batchReader reads up to len(hdrs) datagrams of a UDP socket with one
// recvmmsg call.
type batchReader struct {
	conn  *net.UDPConn
	raw   syscall.RawConn
	fn    func(fd uintptr) bool
	err   syscall.Errno
	hdrs  []mmsghdr
	iovs  []syscall.Iovec
	names []syscall.RawSockaddrAny
	bufs  [][]byte
	n     int
}

// newBatchReader returns a reader of up to n datagrams of size bytes each
// from c, or nil when n is below two or c is nil.
func newBatchReader(c *net.UDPConn, n, size int) *batchReader {
	if c == nil || n < 2 {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return nil
	}
	b := &batchReader{conn: c, raw: raw, hdrs: make([]mmsghdr, n), iovs: make([]syscall.Iovec, n),
		names: make([]syscall.RawSockaddrAny, n), bufs: make([][]byte, n)}
	for i := range n {
		b.bufs[i] = make([]byte, size)
		b.iovs[i].Base = &b.bufs[i][0]
		b.iovs[i].SetLen(size)
		h := &b.hdrs[i].hdr
		h.Name = (*byte)(unsafe.Pointer(&b.names[i]))
		h.Iov = &b.iovs[i]
		h.Iovlen = 1
	}
	b.fn = func(fd uintptr) bool {
		for i := range b.hdrs {
			b.hdrs[i].hdr.Namelen = syscall.SizeofSockaddrAny
			b.hdrs[i].hdr.Flags = 0
			b.hdrs[i].n = 0
		}
		for {
			r, _, errno := syscall.Syscall6(syscall.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&b.hdrs[0])),
				uintptr(len(b.hdrs)), 0, 0, 0)
			switch errno {
			case 0:
				b.n, b.err = int(r), 0
				return true
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				return false
			default:
				b.n, b.err = 0, errno
				return true
			}
		}
	}
	return b
}

// read reads the next datagrams, waiting for one, and returns how many.
func (b *batchReader) read() (int, error) {
	if err := b.raw.Read(b.fn); err != nil {
		return 0, rawOpError(err, "read")
	}
	if b.err != 0 {
		return 0, &net.OpError{Op: "read", Net: b.conn.LocalAddr().Network(), Source: b.conn.LocalAddr(),
			Err: os.NewSyscallError("recvmmsg", b.err)}
	}
	return b.n, nil
}

// datagram returns the i-th datagram of the last read, valid until the next
// one, and its source.
func (b *batchReader) datagram(i int) ([]byte, netip.AddrPort) {
	p := b.bufs[i][:min(int(b.hdrs[i].n), len(b.bufs[i]))]
	name := &b.names[i]
	switch name.Addr.Family {
	case syscall.AF_INET:
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(name))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
		return p, netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port)
	case syscall.AF_INET6:
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(name))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
		return p, netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), port)
	}
	return p, netip.AddrPort{}
}
