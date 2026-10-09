//go:build freebsd

package transparent

import (
	"io"
	"net"
	"testing"
	"time"
	"unsafe"
)

type stubFreeBSDTransparentConn struct {
	local net.Addr
}

func (c stubFreeBSDTransparentConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c stubFreeBSDTransparentConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (c stubFreeBSDTransparentConn) Close() error                     { return nil }
func (c stubFreeBSDTransparentConn) LocalAddr() net.Addr              { return c.local }
func (c stubFreeBSDTransparentConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c stubFreeBSDTransparentConn) SetDeadline(time.Time) error      { return nil }
func (c stubFreeBSDTransparentConn) SetReadDeadline(time.Time) error  { return nil }
func (c stubFreeBSDTransparentConn) SetWriteDeadline(time.Time) error { return nil }

func TestDestinationFromLocalAddrIPv4(t *testing.T) {
	addr, err := destinationFromLocalAddr(&net.TCPAddr{
		IP:   net.ParseIP("203.0.113.10"),
		Port: 8443,
	})
	if err != nil {
		t.Fatalf("destinationFromLocalAddr error = %v", err)
	}
	if addr.String() != "203.0.113.10:8443" {
		t.Fatalf("destinationFromLocalAddr = %q, want %q", addr.String(), "203.0.113.10:8443")
	}
}

func TestDestinationFromLocalAddrIPv6(t *testing.T) {
	addr, err := destinationFromLocalAddr(&net.TCPAddr{
		IP:   net.ParseIP("2001:db8::25"),
		Port: 9443,
	})
	if err != nil {
		t.Fatalf("destinationFromLocalAddr error = %v", err)
	}
	if addr.String() != "[2001:db8::25]:9443" {
		t.Fatalf("destinationFromLocalAddr = %q, want %q", addr.String(), "[2001:db8::25]:9443")
	}
}

func TestOriginalDestinationFallsBackToLocalAddrForTransparentConn(t *testing.T) {
	addr, err := OriginalDestination(stubFreeBSDTransparentConn{
		local: &net.TCPAddr{
			IP:   net.ParseIP("198.51.100.25"),
			Port: 443,
		},
	})
	if err != nil {
		t.Fatalf("OriginalDestination error = %v", err)
	}
	if addr.String() != "198.51.100.25:443" {
		t.Fatalf("OriginalDestination = %q, want %q", addr.String(), "198.51.100.25:443")
	}
}

func TestPfiocNatlookLayout(t *testing.T) {
	var nl pfiocNatlook
	if size := unsafe.Sizeof(nl); size != sizeofPfiocNatlook {
		t.Fatalf("sizeof(pfiocNatlook) = %#x, want %#x", size, sizeofPfiocNatlook)
	}
	for _, f := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "sport", got: unsafe.Offsetof(nl.Sport), want: 64},
		{name: "dport", got: unsafe.Offsetof(nl.Dport), want: 66},
		{name: "rsport", got: unsafe.Offsetof(nl.Rsport), want: 68},
		{name: "rdport", got: unsafe.Offsetof(nl.Rdport), want: 70},
		{name: "af", got: unsafe.Offsetof(nl.Af), want: 72},
		{name: "proto", got: unsafe.Offsetof(nl.Proto), want: 73},
		{name: "direction", got: unsafe.Offsetof(nl.Direction), want: 74},
	} {
		if f.got != f.want {
			t.Fatalf("offsetof(pfioc_natlook.%s) = %d, want %d", f.name, f.got, f.want)
		}
	}
}

func TestPfDIOCNATLOOK(t *testing.T) {
	const iocInOut = 0xc0000000
	const iocParmMask = 0x1fff
	want := uintptr(iocInOut | (sizeofPfiocNatlook&iocParmMask)<<16 | 'D'<<8 | 23)
	if sysDIOCNATLOOK != want {
		t.Fatalf("DIOCNATLOOK = %#x, want _IOWR('D', 23, struct pfioc_natlook) = %#x", uint64(sysDIOCNATLOOK), uint64(want))
	}
}

func TestPfiocNatlookPortsAreNetworkByteOrder(t *testing.T) {
	var nl pfiocNatlook
	nl.setPorts(51234, 8080)
	if nl.Sport != [2]byte{0xc8, 0x22} || nl.Dport != [2]byte{0x1f, 0x90} {
		t.Fatalf("setPorts(51234, 8080) = sport % x dport % x, want c8 22 and 1f 90", nl.Sport, nl.Dport)
	}

	nl.Rdport = [2]byte{0x01, 0xbb}
	if got := nl.redirectPort(); got != 443 {
		t.Fatalf("redirectPort({0x01, 0xbb}) = %d, want 443", got)
	}
}
