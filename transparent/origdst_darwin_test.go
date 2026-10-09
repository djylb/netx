//go:build darwin

package transparent

import (
	"context"
	"testing"
	"unsafe"
)

func TestDarwinDIOCNATLOOK(t *testing.T) {
	// _IOWR('D', 23, struct pfioc_natlook) from XNU bsd/net/pfvar.h.
	// Keep this ABI regression check even though both sides are constants.
	//noinspection GoBoolExpressions
	if diocNatLook != 0xc0544417 {
		t.Fatalf("DIOCNATLOOK = %#x, want 0xc0544417", uint64(diocNatLook))
	}
}

func TestDarwinPfiocNatlookLayout(t *testing.T) {
	var nl pfiocNatlook
	if size := unsafe.Sizeof(nl); size != 84 {
		t.Fatalf("sizeof(pfiocNatlook) = %d, want 84", size)
	}
	if natLookLen != unsafe.Sizeof(nl) {
		t.Fatalf("natLookLen = %d, want sizeof(pfiocNatlook) = %d", natLookLen, unsafe.Sizeof(nl))
	}
	for _, f := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "rdaddr", got: unsafe.Offsetof(nl.rdaddr), want: 48},
		{name: "sxport", got: unsafe.Offsetof(nl.sxport), want: 64},
		{name: "dxport", got: unsafe.Offsetof(nl.dxport), want: 68},
		{name: "rdxport", got: unsafe.Offsetof(nl.rdxport), want: 76},
		{name: "af", got: unsafe.Offsetof(nl.af), want: 80},
		{name: "proto", got: unsafe.Offsetof(nl.proto), want: 81},
		{name: "direction", got: unsafe.Offsetof(nl.direction), want: 83},
	} {
		if f.got != f.want {
			t.Fatalf("offsetof(pfioc_natlook.%s) = %d, want %d", f.name, f.got, f.want)
		}
	}
}

func TestDarwinPfiocNatlookPortsAreNetworkByteOrder(t *testing.T) {
	var nl pfiocNatlook
	nl.setPorts(51234, 8080)
	if nl.sxport != [4]byte{0xc8, 0x22} || nl.dxport != [4]byte{0x1f, 0x90} {
		t.Fatalf("setPorts(51234, 8080) = sxport % x dxport % x, want c8 22 00 00 and 1f 90 00 00", nl.sxport, nl.dxport)
	}

	// Ports above 255 need the high byte widened before shifting.
	nl.rdxport = [4]byte{0x1f, 0x90}
	if got := nl.redirectPort(); got != 8080 {
		t.Fatalf("redirectPort({0x1f, 0x90}) = %d, want 8080", got)
	}
}

func TestOriginalDestinationOfDirectConnOnDarwin(t *testing.T) {
	ln, err := Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, server := dialAccepted(t, ln)

	// Without root /dev/pf cannot be opened, and a direct connection has no
	// rdr state; if pf does keep plain state for it, the lookup reports the
	// connection's own destination.
	dst, err := OriginalDestination(server)
	if err == nil && dst.String() != ln.Addr().String() {
		t.Fatalf("OriginalDestination = %v, want error or %v", dst, ln.Addr())
	}
}
