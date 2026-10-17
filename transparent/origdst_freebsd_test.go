//go:build freebsd

package transparent

import (
	"testing"
	"unsafe"
)

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
