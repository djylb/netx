package netx

import (
	"bytes"
	"net"
	"testing"
)

func TestNormalizeTargetIP(t *testing.T) {
	tests := []struct {
		name string
		src  net.IP
		dst  net.IP
		want net.IP
	}{
		{
			name: "ipv4 source without target",
			src:  net.ParseIP("192.0.2.10"),
			dst:  nil,
			want: net.IPv4zero,
		},
		{
			name: "ipv6 source without target",
			src:  net.ParseIP("2001:db8::10"),
			dst:  nil,
			want: net.IPv6zero,
		},
		{
			name: "ipv6 source normalizes ipv4 target",
			src:  net.ParseIP("2001:db8::10"),
			dst:  net.ParseIP("203.0.113.8"),
			want: net.ParseIP("::cb00:7108"),
		},
		{
			name: "matching family keeps target",
			src:  net.ParseIP("192.0.2.10"),
			dst:  net.ParseIP("198.51.100.8"),
			want: net.ParseIP("198.51.100.8"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeTargetIP(tt.src, tt.dst)
			if !got.Equal(tt.want) {
				t.Fatalf("normalizeTargetIP(%v, %v) = %v, want %v", tt.src, tt.dst, got, tt.want)
			}
		})
	}
}

func TestBuildProxyProtocolHeaderByAddr(t *testing.T) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}

	if got := BuildProxyProtocolHeaderByAddr(clientAddr, nil, 0); got != nil {
		t.Fatalf("BuildProxyProtocolHeaderByAddr(protocol=0) = %q, want nil", got)
	}
	if got := BuildProxyProtocolHeaderByAddr(clientAddr, nil, 9); got != nil {
		t.Fatalf("BuildProxyProtocolHeaderByAddr(protocol=9) = %q, want nil", got)
	}

	v1 := BuildProxyProtocolHeaderByAddr(clientAddr, nil, 1)
	wantV1 := "PROXY TCP4 192.0.2.10 0.0.0.0 1234 0\r\n"
	if string(v1) != wantV1 {
		t.Fatalf("BuildProxyProtocolHeaderByAddr(v1) = %q, want %q", string(v1), wantV1)
	}

	v2 := BuildProxyProtocolHeaderByAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 5353}, nil, 2)
	if len(v2) != 52 {
		t.Fatalf("BuildProxyProtocolHeaderByAddr(v2) len = %d, want 52", len(v2))
	}
	if !bytes.HasPrefix(v2, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		t.Fatalf("BuildProxyProtocolHeaderByAddr(v2) missing signature: %v", v2[:12])
	}
	if famProto := v2[13]; famProto != 0x22 {
		t.Fatalf("BuildProxyProtocolHeaderByAddr(v2) fam/proto = 0x%x, want 0x22", famProto)
	}
}
