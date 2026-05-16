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

func TestProxyProtocolHeaderFromAddrs(t *testing.T) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	targetAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 8080}

	if got := ProxyProtocolHeaderFromAddrs(clientAddr, nil, ProxyProtocolNone); got != nil {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(protocol=0) = %q, want nil", got)
	}
	if got := ProxyProtocolHeaderFromAddrs(clientAddr, nil, ProxyProtocolVersion(9)); got != nil {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(protocol=9) = %q, want nil", got)
	}

	v1 := ProxyProtocolHeaderFromAddrs(clientAddr, nil, ProxyProtocolV1)
	wantV1 := "PROXY TCP4 192.0.2.10 0.0.0.0 1234 0\r\n"
	if string(v1) != wantV1 {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(v1) = %q, want %q", string(v1), wantV1)
	}
	explicitV1 := ProxyProtocolHeaderFromAddrs(clientAddr, targetAddr, ProxyProtocolV1)
	wantExplicitV1 := "PROXY TCP4 192.0.2.10 198.51.100.20 1234 8080\r\n"
	if string(explicitV1) != wantExplicitV1 {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(explicit v1) = %q, want %q", string(explicitV1), wantExplicitV1)
	}
	if !targetAddr.IP.Equal(net.ParseIP("198.51.100.20")) {
		t.Fatalf("ProxyProtocolHeaderFromAddrs mutated target addr: %v", targetAddr)
	}
	udpV1 := ProxyProtocolHeaderFromAddrs(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 53}, nil, ProxyProtocolV1)
	wantUDPV1 := "PROXY TCP4 192.0.2.10 0.0.0.0 53 0\r\n"
	if string(udpV1) != wantUDPV1 {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(udp v1) = %q, want %q", string(udpV1), wantUDPV1)
	}
	udpV1IPv6 := ProxyProtocolHeaderFromAddrs(&net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 53}, nil, ProxyProtocolV1)
	wantUDPV1IPv6 := "PROXY TCP6 2001:db8::10 :: 53 0\r\n"
	if string(udpV1IPv6) != wantUDPV1IPv6 {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(udp v1 ipv6) = %q, want %q", string(udpV1IPv6), wantUDPV1IPv6)
	}

	v2 := ProxyProtocolHeaderFromAddrs(&net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 5353}, nil, ProxyProtocolV2)
	if len(v2) != 52 {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(v2) len = %d, want 52", len(v2))
	}
	if !bytes.HasPrefix(v2, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(v2) missing signature: %v", v2[:12])
	}
	if famProto := v2[13]; famProto != 0x22 {
		t.Fatalf("ProxyProtocolHeaderFromAddrs(v2) fam/proto = 0x%x, want 0x22", famProto)
	}
}
