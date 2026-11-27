package transparent

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestListenUDPFlowsDirect(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprint("direct=", direct), func(t *testing.T) {
			var opts []FlowOption
			if direct {
				opts = append(opts, WithFlowDirect())
			}
			l, err := ListenUDPFlows(context.Background(), "udp4", "127.0.0.1:0", opts...)
			skipWithoutPrivilege(t, err)
			if err != nil {
				t.Fatalf("ListenUDPFlows() error = %v", err)
			}
			defer func() { _ = l.Close() }()
			lnAddr := l.Addr().(*net.UDPAddr)
			client, err := net.DialUDP("udp4", nil, lnAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			if _, err := client.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			if !direct {
				time.Sleep(100 * time.Millisecond)
				n := l.flows.Len()
				if n != 0 {
					t.Fatalf("%d direct flows started, want 0", n)
				}
				return
			}
			c, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			f := c.(*FlowConn)
			if f.Redirected() || f.RemoteAddr().String() != client.LocalAddr().String() || f.LocalAddr().String() != lnAddr.String() {
				t.Fatalf("flow %v -> %v, redirected %v", f.RemoteAddr(), f.LocalAddr(), f.Redirected())
			}
			readFlow(t, f, "ping")
			if _, err := f.Write([]byte("pong")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if n, err := client.Read(buf); err != nil || string(buf[:n]) != "pong" {
				t.Fatalf("client Read() = %q, %v; want pong", buf[:n], err)
			}
		})
	}
}

// TestFlowClientHelper is the client of TestFlowListenerTPROXY, run in
// another network namespace: it sends to NETX_FLOW_CLIENT and expects each
// datagram answered from there.
func TestFlowClientHelper(t *testing.T) {
	target := os.Getenv("NETX_FLOW_CLIENT")
	if target == "" {
		t.Skip("helper process")
	}
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(target)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, 64)
	for i := range 3 {
		if _, err := c.Write([]byte("ping" + strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if want := "pong" + strconv.Itoa(i); err != nil || string(buf[:n]) != want {
			t.Fatalf("Read() = %q, %v; want %q", buf[:n], err, want)
		}
	}
}

// TestFlowListenerTPROXY redirects UDP from another network namespace with
// a TPROXY rule and answers it through flows. It changes the host's firewall
// and network configuration, so it runs only as root with
// NETX_TEST_IPTABLES=1, as in CI.
func TestFlowListenerTPROXY(t *testing.T) {
	if os.Getenv("NETX_TEST_IPTABLES") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and NETX_TEST_IPTABLES=1")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fds := openFDs(t)
	l, err := ListenUDPFlows(context.Background(), "udp4", "0.0.0.0:0", WithFlowIdleTimeout(time.Minute))
	if err != nil {
		t.Fatalf("ListenUDPFlows() error = %v", err)
	}
	defer func() { _ = l.Close() }()
	port := strconv.Itoa(l.Addr().(*net.UDPAddr).Port)

	const (
		ns, hostIf, nsIf = "netxflow", "netxv0", "netxv1"
		targetIP         = "203.0.113.5"
		targetPort       = "53"
		clientIP         = "10.231.0.2"
		mark, table      = "0x4e7", "4231"
	)
	target := net.JoinHostPort(targetIP, targetPort)
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
	}
	cleanup := func(name string, args ...string) {
		t.Cleanup(func() { _ = exec.Command(name, args...).Run() })
	}
	run("ip", "netns", "add", ns)
	cleanup("ip", "netns", "del", ns)
	run("ip", "link", "add", hostIf, "type", "veth", "peer", "name", nsIf)
	cleanup("ip", "link", "del", hostIf)
	run("ip", "link", "set", nsIf, "netns", ns)
	run("ip", "addr", "add", "10.231.0.1/24", "dev", hostIf)
	run("ip", "link", "set", hostIf, "up")
	run("ip", "netns", "exec", ns, "ip", "addr", "add", clientIP+"/24", "dev", nsIf)
	run("ip", "netns", "exec", ns, "ip", "link", "set", nsIf, "up")
	run("ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", "10.231.0.1")
	// Source validation can use the mark too. Keep the route back to the
	// client unicast even when src_valid_mark is enabled.
	route := []string{"local", targetIP + "/32", "dev", "lo", "table", table}
	run("ip", append([]string{"route", "add"}, route...)...)
	cleanup("ip", append([]string{"route", "del"}, route...)...)
	policy := []string{"iif", hostIf, "fwmark", mark, "lookup", table}
	run("ip", append([]string{"rule", "add"}, policy...)...)
	cleanup("ip", append([]string{"rule", "del"}, policy...)...)
	run("ip", "route", "get", targetIP, "from", clientIP, "iif", hostIf, "mark", mark)
	rule := []string{"PREROUTING", "-t", "mangle", "-i", hostIf, "-p", "udp", "-d", targetIP, "--dport", targetPort, "-j", "TPROXY", "--on-port", port, "--tproxy-mark", mark}
	run("iptables", append([]string{"-A"}, rule...)...)
	cleanup("iptables", append([]string{"-D"}, rule...)...)

	for round := range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		client := exec.CommandContext(ctx, "ip", "netns", "exec", ns, exe, "-test.run=^TestFlowClientHelper$", "-test.count=1")
		client.Env = append(os.Environ(), "NETX_FLOW_CLIENT="+target)
		var out bytes.Buffer
		client.Stdout, client.Stderr = &out, &out
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if client.ProcessState == nil {
				_ = client.Wait()
			}
		})
		f := acceptFlow(t, l)
		if !f.Redirected() || f.LocalAddr().String() != target || f.RemoteAddr().(*net.UDPAddr).IP.String() != clientIP {
			t.Fatalf("round %d: flow %v -> %v, redirected %v", round, f.RemoteAddr(), f.LocalAddr(), f.Redirected())
		}
		// The first datagram arrives on the listener, the later ones on the
		// socket that the first answer opened.
		for i := range 3 {
			readFlow(t, f, "ping"+strconv.Itoa(i))
			if _, err := f.Write([]byte("pong" + strconv.Itoa(i))); err != nil {
				t.Fatalf("round %d: Write() error = %v", round, err)
			}
		}
		if err := client.Wait(); err != nil {
			t.Fatalf("round %d: client: %v: %s", round, err, &out)
		}
		cancel()
		// Closing the flow closes its socket, so the next client's flow,
		// from another port, starts anew.
		_ = f.Close()
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if n := openFDs(t); n > fds {
		t.Fatalf("%d open descriptors after Close, want at most %d", n, fds)
	}
}

// A direct flow on a wildcard socket is answered from the address its source
// sent to, not the one the kernel would pick for the route back.
func TestFlowDirectAnswersFromDestination(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	l := newFlowListener(c, []FlowOption{WithFlowDirect()})
	defer func() { _ = l.Close() }()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	// The route back to 127.0.0.1 has source 127.0.0.1; the client sent to
	// 127.0.0.2, also an address of this host.
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(c.LocalAddr().(*net.UDPAddr).Port))
	l.deliver([]byte("ping"), PacketInfo{Src: client.LocalAddr().(*net.UDPAddr).AddrPort(), Dst: dst})
	f := acceptFlow(t, l)
	checkFlowReply(t, f, client, dst)
}

// Broadcast datagrams reach a wildcard socket directly: they are not
// redirected, and a FlowListener does not take them for a flow.
func TestBroadcastIsNotRedirected(t *testing.T) {
	ln, err := ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	skipWithoutPrivilege(t, err)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.LocalAddr().(*net.UDPAddr).Port
	targets := []netip.Addr{netip.MustParseAddr("255.255.255.255")}
	if b, ok := directedBroadcast(); ok {
		targets = append(targets, b)
	}
	for _, ip := range targets {
		s, err := net.ListenUDP("udp4", nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := s.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
		_, err = s.WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(ip, uint16(port)))
		_ = s.Close()
		if err != nil {
			t.Logf("send to %v: %v", ip, err) // no route for broadcast
			continue
		}
		_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, info, err := ReadFromUDP(ln, make([]byte, 16))
		if err != nil {
			t.Fatalf("ReadFromUDP() for %v error = %v", ip, err)
		}
		if info.Redirected {
			t.Errorf("ReadFromUDP() = %+v, want a broadcast to %v not redirected", info, ip)
		}
	}
}

// directedBroadcast returns the broadcast address of an IPv4 network of this
// host other than loopback.
func directedBroadcast() (netip.Addr, bool) {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || n.IP.IsLoopback() {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 || ones >= 31 {
			continue
		}
		ip := n.IP.To4()
		var b [4]byte
		for i := range b {
			b[i] = ip[i] | ^n.Mask[i]
		}
		return netip.AddrFrom4(b), true
	}
	return netip.Addr{}, false
}
