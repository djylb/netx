# netx

Reusable Go networking helpers with no third-party dependencies.

Requires Go 1.25. The package builds on all major Go ports, including Windows,
the BSDs, js/wasm, wasip1 and Plan 9. Platform-specific features return an
`Err...Unsupported` error where they are not available.

## Install

```bash
go get github.com/djylb/netx
```

## Connections

```go
package main

import (
	"crypto/tls"
	"log"
	"net"
	"time"

	"github.com/djylb/netx"
)

// wrap refreshes an idle deadline before every read and write and counts traffic.
func wrap(c net.Conn) net.Conn {
	c = netx.NewTimeoutConn(c, 30*time.Second)
	return netx.ObserveConn(c, netx.TrafficObserver{
		OnRead:  func(n int64) error { return nil },
		OnWrite: func(n int64) error { return nil },
	})
}

// tlsClient runs a client handshake that is bounded by a 5s timeout.
func tlsClient(c net.Conn) (net.Conn, error) {
	tc, err := netx.NewTLSConn(c, 5*time.Second, &tls.Config{ServerName: "example.com"})
	if err != nil {
		// Return an untyped nil: a nil *netx.TLSConn stored in a net.Conn is not == nil.
		return nil, err
	}
	return tc, nil
}

func main() {
	raw, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	conn, err := tlsClient(wrap(raw))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
```

- A non-positive timeout means `netx.DefaultTimeout` (5s). This also applies to
  a `TimeoutConn` built as a struct literal.
- `NewTLSConn`, `NewTLSConnContext`, `NewTimeoutTLSConn` and
  `NewTimeoutTLSConnContext` bound the handshake by the timeout through both a
  connection deadline and a derived context. They return concrete pointers that
  are nil on error.

### Framed messages

`FramedConn` sends each message as a 2-byte big-endian length followed by up to
`MaxFramePayload` (65535) bytes.

```go
func exchange(conn net.Conn, packet []byte) ([]byte, error) {
	framed := netx.NewFramedConn(conn)
	if err := framed.WriteFrame(packet); err != nil {
		return nil, err
	}
	return framed.ReadFrame()
}

// relayDatagrams forwards each frame as one UDP datagram.
func relayDatagrams(tunnel net.Conn, udp *net.UDPConn, peer *net.UDPAddr) error {
	framed := netx.NewFramedConn(tunnel, netx.WithDatagramReads())
	buf := make([]byte, netx.MaxFramePayload)
	for {
		n, err := framed.Read(buf)
		if err != nil {
			return err
		}
		if _, err := udp.WriteToUDP(buf[:n], peer); err != nil {
			return err
		}
	}
}
```

- By default `Read` has stream semantics: when a frame is larger than the
  buffer, the rest of it is returned by the following reads.
- With `WithDatagramReads`, every `Read` returns exactly one frame and drops the
  bytes that do not fit in the buffer, like a UDP socket.
- `ReadFrame` returns one whole frame, or the rest of a frame that a stream
  `Read` has already started.
- If a read or write fails partway through a frame, the frame boundaries are
  lost: that call and every later call in the same direction return an error
  matching `errors.Is(err, netx.ErrFrameDesync)`, which is never a timeout.
  The error still matches its cause with `errors.Is` (an EOF inside a frame
  becomes `io.ErrUnexpectedEOF`), except a timeout cause, which is hidden.
  Close the connection. An error between frames, such as an expired read
  deadline, is returned unchanged and may be retried.

### Wrapping and unwrapping

```go
func expose(rwc io.ReadWriteCloser, parent net.Conn) net.Conn {
	// Addresses and deadlines come from parent. Closing the result closes rwc
	// and, with WithParentClose, parent too; a parent that rwc already closed is
	// not reported as an error.
	return netx.WrapConn(rwc, parent, netx.WithParentClose())
}

func withAddrs(rawConn net.Conn) net.Conn {
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 443}
	// A nil address falls back to the wrapped connection's own address.
	return netx.NewAddrOverrideConn(rawConn, remote, nil)
}

func socketOf(c net.Conn) net.Conn {
	// Follows RawConn() and the standard NetConn() method (for example on
	// *tls.Conn) down to the innermost connection.
	return netx.RawConnOf(c)
}

// sniff reads the first bytes of c and hands back the connection together with
// the bytes already consumed, so another handler can replay them.
func sniff(c net.Conn) (net.Conn, []byte, error) {
	tee := netx.NewTeeConn(c, 4096)
	if _, err := io.ReadFull(tee, make([]byte, 5)); err != nil {
		return nil, nil, err
	}
	raw, consumed := tee.Release()
	return raw, consumed, nil
}
```

### Relaying

```go
// forward copies between client and backend until either side stops, then
// closes both.
func forward(client, backend net.Conn) {
	up, down, err := netx.Relay(client, backend)
	log.Printf("sent=%d received=%d err=%v", up, down, err)
}
```

- `Relay` returns the bytes copied in each direction and the error that
  stopped the first direction, or nil at EOF. Errors caused by its own
  `Close` calls are not reported.
- Copies go through `io.CopyBuffer` with a pooled 32 KiB buffer, so two raw
  `*net.TCPConn`s still use `splice`/`sendfile` where the platform has it.

## Listeners

```go
// handOff serves connections that were accepted and routed elsewhere.
func handOff(srv *http.Server) *netx.ChanListener {
	l := netx.NewChanListener(&net.TCPAddr{Port: 443}, 128)
	go func() { _ = srv.Serve(l) }()
	return l
}

func route(ctx context.Context, l *netx.ChanListener, c net.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	return l.Deliver(ctx, c) // closes c if it cannot be queued
}

// dialInProcess reaches the same server without a socket.
func dialInProcess(ctx context.Context, l *netx.ChanListener) (net.Conn, error) {
	return l.Dial(ctx, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000})
}

// serveOne runs an http.Server on one connection and returns when the
// connection is closed.
func serveOne(c net.Conn, h http.Handler) error {
	err := (&http.Server{Handler: h}).Serve(netx.NewSingleConnListener(c))
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
```

- `Deliver` waits for queue space until the context is done or the listener
  closes. On success the listener owns the connection: `Accept` returns it or
  `Close` closes it. On failure `Deliver` closes it.
- `Dial` connects through a synchronous `net.Pipe`. The server end reports the
  given remote address and the listener address; the client end reports the
  reverse.
- `NewSingleConnListener` returns the connection once. Later `Accept` calls
  return `net.ErrClosed` after the connection or the listener is closed. The
  accepted connection is a wrapper (unwrap it with `RawConnOf`), so for TLS
  wrap the listener with `tls.NewListener` instead of passing a `*tls.Conn`.

## SOCKS5

`github.com/djylb/netx/socks5` reads and writes SOCKS5 messages (RFC 1928)
and username/password authentication (RFC 1929) for clients and servers. It
neither dials nor listens, and every message is written with a single `Write`.

```go
// handshake runs the server side of a SOCKS5 CONNECT without authentication.
func handshake(c net.Conn) (socks5.Addr, error) {
	methods, err := socks5.ReadMethods(c)
	if err != nil {
		return socks5.Addr{}, err
	}
	if !slices.Contains(methods, socks5.MethodNoAuth) {
		_ = socks5.WriteMethod(c, socks5.MethodNoAcceptable)
		return socks5.Addr{}, socks5.ErrNoAcceptableMethod
	}
	if err := socks5.WriteMethod(c, socks5.MethodNoAuth); err != nil {
		return socks5.Addr{}, err
	}
	cmd, dst, err := socks5.ReadRequest(c)
	switch {
	case errors.Is(err, socks5.ErrAddrType):
		_ = socks5.WriteReply(c, socks5.ReplyAddrTypeNotSupported, socks5.Addr{})
		return socks5.Addr{}, err
	case err != nil:
		return socks5.Addr{}, err
	case cmd != socks5.CmdConnect:
		_ = socks5.WriteReply(c, socks5.ReplyCommandNotSupported, socks5.Addr{})
		return socks5.Addr{}, fmt.Errorf("unsupported %v", cmd)
	}
	return dst, nil // dial dst, then socks5.WriteReply(c, socks5.ReplySucceeded, bound)
}

// udpRelay unwraps a UDP ASSOCIATE datagram and wraps the answer.
func udpRelay(packet []byte, exchange func(dst string, payload []byte) (net.Addr, []byte)) ([]byte, error) {
	dst, payload, err := socks5.ParseDatagram(packet)
	if err != nil {
		return nil, err
	}
	from, answer := exchange(dst.String(), payload)
	return socks5.AppendDatagram(nil, socks5.AddrFromNetAddr(from), answer)
}
```

- `Addr` holds an IP address (`netip.Addr`) or a domain name, and a port.
  IPv4-mapped addresses are sent as IPv4, zones are dropped, and the zero
  `Addr` is sent as `0.0.0.0:0`.
- `ReadReply` returns a `*socks5.ReplyError` for a reply other than
  `ReplySucceeded`. `DecodeAddr` decodes an address embedded in another
  message. `ParseDatagram` rejects fragments with `ErrFragmented` and
  ignores the reserved field.

## Upstream Proxies

`github.com/djylb/netx/proxy` dials TCP through an HTTP CONNECT or SOCKS5
proxy.

```go
func dialVia(ctx context.Context, proxyURL, target string) (net.Conn, error) {
	forward := &net.Dialer{Timeout: 10 * time.Second}
	var d proxy.ContextDialer = forward
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		if d, err = proxy.FromURL(u, forward); err != nil {
			return nil, err
		}
	} else {
		var err error
		if d, err = proxy.FromEnvironment(forward); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return d.DialContext(ctx, "tcp", target)
}
```

- Schemes: `http` (port 80), `https` (port 443, TLS to the proxy), `socks5`
  and `socks5h` (port 1080). User information is sent as Basic
  `Proxy-Authorization` or as SOCKS5 username/password. Both SOCKS5 schemes let
  the proxy resolve host names.
- The context bounds the dial and the proxy handshake; the returned connection
  has no deadline. Bytes the HTTP proxy sends right after its `2xx` reply are
  kept.
- `FromEnvironment` reads `ALL_PROXY` and bypasses the proxy for targets in
  `NO_PROXY`: `*`, IP addresses, CIDR ranges, and domain names, which also
  match their subdomains (a leading `.` or `*.` matches subdomains only). An
  entry may end in `:port`. `ParseNoProxy` exposes the same matcher for other
  dialers.

## PROXY Protocol

```go
func sendProxyHeader(backend, client net.Conn) error {
	// client.RemoteAddr() is the source, client.LocalAddr() the destination.
	_, err := backend.Write(netx.ProxyProtocolHeader(client, netx.ProxyProtocolV2))
	return err
}

func udpProxyHeader(client, target *net.UDPAddr) []byte {
	return netx.ProxyProtocolHeaderFromAddrs(client, target, netx.ProxyProtocolV2)
}
```

- A nil or unspecified target is sent as `0.0.0.0` or `::`, matching the
  client's address family.
- As in HAProxy, an IPv4/IPv6 pair is sent as `TCP6` (v1) or `AF_INET6` (v2),
  with the IPv4 side in its IPv4-mapped form `::ffff:a.b.c.d`.
- v1 has no UDP token, so UDP pairs are written with `TCP4`/`TCP6` (historical
  nps behavior). Use v2 to mark them as UDP (`DGRAM`).
- Unsupported addresses give `PROXY UNKNOWN\r\n` (v1) or a `LOCAL` header (v2).

## TCP Transport

```go
func listen(ctx context.Context) (net.Listener, error) {
	return netx.ListenTCPContext(ctx, "0.0.0.0:8080", netx.WithTransparent())
}

func target(conn net.Conn) (string, error) {
	dst, err := netx.OriginalDestination(conn)
	if err != nil {
		return "", err
	}
	return dst.String(), nil
}
```

| Platform       | `ListenTCP(addr, WithTransparent())`                             | `OriginalDestination`                                              |
|----------------|------------------------------------------------------------------|--------------------------------------------------------------------|
| Linux, Android | sets `IP_TRANSPARENT`/`IPV6_TRANSPARENT` (needs `CAP_NET_ADMIN`) | `SO_ORIGINAL_DST` (REDIRECT/DNAT), else the local address (TPROXY) |
| FreeBSD        | sets `IP_BINDANY`/`IPV6_BINDANY`                                 | pf `DIOCNATLOOK`, else the local address                           |
| macOS, iOS     | plain listener (pf `rdr` needs no socket option)                 | pf `DIOCNATLOOK` (needs root)                                      |
| Others         | `ErrTransparentListenUnsupported`                                | `ErrOriginalDestinationUnsupported`                                |

`ListenTCP` without options is a plain TCP listener on every platform. For
TCP keepalive tuning, use the standard library:

```go
func keepAlive(c *net.TCPConn) error {
	return c.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     30 * time.Second,
		Interval: 10 * time.Second,
		Count:    3,
	})
}
```

## Error Helpers

```go
func dialStatus(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	switch {
	case err == nil:
		_ = c.Close()
		return "ok"
	case netx.IsConnRefused(err):
		return "refused"
	case netx.IsHostUnreachable(err), netx.IsNetworkUnreachable(err):
		return "unreachable"
	case netx.IsPermissionDenied(err):
		return "blocked"
	case netx.IsTimeout(err):
		return "timeout"
	default:
		return netx.NetErrorKind(err)
	}
}

func logReadError(c net.Conn, err error) {
	if netx.IsTimeout(err) {
		return // idle connection
	}
	// kind=rst err="read tcp ...: connection reset by peer" local=... remote=...
	// timeout=false op=read net=tcp source=... addr=... syscall=read errno=...
	// errno_name=ECONNRESET
	log.Printf("read failed: %s", netx.DescribeNetError(err, c))
}
```

The classifiers check the platform errno first, so they work whatever the
system language is. On Windows this includes the Winsock codes (`WSAECONNRESET`,
`WSAETIMEDOUT`, ...), which the `syscall.E*` constants do not match. Errors that
only carry text fall back to well-known English messages. `NetErrorKind`
returns one of `none`, `rst`, `aborted`, `broken_pipe`, `refused`,
`host_unreachable`, `network_unreachable`, `permission_denied`, `timeout`,
`unexpected_eof`, `eof`, `closed` or `other`. DNS failures are not classified
as unreachable; check for `*net.DNSError`. `DescribeNetError` adds `errno_name`
only for errnos the classifiers recognise; others appear as `errno=<number>`.
