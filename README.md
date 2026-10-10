# netx

Reusable Go networking helpers with no third-party dependencies.

Requires Go 1.26. Every package builds on all major Go ports, including
Windows, the BSDs, js/wasm, wasip1 and Plan 9. Platform-specific features
return an error matching `errors.ErrUnsupported` where they are not available.

| Package                             | Contents                                                                     |
|-------------------------------------|------------------------------------------------------------------------------|
| `github.com/djylb/netx`             | connection wrappers, `Relay`, in-memory and UDP listeners, error classifiers |
| `github.com/djylb/netx/tlsconn`     | bounded TLS handshakes, TLS over any dialer, self-signed certs, pins, cache  |
| `github.com/djylb/netx/proxyproto`  | PROXY protocol v1 and v2: build, parse, header-reading listener              |
| `github.com/djylb/netx/transparent` | transparent-proxy listeners (TCP, Linux TPROXY UDP), original destinations   |
| `github.com/djylb/netx/socks5`      | SOCKS5 and SOCKS4 codec, client dialer and a configurable server             |
| `github.com/djylb/netx/proxy`       | dialing through HTTP(S), SOCKS5 and SOCKS4 proxies, `ALL_PROXY`/`NO_PROXY`   |

Each package depends only on the standard library and links only what it uses.
`crypto/tls` adds about 800 KB to a binary as soon as it is imported, so only
`tlsconn` and `proxy` (for `https` proxies) import it; the root package,
`proxyproto`, `transparent` and `socks5` each add tens of kilobytes.

## Install

```bash
go get github.com/djylb/netx
```

## Connections

```go
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/tlsconn"
)

// wrap refreshes an idle deadline before every read and write and counts traffic.
func wrap(c net.Conn) net.Conn {
	c = netx.NewTimeoutConn(c, 30*time.Second)
	return netx.ObserveConn(c, netx.TrafficObserver{
		OnRead:  func(n int64) error { return nil },
		OnWrite: func(n int64) error { return nil },
	})
}

func main() {
	raw, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	// The handshake is bounded by 5s; on failure raw is closed.
	conn, err := tlsconn.Client(context.Background(), wrap(raw), &tls.Config{ServerName: "example.com"}, 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
```

- A non-positive timeout means 5s (`netx.DefaultTimeout`,
  `tlsconn.DefaultTimeout`). This also applies to a `TimeoutConn` built as a
  struct literal.
- `TimeoutConn` moves the deadline only once it lags by more than idle/16 (at
  most 1s), so the per-call cost is an atomic load; a connection may time out
  up to that slack early. Idle tracking uses the monotonic clock.
- Deadlines set with `SetDeadline`, `SetReadDeadline` or `SetWriteDeadline`
  stay in effect until changed: setting them and each read or write set a
  direction's deadline to the earlier of that deadline and now plus the idle
  timeout, so `SetReadDeadline(time.Now())` interrupts a blocked `Read` even
  while writes continue, and a later or zero deadline does not lift the idle
  timeout of a `Read` or `Write` that is already blocked.
- `tlsconn.Client` and `tlsconn.Server` bound the handshake by the context and
  the timeout, applied as both a connection deadline and a context deadline,
  and return a `*tls.Conn` with no deadline set. On failure they close the raw
  connection. They live in their own package so that the root package does not
  import `crypto/tls`.
- `tlsconn.Dialer` dials with any `Forward` dialer, such as a proxy dialer, and
  runs `tlsconn.Client` on the result, taking the server name from the dialed
  address unless the config sets one. Used as a proxy dialer's `Forward`, it
  reaches the proxy over TLS.

### TLS certificates

`tlsconn` also generates self-signed certificates, trusts peers by
certificate fingerprint, and caches certificates loaded from files or PEM:

```go
// pinnedTunnel serves a self-signed certificate and returns a client config
// that trusts exactly that certificate.
func pinnedTunnel() (server, client *tls.Config, err error) {
	cert, err := tlsconn.NewSelfSigned(tlsconn.SelfSignedOptions{Hosts: []string{"tunnel.internal"}})
	if err != nil {
		return nil, nil, err
	}
	pins := tlsconn.NewPinSet(tlsconn.Fingerprint(cert.Certificate[0]))
	return &tls.Config{Certificates: []tls.Certificate{cert}}, pins.ClientConfig(nil), nil
}

// perHost serves certificates from files, picking up renewals within an hour.
func perHost() *tls.Config {
	certs := &tlsconn.CertCache{MaxEntries: 1000, ReloadInterval: time.Hour, IdleTimeout: 24 * time.Hour}
	return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		dir := filepath.Join("/etc/certs", filepath.Base(hello.ServerName))
		return certs.LoadFiles(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
	}}
}
```

- `NewSelfSigned` makes a server certificate for DNS names and IP addresses,
  with a new ECDSA P-256 key or a given one (such as RSA), valid for a year by
  default and from an hour in the past. `EncodePEM` writes it, or any
  `tls.Certificate` with an RSA, ECDSA, Ed25519 or ECDH key, as PEM that
  `tls.X509KeyPair` reads back.
- `Fingerprint` is the SHA-256 of a DER certificate. A `PinSet` of them,
  changeable while in use, verifies peers in `VerifyConnection`, which also
  runs for resumed sessions, so removing a pin cuts off resumptions too.
  `ClientConfig` returns a config that trusts exactly the pins, keeping the
  base config's own `VerifyConnection` after the pin check; on a server, use
  `VerifyConnection` with `ClientAuth: tls.RequireAnyClientCert`. A pin names
  one exact certificate, so host names and expiry are not checked.
- `CertCache` keeps certificates by file names, or by a hash of PEM data, for
  `GetCertificate` callbacks that run on every handshake. Concurrent first
  loads share one read, files are read again after `ReloadInterval` (or once
  an expired certificate is due, at most once a minute), a failed reload keeps
  the previous certificate, and `MaxEntries` and `IdleTimeout` bound the
  cache, without a background goroutine.

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

- By default `Read` has stream semantics: it returns what one read of the
  connection delivers of the current frame, and when a frame is larger than
  the buffer or still arriving, the rest of it is returned by the following
  reads, without buffering or allocating. Empty frames carry no stream bytes
  and are skipped.
- `WithReadBuffer(size)` reads the stream through a buffer, so a burst of small
  frames costs one read of the connection (about 30x faster for 64-byte frames
  over loopback TCP).
- With `WithDatagramReads`, every `Read` returns exactly one frame and drops the
  bytes that do not fit in the buffer, like a UDP socket; an empty frame is
  returned as a 0-byte read.
- `ReadFrame` returns one whole frame, or the rest of a frame that a stream
  `Read` has already started.
- An error that loses no frame bytes is returned unchanged and may be
  retried: an expired read deadline between frames or inside a frame header,
  and anywhere in a frame for stream `Read`s, which keep their place. When
  frame bytes are lost, by a `ReadFrame` or datagram `Read` that fails after
  part of the payload, the end of the stream inside a frame, or a write that
  fails partway through a frame, the frame boundaries are lost: that call and
  every later call in the same direction return an error matching
  `errors.Is(err, netx.ErrFrameDesync)`, which is never a timeout. The error
  still matches its cause with `errors.Is` (an EOF inside a frame becomes
  `io.ErrUnexpectedEOF`), except a timeout cause, which is hidden. Close the
  connection.

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

// sniff reads the first bytes of c and hands the connection on with those
// bytes replayed, as if they had not been read.
func sniff(c net.Conn) (net.Conn, error) {
	tee := netx.NewTeeConn(c, 4096)
	if _, err := io.ReadFull(tee, make([]byte, 5)); err != nil {
		return nil, err
	}
	raw, consumed := tee.Release()
	return netx.NewPrefixConn(raw, consumed), nil
}
```

- `PrefixConn` implements `io.WriterTo`: after the prefix it copies through the
  wrapped connection's own `WriteTo`, so a `*net.TCPConn` can still splice.
- The wrappers pass `CloseWrite` on to the wrapped connection, so a half-close
  works through them; it returns an error matching `errors.ErrUnsupported` when
  the wrapped connection cannot do it.

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
  stopped the relay, or nil at EOF. Errors caused by its own `Close` calls are
  not reported.
- With `netx.WithHalfClose()`, EOF in one direction is passed on with
  `CloseWrite` and the other direction keeps going, for protocols where a
  client shuts down its sending side and then reads the answer. Ends without
  `CloseWrite` are closed as usual. Pair it with an idle timeout.
- On Linux, a direction between two `*net.TCPConn`s, or between a
  `*net.TCPConn` and a `*net.UnixConn` (also beneath a `PrefixConn` on the
  reading side), is left to the kernel with `splice`.
- Otherwise a direction is copied with the reading end's `WriteTo` or else the
  writing end's `ReadFrom`, as `io.Copy` would, so a datagram connection that
  implements them keeps each datagram whole. The `WriteTo` and `ReadFrom` of
  `*net.TCPConn` and `*net.UnixConn` are skipped (also beneath a `PrefixConn`)
  and the data goes through a pooled 32 KiB buffer instead of one they
  allocate. Sources that return one datagram per read (`*net.UDPConn`,
  `PacketListener` connections, `FramedConn` with `WithDatagramReads`) get a
  64 KiB buffer, so no datagram is cut short.

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

### UDP peers

`PacketListener` splits a packet connection, such as a UDP socket, into one
`net.Conn` per peer, so a UDP server can be written like a TCP server.

```go
func serveUDP(pc net.PacketConn, handle func(net.Conn)) error {
	l := netx.NewPacketListener(pc,
		netx.WithIdleTimeout(2*time.Minute),
		netx.WithAcceptFilter(func(peer net.Addr) bool { return true }),
	)
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go handle(c) // each Read is one datagram, each Write sends one
	}
}
```

- The first datagram from a new peer starts a connection; later ones are read
  from it, truncated to the buffer like a UDP socket. Closing a connection
  lets the next datagram of that peer start a new one.
- Datagrams are dropped, as a socket buffer would, when a connection's queue
  (`WithPacketQueue`, 128) or the accept backlog (`WithAcceptBacklog`, 128) is
  full. A datagram larger than 2 KiB takes the room of several, so a queue
  holds at most 128 × 2 KiB by default however large the datagrams are.
  `WithAcceptFilter` rejects peers before a connection is created.
- As on a socket, a closed connection or an expired read deadline fails
  `Read` even while datagrams are queued.
- `WithIdleTimeout` closes a connection that has been idle since `Accept`
  returned it; connections still waiting for `Accept` are not closed, and their
  datagrams are kept.
- On a `*net.UDPConn` the read loop, queueing and writes do not allocate per
  datagram up to 2 KiB.
  The listener owns the socket and closes it, and all connections, on `Close`.

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
`unexpected_eof`, `eof`, `closed` or `other`; `IsClosed` reports the `closed`
class (`net.ErrClosed`, `io.ErrClosedPipe` and the "use of closed network
connection" text), which ends an accept or read loop. DNS failures are not
classified as unreachable; check for `*net.DNSError`. `DescribeNetError` adds `errno_name`
only for errnos the classifiers recognise; others appear as `errno=<number>`.

## PROXY Protocol

`github.com/djylb/netx/proxyproto` builds, parses and serves the PROXY protocol
headers that tell a backend the original client and destination of a proxied
connection or UDP flow. It depends only on the standard library and not on the
`netx` root package, so importing it adds no more than the header code.

```go
func sendProxyHeader(backend, client net.Conn) error {
	// client.RemoteAddr() is the source, client.LocalAddr() the destination.
	_, err := backend.Write(proxyproto.HeaderFromConn(client, proxyproto.V2))
	return err
}

// behindLoadBalancer reports the client addresses sent by trusted balancers.
func behindLoadBalancer(ln net.Listener, balancers netip.Prefix) net.Listener {
	return &proxyproto.Listener{
		Listener: ln,
		Policy: func(peer net.Addr) proxyproto.Policy {
			if ap, err := netip.ParseAddrPort(peer.String()); err == nil && balancers.Contains(ap.Addr()) {
				return proxyproto.Required
			}
			return proxyproto.Ignore
		},
	}
}

// udpBehindProxy reads the header from the first datagram of each UDP flow.
func udpBehindProxy(pc net.PacketConn) net.Listener {
	return &proxyproto.Listener{Listener: netx.NewPacketListener(pc), Datagram: true}
}
```

- `V1Header`, `V2Header`, `HeaderFromAddrs` and `HeaderFromConn` build a header
  from two addresses. `Header.AppendBinary` encodes a full `Header`, including
  version 2 TLVs and AF_UNIX addresses.
- `Parse` decodes a header at the start of a byte slice and returns
  `io.ErrUnexpectedEOF` while it is incomplete, for protocol sniffers. `Read`
  decodes one from a `bufio.Reader` and leaves a stream without a header
  unread (`ErrNoHeader`).
- Parsing accepts non-standard senders wherever that cannot misattribute a
  connection: v1 lines ending in a bare LF, with runs of spaces, any letter
  case, `UDP4`/`UDP6` tokens, families that differ from the token or padded
  ports; any v2 version nibble. Unknown commands, protocols and families,
  short address blocks and truncated TLVs fall back to the connection's own
  addresses, or to the whole TLVs, instead of failing.
- `Listener` reads the header lazily, on the first read or address query, with
  a timeout (`DefaultHeaderTimeout`), so a slow peer cannot stall `Accept`. The
  read that reaches the timeout returns it; later ones return an error matching
  `ErrNoHeader` that is not a timeout, so loops that retry timeouts do not
  spin. Its `Policy` decides per peer between `Required` (the zero value),
  `Optional` and `Ignore`; only trusted peers should be allowed to send a
  header.
- With `Datagram` set, for listeners such as `netx.PacketListener` whose reads
  return one datagram, the header is taken from the first datagram of each
  flow, alone or followed by payload; later datagrams are passed through
  untouched. Addresses are reported as `*net.UDPAddr`, since UDP senders use
  the v1 `TCP4`/`TCP6` tokens or a v2 `STREAM` transport; `Header.UDPAddrs`
  does the same conversion for other callers. Leave it unset for stream
  protocols over UDP such as KCP or QUIC.
- A nil or unspecified target is sent as `0.0.0.0` or `::`, matching the
  client's address family. As in HAProxy, an IPv4/IPv6 pair is sent as `TCP6`
  (v1) or `AF_INET6` (v2), with the IPv4 side in its IPv4-mapped form
  `::ffff:a.b.c.d`. v1 has no UDP token, so UDP pairs are written with
  `TCP4`/`TCP6`; use v2 to mark them as `DGRAM`.
  Unsupported addresses give `PROXY UNKNOWN\r\n` (v1) or a `LOCAL` header (v2).

## Transparent Proxying

`github.com/djylb/netx/transparent` listens for connections that firewall
rules redirect to a local port and recovers where they were going.

```go
func serve(ctx context.Context, handle func(c net.Conn, target string)) error {
	ln, err := transparent.Listen(ctx, "0.0.0.0:8080")
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		dst, err := transparent.OriginalDestination(c)
		if err != nil {
			_ = c.Close()
			continue
		}
		go handle(c, dst.String())
	}
}
```

| Platform       | `Listen`                                                         | `OriginalDestination`                                              |
|----------------|------------------------------------------------------------------|--------------------------------------------------------------------|
| Linux, Android | sets `IP_TRANSPARENT`/`IPV6_TRANSPARENT` (needs `CAP_NET_ADMIN`) | `SO_ORIGINAL_DST` (REDIRECT/DNAT), else the local address (TPROXY) |
| FreeBSD        | sets `IP_BINDANY`/`IPV6_BINDANY`                                 | pf `DIOCNATLOOK`, else the local address                           |
| macOS, iOS     | plain listener (pf `rdr` needs no socket option)                 | pf `DIOCNATLOOK` (needs root)                                      |
| Others         | `ErrListenUnsupported`                                           | `ErrOriginalDestinationUnsupported`                                |

Both errors match `errors.ErrUnsupported`. For a plain listener use `net.Listen`.
`OriginalDestination` looks through wrappers such as `netx.TimeoutConn` with
`netx.RawConnOf`, so it can be called on a wrapped connection.

On Linux and Android, `ListenPacket`, `ReadFromUDP` and `DialUDP` handle UDP
redirected by TPROXY: each datagram reports its original destination, and
`DialUDP` opens a socket bound to that destination to answer from it.

```go
func serveRedirectedUDP(ctx context.Context) error {
	ln, err := transparent.ListenPacket(ctx, "0.0.0.0:8080")
	if err != nil {
		return err
	}
	buf := make([]byte, 65535)
	for {
		n, src, dst, err := transparent.ReadFromUDP(ln, buf)
		if err != nil {
			return err
		}
		reply, err := transparent.DialUDP(ctx, dst, src)
		if err != nil {
			continue
		}
		_, _ = reply.Write(buf[:n])
		_ = reply.Close()
	}
}
```

For TCP keepalive tuning, use the standard library:

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

## SOCKS5

`github.com/djylb/netx/socks5` reads and writes SOCKS5 messages (RFC 1928),
username/password authentication (RFC 1929) and SOCKS4/SOCKS4a messages for
clients and servers, and provides a client `Dialer` and a `Server` built on
them. The codec functions
neither dial nor listen, and every message is written with a single `Write`.

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
- `ReadRequest4`, `WriteRequest4`, `WriteReply4` and `ReadReply4` handle
  SOCKS4, and SOCKS4a for domain names. SOCKS4 replies (`Reply4Granted`,
  `Reply4Rejected`, ...) share the `Reply` type, whose SOCKS5 codes they do not
  overlap, so `ReadReply4` also fails with a `*socks5.ReplyError`.

### Client

`socks5.Dialer` dials TCP through a SOCKS5 proxy with CONNECT, or a SOCKS4 or
SOCKS4a proxy with `SOCKS4` set. Host names are sent to the proxy, which
resolves them, unless `Resolver` resolves them first, as SOCKS4 servers
without the 4a extension need. A non-success reply is returned as a
`*socks5.ReplyError`.

```go
func dialSOCKS(ctx context.Context, target string) (net.Conn, error) {
	d := &socks5.Dialer{
		ProxyAddr: "127.0.0.1:1080",
		Username:  "alice", // also offers no authentication
		Password:  "secret",
		Forward:   &net.Dialer{Timeout: 10 * time.Second},
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return d.DialContext(ctx, "tcp", target)
}
```

For SOCKS over TLS, give the dialer a `Forward` that returns TLS connections:
`&tls.Dialer{Config: cfg}` or, to reach the proxy through another dialer,
`&tlsconn.Dialer{Config: cfg, Forward: next}`.

### Server

`socks5.Server` serves SOCKS5 CONNECT and UDP ASSOCIATE, and SOCKS4/SOCKS4a
CONNECT when `SOCKS4` is set. Every field is optional; the zero `Server`
accepts anonymous clients and dials directly.

```go
func runSOCKS(ln net.Listener, udp net.PacketConn) error {
	s := &socks5.Server{
		Auth: []socks5.Authenticator{
			socks5.UserPassAuth{Check: socks5.Credentials(map[string]string{"alice": "secret"})},
		},
		Allow: func(ctx context.Context, req *socks5.Request) error {
			if req.Dst.Port == 25 {
				return &socks5.ReplyError{Reply: socks5.ReplyNotAllowed}
			}
			return nil
		},
		Dial: func(ctx context.Context, req *socks5.Request) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", req.Dst.String())
		},
		PacketConn: udp, // one fixed UDP port for every association
	}
	return s.Serve(ln)
}
```

- Hooks: `Auth` (any `Authenticator`), `Allow`, `Dial` (its error picks the
  reply code through `ReplyFor`), `ConnectAddr`, `Relay`, and for UDP
  `DialPacket` (the outbound side, a `socks5.PacketConn` that receives domain
  names unresolved, for example to forward through a tunnel), `AllowPacket`
  and `UDPAddr` (the address advertised to clients).
- `Allow` and `AllowPacket` see every IP address a client sends in
  `Dst.IP`, including IPv4-mapped IPv6 addresses and domain names that are IP
  literals, also with one trailing dot such as `127.0.0.1.`. Other names arrive unresolved, so an IP policy must also check the
  resolved address where `Dial` or `DialPacket` resolves it, for example with
  a `net.Dialer` `Control` function: some resolvers accept forms such as
  `127.1`.
- UDP on a fixed port (`PacketConn`): datagrams must come from the IP address
  of their association's control connection, and are matched by the exact
  source the client announced, or else as the only pending association of that
  IP; ambiguous sources are dropped. Announcements of another IP are ignored,
  so a client cannot claim the datagrams of others; a port announced with
  `0.0.0.0` or a name, by a client that does not know its address, counts at
  the control connection's IP. A control connection without an IP address,
  such as a tunneled stream, must announce the client's IP address, or the
  request is refused. `ListenUDP` instead gives each association its own
  socket, which without a known client IP takes the first source that sends.
  Replies from any source are relayed (full cone), and a reply that cannot be
  delivered is reported to `OnError` and dropped. An association ends with its
  control connection, or after `UDPIdleTimeout`, which closes the control
  connection; `UDPOutlivesControl` keeps it for clients that close the control
  connection early.
- `OnError` receives the errors that end connections and drop datagrams, for
  logging; the package itself does not log.
- The server runs over any `net.Conn`. For SOCKS over TLS, serve
  `tls.NewListener(ln, cfg)`: the TLS handshake happens within
  `HandshakeTimeout`. UDP ASSOCIATE then has a TLS control connection, and its
  datagrams stay plain UDP. To share a port with HTTP or TLS, sniff the first
  byte (5 for SOCKS5, 4 for SOCKS4, 0x16 for a TLS handshake), for example with
  `github.com/djylb/portmux`, and pass SOCKS connections to `ServeConn`, after
  `tlsconn.Server` for TLS ones.
- For non-standard clients, a server without required authentication accepts
  an empty or mismatched method list (username/password with any
  credentials), and reserved bytes and the username/password version byte are
  not checked. A custom `MethodNoAuth` authenticator, such as an IP allowlist,
  still decides on those clients and on SOCKS4 ones.

## Upstream Proxies

`github.com/djylb/netx/proxy` dials TCP through an HTTP CONNECT or SOCKS5
proxy. `FromURL` and `FromEnvironment` build the dialers from a URL; they are
plain structs (`HTTPDialer`, `socks5.Dialer`) that can also be configured
directly, for example with a private CA or extra request headers. A program
that only talks to SOCKS5 proxies can use `socks5.Dialer` alone and avoid the
`crypto/tls` that `https` proxies need.

```go
func corporateProxy(ca *x509.CertPool) *proxy.HTTPDialer {
	return &proxy.HTTPDialer{
		ProxyAddr: "proxy.corp.example:3128",
		TLSConfig: &tls.Config{RootCAs: ca},
		Header:    textproto.MIMEHeader{"User-Agent": {"my-agent/1.0"}},
		Forward:   &net.Dialer{Timeout: 10 * time.Second},
	}
}
```

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

- Schemes: `http` (port 80), `https` (port 443, TLS to the proxy), `socks5`,
  `socks5h`, `socks4a` and `socks4` (port 1080), and `socks5+tls`,
  `socks5h+tls`, `socks4a+tls` and `socks4+tls` for SOCKS over TLS, verified
  against the proxy's host name. User information is sent as Basic
  `Proxy-Authorization`, as SOCKS5 username/password or as the SOCKS4 user ID.
  The SOCKS5 and SOCKS4a schemes let the proxy resolve host names; `socks4`
  resolves them locally. A dialer for one proxy can be the `Forward` dialer of
  another, which chains them.
- The dialers also have a `Dial(network, address)` method, so they satisfy the
  `Dialer` interface of `golang.org/x/net/proxy`.
- The context bounds the dial and the proxy handshake; the returned connection
  has no deadline. Bytes the HTTP proxy sends right after its `2xx` reply are
  kept.
- `FromEnvironment` reads `ALL_PROXY`, where a value without a scheme, such
  as `proxy:3128`, is an `http` proxy, and bypasses the proxy for targets in
  `NO_PROXY`: `*`, IP addresses (IPv6 with or without brackets), CIDR ranges,
  and domain names, which also match their subdomains (a leading `.` or `*.`
  matches subdomains only). An entry may end in `:port`. `ParseNoProxy`
  exposes the same matcher for other dialers.
