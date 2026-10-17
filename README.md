# netx

Reusable Go networking helpers with no third-party dependencies.

Requires Go 1.26. Every package builds on all major Go ports, including
Windows, the BSDs, js/wasm, wasip1 and Plan 9. Platform-specific features
return an error matching `errors.ErrUnsupported` where they are not available.

| Package                             | Contents                                                                     |
|-------------------------------------|------------------------------------------------------------------------------|
| `github.com/djylb/netx`             | conn wrappers, `Relay`, `ConnGroup`, in-memory/UDP listeners, error helpers  |
| `github.com/djylb/netx/tlsconn`     | bounded TLS handshakes, TLS over any dialer, self-signed certs, pins, certs  |
| `github.com/djylb/netx/proxyproto`  | PROXY protocol v1 and v2: build, decode, header-reading conn and listener    |
| `github.com/djylb/netx/transparent` | transparent-proxy listeners (TCP, Linux TPROXY UDP), original destinations   |
| `github.com/djylb/netx/socks5`      | SOCKS5 and SOCKS4 codec, client dialer and a configurable server             |
| `github.com/djylb/netx/proxydial`   | dialing through HTTP(S), SOCKS5 and SOCKS4 proxies, `ALL_PROXY`/`NO_PROXY`   |

Each package depends only on the standard library and links only what it uses.
`crypto/tls` adds a large amount of code to a binary as soon as it is
imported, so only `tlsconn` and `proxydial` (for `https` proxies) import it; the
root package, `proxyproto`, `transparent` and `socks5` stay small.

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
	return netx.ObserveConn(c,
		func(n int64) error { return nil }, // read
		func(n int64) error { return nil }, // write
	)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	// The dial and the handshake are bounded by ctx; on failure raw is closed.
	conn, err := tlsconn.Client(ctx, wrap(raw), &tls.Config{ServerName: "example.com"})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
```

- A non-positive idle timeout sets none; `SetIdleTimeout` changes it later,
  such as from a short one during a handshake to a longer one after it.
- `TimeoutConn` moves the deadline only once less than the idle timeout is
  left, and then to the idle timeout plus a slack of idle/16 (at most 1s), so
  the per-call cost is an atomic load. A connection never times out before
  it has been idle for the idle timeout, and at most that slack later. Idle
  tracking uses the monotonic clock.
- Deadlines set with `SetDeadline`, `SetReadDeadline` or `SetWriteDeadline`
  stay in effect until changed: setting them and each read or write set a
  direction's deadline to the earlier of that deadline and now plus the idle
  timeout, so `SetReadDeadline(time.Now())` interrupts a blocked `Read` even
  while writes continue, and a later or zero deadline does not lift the idle
  timeout of a `Read` or `Write` that is already blocked.
- `tlsconn.Client` and `tlsconn.Server` bound the handshake by the context's
  deadline, applied as both a connection deadline and through the context, so
  it also holds on connections that ignore deadlines; a context without a
  deadline gets `DefaultHandshakeTimeout` (10s, room for a slow link and a
  large certificate chain) as a safety bound. They return a `*tls.Conn` with
  no deadline set and close the raw connection on failure. They live in their
  own package so that the root package does not import `crypto/tls`.
- `tlsconn.Dialer` dials with any `Forward` dialer, such as a proxy dialer, and
  runs `tlsconn.Client` on the result, taking the server name from the dialed
  address unless the config sets one. The context bounds the dial and the
  handshake; a positive `HandshakeTimeout` also bounds the handshake. Used as
  a proxy dialer's `Forward`, it reaches the proxy over TLS.

### TLS certificates

`tlsconn` also generates self-signed certificates and issues them from a
private CA, trusts peers by certificate fingerprint, keeps certificates from
files in sync, and picks a certificate for each handshake from many:

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

// mutualPins makes each side trust exactly the other's certificate, both
// made with ExtKeyUsage ServerAuth and ClientAuth.
func mutualPins(serverCert, clientCert tls.Certificate) (server, client *tls.Config) {
	clientPins := tlsconn.NewPinSet(tlsconn.Fingerprint(clientCert.Certificate[0]))
	serverPins := tlsconn.NewPinSet(tlsconn.Fingerprint(serverCert.Certificate[0]))
	server = clientPins.ServerConfig(&tls.Config{Certificates: []tls.Certificate{serverCert}})
	client = serverPins.ClientConfig(&tls.Config{Certificates: []tls.Certificate{clientCert}})
	return server, client
}

// perHost serves certificates from files, picking up renewals as the files
// change.
func perHost() *tls.Config {
	certs := &tlsconn.CertFiles{MaxEntries: 1000, IdleTimeout: 24 * time.Hour}
	return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		dir := filepath.Join("/etc/certs", filepath.Base(hello.ServerName))
		return certs.LoadFiles(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
	}}
}
```

- `NewSelfSigned` makes a certificate for DNS names and IP addresses, with a
  new ECDSA P-256 key or a given one (such as RSA), valid for a year by
  default and from an hour in the past. It is a server certificate unless
  `ExtKeyUsage` says otherwise: `x509.ExtKeyUsageClientAuth` for a client
  certificate, or both for peers that take either side. `EncodePEM` writes it,
  or any `tls.Certificate` with an RSA, ECDSA, Ed25519 or ECDH key, as PEM that
  `tls.X509KeyPair` reads back.
- For a private network, `NewCA` makes a self-signed CA that signs leaves
  only (MaxPathLen 0), and `Issue(ca, opts)` signs a leaf for `opts.Hosts`
  with `opts.ExtKeyUsage` (server by default, `ClientAuth` for mutual TLS),
  its chain holding the leaf, then the CA, its validity ending no later than
  the CA's. Peers trust the CA in `RootCAs`, `ClientCAs` or `CertStore.Roots`.
  It is minimal issuing, not a full CA: there is no revocation.
- `Fingerprint` is the SHA-256 of a DER certificate. A `PinSet` of them,
  changeable while in use, verifies peers in `VerifyConnection`, which also
  runs for resumed sessions, so removing a pin cuts off resumptions too.
  `ClientConfig` returns a config that trusts exactly the pinned server
  certificates; `ServerConfig` returns one that requires a client certificate
  (`tls.RequireAnyClientCert`) and accepts exactly the pinned ones, also in
  configs that the base's `GetConfigForClient` returns. Both keep
  the base config's own `VerifyConnection` after the pin check. A pin names
  one exact certificate, so host names and expiry are not checked.
- `CertFiles` keeps certificates by file names, or by a hash of PEM data, for
  `GetCertificate` callbacks that run on every handshake. Concurrent first
  loads share one read. Files stay in sync by change: a use at most every
  `CheckInterval` (`DefaultCheckInterval`, 10s; negative never) stats both
  files, following symbolic links, and reads them again only if the size,
  modification time or file identity changed, so a certbot-style link swap
  counts. Once a certificate has expired, its files are read again even when
  they look unchanged, at most once a minute, and it is not returned
  (`ErrNotValidNow`). A read that fails, such as a certificate replaced before
  its key, or that brings a certificate not valid now while the previous one
  is (an old pair copied back), keeps the previous certificate, goes to
  `OnError`, and is retried at the next check. `MaxEntries` and `IdleTimeout` bound the cache, without
  a background goroutine. `Forget` drops one file pair and `Clear` drops all.
- `CertStore` holds certificates by ID and picks one for each handshake, for
  `GetCertificate`. `Add`, `AddPEM` and `AddFiles` (kept in sync as in
  `CertFiles`, in the background as handshakes come, or at once with
  `CheckFiles`) take an ID; an empty one means the certificate file's
  cleaned path for `AddFiles`, which stays across renewals, and
  `CertID(cert)`, the leaf's hex SHA-256 fingerprint, for `Add` and
  `AddPEM`. A fingerprint names one exact certificate, so give certificates
  that get renewed a stable ID, such as the host configuration's ID or the
  domain. They serve the leaf's DNS names (wildcards included) and IP
  addresses, or the names given. `Remove`, `Certificate`, `List` and
  `SetDefault` work by ID. One name can match several certificates; a
  handshake gets:
  1. the one `Select` names, as a host-routing proxy looks up the requested
     host's configuration, served even if not for the name; an ID the store
     does not hold or that is not valid now goes to `OnError` and the ranking
     chooses;
  2. else the best for the server name: one the client can use
     (`SupportsCertificate`, asked only when there is a choice), then one
     issued by an authority (verified against `Roots`, nil for the system
     roots, when added or read) over a self-signed one, then an exact name
     over a wildcard (`*.example.com`, one label), then the later
     `NotAfter`, then the one added last;
  3. else the one `Load` brings for the name;
  4. else the default, which also serves clients without SNI, after any
     certificate for the IP address they connected to.

  No certificate serves before its `NotBefore` or from its `NotAfter` on.
  `Match(name)` lists the certificates for a name in this order, each once,
  with its `Role` (candidate, loaded or default) and why (authority,
  wildcard, validity, default, source, files) for an admin view. `Load` fetches
  certificates on demand: concurrent handshakes for a name share one call,
  bounded by `LoadTimeout` (`DefaultLoadTimeout`, 30s) even when `Load`
  ignores its context, a panic, a failure or a certificate not valid now
  (expired or not valid yet) fails it, and a failure is remembered for
  `RetryAfter`. A loaded certificate is loaded again before it
  expires (`RefreshBefore`, or a third of its lifetime if shorter) while it
  serves on, also when that fails or brings one not valid now; a refresh that
  finds none stops it serving. `Refresh` makes one due, also during a load,
  and `Forget` drops one; adding a certificate drops what was loaded for the
  names it covers. Names come from clients, so bound the loaded ones with
  `MaxEntries` or `IdleTimeout` and have `Load` turn unknown names away
  cheaply. Names are matched in ASCII (punycode) form. `OnError` receives a
  `*CertError` (ID, name, files, cause) for every failure no handshake sees,
  runs without locks held and may call back into the store.

```go
store := &tlsconn.CertStore{
	Select: func(hello *tls.ClientHelloInfo) (string, error) {
		return hosts[hello.ServerName].CertID, nil // "" lets the ranking choose
	},
	Load: func(ctx context.Context, name string) (*tls.Certificate, error) {
		return fetchCertificate(ctx, name) // nil, nil when there is none
	},
	OnError: func(err *tlsconn.CertError) { log.Println(err) },
}
_, err := store.AddFiles("wildcard", "/etc/certs/wildcard/fullchain.pem", "/etc/certs/wildcard/privkey.pem")
store.SetDefault("wildcard")
srv := &http.Server{TLSConfig: &tls.Config{GetCertificate: store.GetCertificate}}
```

### Framed messages

`FramedConn` sends each message as a 2-byte big-endian length followed by up to
`MaxFramePayload` (65535) bytes. Each frame goes out with one write of the
connection, header and payload together (a vectored write on TCP), so a
layer beneath that compresses or encrypts each write sees whole frames.

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
	framed := netx.NewFramedConn(tunnel, netx.WithFramedDatagrams())
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

- By default the connection is a stream: `Write` sends data longer than
  `MaxFramePayload` (65535 bytes) as several frames, and `Read` returns the
  current frame, or as much of it as fits in the buffer, waiting for its
  bytes, and a frame larger than the buffer continues in the following reads,
  without buffering or allocating. Empty frames carry no stream bytes and are skipped. An error
  inside a frame returns the bytes read so far, so use `WithFramedDatagrams` or
  `ReadFrame` when message boundaries matter.
- `WithFramedReadBuffer(size)` reads the stream through a buffer, so a burst
  of small frames costs one read of the connection.
- With `WithFramedDatagrams` each frame is a message: every `Read` returns
  exactly one frame and drops the bytes that do not fit in the buffer, like a
  UDP socket, an empty frame is returned as a 0-byte read, and `Write` sends
  exactly one frame, failing with `ErrFrameTooLarge` above `MaxFramePayload`.
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
	// and, with WithWrapParentClose, parent too; a parent that rwc already closed is
	// not reported as an error.
	return netx.WrapConn(rwc, parent, netx.WithWrapParentClose())
}

func withAddrs(rawConn net.Conn) net.Conn {
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 443}
	// A nil address falls back to the wrapped connection's own address.
	return netx.NewAddrOverrideConn(rawConn, remote, nil)
}

func socketOf(c net.Conn) net.Conn {
	// Follows the standard NetConn() methods (for example of *tls.Conn and
	// of this package's wrappers) down to the innermost connection.
	return netx.InnermostConn(c)
}

// sniff reads the first bytes of c, within 5s, and hands the connection on
// with those bytes replayed, as if they had not been read. Peek returns after
// the first read, so a client whose first message is short, such as a
// SOCKS5 greeting, does not wait for the timeout; PeekFull reads exactly n.
func sniff(ctx context.Context, c net.Conn) (net.Conn, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, first, err := netx.Peek(ctx, c, 5)
	return c, bytes.HasPrefix(first, []byte{0x16, 0x03}), err // a TLS record?
}
```

- `PrefixConn` implements `io.WriterTo`: after the prefix it copies through the
  wrapped connection's own `WriteTo`, so a `*net.TCPConn` can still splice.
- The wrappers pass `CloseWrite` on to the wrapped connection, so a half-close
  works through them; it returns an error matching `errors.ErrUnsupported` when
  the wrapped connection cannot do it.

### Relaying

```go
// forward copies between client and backend until either side stops or ctx
// ends, then closes both.
func forward(ctx context.Context, client, backend net.Conn) {
	up, down, err := netx.Relay(ctx, client, backend)
	log.Printf("sent=%d received=%d err=%v", up, down, err)
}
```

- `Relay` returns the bytes copied in each direction and the error that
  stopped the relay, or nil at EOF. Errors caused by its own `Close` calls are
  not reported.
- With `netx.WithRelayHalfClose()`, EOF in one direction is passed on with
  `CloseWrite` and the other direction keeps going, for protocols where a
  client shuts down its sending side and then reads the answer. Ends without
  `CloseWrite` are closed as usual. Pair it with an idle timeout.
- The end of `ctx` ends the relay, closing both ends, and `Relay` returns
  `context.Cause(ctx)`. Cancelling one context ends every relay that shares
  it, also those idle in a read.
- `WithRelayIdleTimeout(d)` ends a relay through which nothing has passed in
  either direction for `d`, returning `netx.ErrRelayIdle`. Relay watches the
  data it copies, also where it splices, and leaves the ends' deadlines
  alone, so ends without deadlines work too, and time blocked in a
  `RelayFlow.Wait` is not idleness.
- `WithRelayFlows(aToB, bToA)` paces and counts each direction without
  wrapping the connections. `RelayFlow.Wait(ctx, n)` runs before each read
  and returns how many bytes may pass, which a stream reads at most and a
  datagram ignores, as it is read whole; `Done(n)` reports the bytes written,
  so a limiter can charge there and let a later `Wait` wait out the debt.
  `First(b)` gets each direction's first bytes, to tell a connection's
  protocol or log its start, and `End(n, err)` is called once when a
  direction stops, before its end is passed on, with `net.ErrClosed` for a
  direction that the relay cut short. An error from `Wait` or `Done` ends the
  relay and is returned. Hooks shared by both directions or by several relays
  must be safe for concurrent use. A `Wait` that may block for long must
  return when its `ctx` is done: closing a relay's ends does not wake it, so
  end such relays with their context or `WithRelayGroup`.
- `netx.Copy(ctx, dst, src, flow)`, with a zero `RelayFlow` for no hooks,
  copies one direction the same way without closing either end. It returns
  nil at EOF, and once `ctx` is done it sets
  expired deadlines on `src` and `dst` to interrupt a blocked read or write
  and returns `context.Cause(ctx)`.

```go
// forwardMetered relays for one user: limit paces both directions, count
// records what passed, and cancelling ctx ends the user's relays.
func forwardMetered(ctx context.Context, client, backend net.Conn,
	limit func(ctx context.Context, n int64) (int64, error), count func(n int64) error) error {
	flow := netx.RelayFlow{Wait: limit, Done: count}
	_, _, err := netx.Relay(ctx, client, backend, netx.WithRelayFlows(flow, flow))
	return err
}
```

`ExampleWithRelayFlows_limit` in the package documentation shows a complete
limiter for `Wait` and `Done` that many relays can share.

`ConnGroup` closes connections together, such as all of a user's when its
allowance runs out: `remove, err := group.Add(conn)` adds one (`remove` is
called when it is done; a closed group returns `netx.ErrGroupClosed` and
leaves `conn` alone), `CloseMembers(cause)` closes the current members and
keeps the group open, and `Close` also refuses later ones. A connection can
be in several groups, and a group in another, whose `CloseMembers` empties
the inner group without closing it. `netx.WithRelayGroup(groups...)` adds a
relay itself, which the groups then end as its context would, waking a
blocked `Wait`; `Relay` returns `netx.ErrRelayGroupClosed`, which also
matches the cause. `group.Track(conn)` adds a connection and returns it
wrapped so that closing it also removes it, with no `remove` to call; Relay
looks through the wrapper. Hooks such as `RelayFlow.Done` may call
`CloseMembers` themselves.

#### How Relay copies

- On Linux and Android, a direction between two `*net.TCPConn`s, or between a
  `*net.TCPConn` and a `*net.UnixConn`, is left to the kernel with `splice`,
  through a pipe that is held only while data moves, so idle relays hold no
  pipes. Relay looks through `PrefixConn`, `AddrOverrideConn` and
  `TimeoutConn`, refreshing a `TimeoutConn`'s idle deadline itself, but not
  through `ObserveConn` or other wrappers; use `RelayFlow` to count.
- Otherwise a direction is copied with the reading end's `WriteTo` or else
  the writing end's `ReadFrom`, as `io.Copy` would, except those of
  `*net.TCPConn`, whose data goes through a pooled 32 KiB buffer instead. On
  Unix systems a stream read straight from a socket takes that buffer only
  once the socket is readable, so idle relays hold no buffers either, and a
  blocked `Wait` holds none.
- Sources that return one datagram per read (`*net.UDPConn`,
  `PacketListener` connections, `FramedConn` with `WithFramedDatagrams`, and
  connections of other packages whose local address is on a `udp`, `ip` or
  `unixgram` network) get one write per datagram, so no datagram is
  cut short and empty ones are passed on. `PacketListener` connections hand
  their queued datagrams over and `FramedConn`s read each frame into a buffer
  that fits it, so idle UDP relays hold no buffer and each datagram is copied
  once; other datagram sources get a 64 KiB buffer.
- A direction with a `Wait`, `Done` or `First` hook still splices, in pieces
  so that `Done` sees bytes as they pass, but otherwise goes through Relay's
  buffer rather than the ends' own `WriteTo` or `ReadFrom`.

### Dialing the first that connects

`DialFirst` races attempts that may dial in different ways, such as directly
and through a relay or several proxies: it starts them in order, starts the
next whenever one fails or has not connected within the stagger
(`DefaultDialStagger`, 300 ms, if not positive), and closes the connections
that losing attempts still make. It returns the index of the attempt that
won, or the errors of all attempts, joined.

```go
conn, i, err := netx.DialFirst(ctx, 200*time.Millisecond,
	func(ctx context.Context) (net.Conn, error) { return direct.DialContext(ctx, "tcp", peer) },
	func(ctx context.Context) (net.Conn, error) { return relay.DialContext(ctx, "tcp", peer) },
)
```

`DialAny` races one attempt per address of a service, such as the entry
points of a cluster, through one dialer (`nil` for a zero `net.Dialer`):

```go
// addr says which one connected; 0 staggers by DefaultDialStagger.
conn, addr, err := netx.DialAny(ctx, 0, nil, "tcp", "a.example:8024", "b.example:8024")
```

`RaceDialer` races several dialers to one address and is itself a
`netx.ContextDialer`, so it can be an `http.Transport`'s `DialContext` or a
proxy dialer's `Forward`:

```go
d := &netx.RaceDialer{Dialers: []netx.ContextDialer{direct, viaProxy}, Stagger: 200 * time.Millisecond}
transport := &http.Transport{DialContext: d.DialContext}
```

All three return `netx.ErrNoDialAttempts` when there is nothing to dial.

## Listeners

```go
// handOff serves connections that were accepted and routed elsewhere.
func handOff(srv *http.Server) *netx.ChanListener {
	l := netx.NewChanListener(&net.TCPAddr{Port: 443}, 128)
	go func() {
		if err := srv.Serve(l); !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("serve: %v", err)
		}
	}()
	return l
}

func route(ctx context.Context, l *netx.ChanListener, c net.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	if err := l.Deliver(ctx, c); err != nil {
		_ = c.Close() // still ours
		return err
	}
	return nil
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
  `Close` closes it. On failure the caller keeps it, to close or route
  elsewhere; `TryDeliver` queues without waiting.
- `Dial` connects through a synchronous `net.Pipe`. The server end reports the
  given remote address and the listener address; the client end reports the
  reverse.
- `NewSingleConnListener` returns the connection once. Later `Accept` calls
  return `net.ErrClosed` after the connection or the listener is closed. The
  connection belongs to the server once accepted: closing the listener then
  only ends a blocked `Accept` and leaves the connection being served, so stop
  an `http.Server` on it with `Shutdown` or `Close`, or close the connection.
  The accepted connection is a wrapper (unwrap it with `InnermostConn`), so
  for TLS wrap the listener with `tls.NewListener` instead of passing a
  `*tls.Conn`.

### UDP peers

`PacketListener` splits a packet connection, such as a UDP socket, into one
`net.Conn` per peer, so a UDP server can be written like a TCP server.

```go
func serveUDP(pc net.PacketConn, handle func(net.Conn)) error {
	l := netx.NewPacketListener(pc,
		netx.WithPacketIdleTimeout(2*time.Minute),
		// Only datagrams that start like the protocol's first message.
		netx.WithPacketAcceptFilter(func(peer net.Addr, first []byte) bool {
			return len(first) >= 4 && string(first[:4]) == "HELO"
		}),
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
  (`WithPacketQueue`, 128) or the accept backlog (`WithPacketAcceptBacklog`,
  128) is full. A datagram larger than 2 KiB takes the room of several, so a queue
  holds at most 128 × 2 KiB by default however large the datagrams are.
  `WithPacketAcceptFilter` sees a new peer's first datagram and rejects it
  before anything is allocated for the peer; it can answer with
  `l.WriteTo`, as a stateless retry does.
- `l.Dial(peer)` makes a connection to a known peer from the same socket
  without `Accept`, as hole punching needs; it returns
  `netx.ErrPacketPeerConnected` if the peer has one.
- As on a socket, a closed connection or an expired read deadline fails
  `Read` even while datagrams are queued.
- `WithPacketIdleTimeout` closes a connection that has been idle since `Accept`
  returned it; connections still waiting for `Accept` are not closed, and their
  datagrams are kept.
- On a `*net.UDPConn` the read loop, queueing and writes do not allocate per
  datagram up to 2 KiB.
- The listener owns the socket and closes it, and all connections, on `Close`.
- `ListenEphemeralUDP(ctx, lc)` opens a UDP socket on a free port for IPv4 and IPv6, as
  `net.ListenUDP("udp", nil)` does, except that on macOS and iOS it never takes
  a port that another socket holds on one IPv4 address, such as `127.0.0.1`,
  which would receive the replies sent there.

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
		return string(netx.NetErrorKind(err))
	}
}

func logReadError(c net.Conn, err error) {
	if netx.IsTimeout(err) {
		return // idle connection
	}
	// kind=conn_reset err="read tcp ...: connection reset by peer" local=... remote=...
	// timeout=false op=read net=tcp source=... addr=... syscall=read errno=...
	// errno_name=ECONNRESET
	log.Printf("read failed: %s", netx.NetErrorDetails(err, c))
}
```

The classifiers check the platform errno first, so they work whatever the
system language is. On Windows this includes the Winsock codes (`WSAECONNRESET`,
`WSAETIMEDOUT`, ...), which the `syscall.E*` constants do not match. Errors that
only carry text fall back to well-known English messages. Besides the
classifiers above there are `IsConnReset`, `IsConnAborted`, `IsBrokenPipe`,
`IsAddrInUse`, `IsAddrNotAvailable`, `IsMessageTooLarge` and `IsClosed`, which
reports `net.ErrClosed`, `io.ErrClosedPipe` and the "use of closed network
connection" text that ends an accept or read loop. `NetErrorKind` returns an
`ErrorKind` constant named after the classifier that matches (`KindConnReset`,
`KindTimeout`, ..., `KindEOF`, `KindOther`), for metrics. Failed name
lookups are `KindDNS` (`IsDNSError`, and `IsDNSNotFound` for names that do
not exist), not unreachable, and canceled contexts and operations are
`KindCanceled` (`IsCanceled`). `NetErrorDetails`
returns that information as fields, for structured logs, and its `String`
formats them as the line above; `errno_name`/`ErrnoName` are given only for errnos the classifiers
recognise, others appear as the number alone.

## PROXY Protocol

`github.com/djylb/netx/proxyproto` builds, decodes and serves the PROXY protocol
headers that tell a backend the original client and destination of a proxied
connection or UDP flow. It depends only on the standard library and not on the
`netx` root package, so importing it adds no more than the header code.

```go
func sendProxyHeader(backend, client net.Conn) error {
	// client.RemoteAddr() is the source, client.LocalAddr() the destination.
	h, err := proxyproto.HeaderFromConn(proxyproto.V2, client)
	if err != nil {
		return err // an address pair the protocol cannot carry
	}
	_, err = h.WriteTo(backend) // one Write
	return err
}

// behindLoadBalancer reports the client addresses sent by trusted balancers
// and passes other peers' connections through untouched.
func behindLoadBalancer(ln net.Listener, balancers ...netip.Prefix) net.Listener {
	return &proxyproto.Listener{Listener: ln, PolicyFor: proxyproto.TrustPrefixes(balancers...)}
}

// sniffed reads the header of a connection accepted and routed elsewhere,
// and finds it again beneath a TLS layer.
func sniffed(raw net.Conn, cfg *tls.Config) (*tls.Conn, *proxyproto.Header, error) {
	tc := tls.Server(proxyproto.NewConn(raw, proxyproto.Config{Policy: proxyproto.Optional}), cfg)
	h, err := proxyproto.HeaderOf(tc) // nil, nil when the peer sent none
	return tc, h, err
}

// udpBehindProxy reads the header from the first datagram of each UDP flow.
func udpBehindProxy(pc net.PacketConn) net.Listener {
	return &proxyproto.Listener{
		Listener: netx.NewPacketListener(pc),
		Config:   proxyproto.Config{Datagram: true},
	}
}
```

- `NewHeader(version, src, dst)` builds a header from two addresses, and
  `HeaderFromConn` from a connection's; both return an error for a pair the
  protocol cannot carry, such as a nil source, addresses of other types or a
  TCP/UDP mix, rather than a header that would attribute the connection to
  the proxy. `Header.WriteTo` sends a `Header` with one `Write`, and
  `Header.AppendBinary` encodes it into a buffer, including version 2 TLVs
  and AF_UNIX addresses. When a pair cannot be sent, `Header{Version: v}`
  sends a header without addresses (v1 `PROXY UNKNOWN`, v2 `AF_UNSPEC`, TLVs
  allowed), and `Header{Version: v, Local: true}` gives `LOCAL` for a proxy's
  own connections.
- Version 2 TLVs carry an application's own fields in the custom types
  `TLVCustomMin` to `TLVCustomMax` (0xE0–0xEF), such as who a connection
  belongs to: `h.TLVs, err = h.TLVs.Append(proxyproto.TLVCustomMin, id)`, and
  `Header.TLV` reads them back. They are as trustworthy as the peer that sent
  them, so take them from trusted peers only.
- `Decode` decodes a header at the start of a byte slice and returns it with
  its length, `ErrNoHeader` when there is none and `io.ErrUnexpectedEOF`
  while it is incomplete, for protocol sniffers.
- Decoding accepts non-standard senders wherever that cannot misattribute a
  connection: v1 lines ending in a bare LF, with runs of spaces, any letter
  case, `UDP4`/`UDP6` tokens, families that differ from the token or padded
  ports; any v2 version nibble. Unknown commands, protocols and families,
  short address blocks and truncated TLVs fall back to the connection's own
  addresses, or to the whole TLVs, instead of failing.
- `Listener` reads the header lazily, on the first read or address query, with
  a timeout (`DefaultHeaderTimeout`), so a slow peer cannot stall `Accept`. The
  read that reaches the timeout returns it; later ones return an error matching
  `ErrNoHeader` that is not a timeout, so loops that retry timeouts do not
  spin. Its `Config` (`Policy`, `HeaderTimeout`, `Datagram`) applies to every
  accepted connection; `Config.Policy` is `Required` (the default),
  `Optional` or `Ignore`, and `PolicyFor`, when set, picks the policy per
  peer instead. Only trusted peers should be allowed to send a header:
  `PolicyFor: proxyproto.TrustPrefixes(...)` requires one from peers in the
  given networks and ignores the rest. `NewConn` does the same for one
  connection accepted elsewhere, such as a multiplexed stream, and `HeaderOf`
  finds the header beneath wrappers with a `NetConn` method.
- Writes do not wait for the header: under `Required` and `Optional`, a
  server that speaks first, or one that answers a bad request (an HTTP
  server's 400), writes to a peer that may have sent no header or a malformed
  one. When that matters, call `Header()` (or read) first and write only
  once it succeeds.
- With `Config.Datagram` set, for listeners such as `netx.PacketListener` whose reads
  return one datagram, the header is taken from the first datagram of each
  flow, alone or followed by payload; later datagrams are passed through
  untouched. Addresses are reported as `*net.UDPAddr`, since UDP senders use
  the v1 `TCP4`/`TCP6` tokens or a v2 `STREAM` transport; `Header.UDPAddrs`
  does the same conversion for other callers. Leave it unset for stream
  protocols over UDP such as KCP or QUIC.
- A nil or unspecified target is sent as `0.0.0.0` or `::`, matching the
  client's address family. An IPv4/IPv6 pair is sent as `TCP6`
  (v1) or `AF_INET6` (v2), with the IPv4 side in its IPv4-mapped form
  `::ffff:a.b.c.d`. v1 has no UDP token, so UDP pairs are written with
  `TCP4`/`TCP6`; use v2 to mark them as `DGRAM`.

## Transparent Proxying

`github.com/djylb/netx/transparent` listens for connections that firewall
rules redirect to a local port and recovers where they were going.

```go
func serve(ctx context.Context, handle func(c net.Conn, target netip.AddrPort)) error {
	ln, err := transparent.Listen(ctx, "tcp", "0.0.0.0:8080")
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		dst, redirected, err := transparent.OriginalDestination(c)
		// A connection made to the listener directly would connect the
		// proxy to itself, again and again.
		if err != nil || !redirected {
			_ = c.Close()
			continue
		}
		go handle(c, dst)
	}
}
```

| Platform       | `Listen` / `Control`                                             | `OriginalDestination`                                              |
|----------------|------------------------------------------------------------------|--------------------------------------------------------------------|
| Linux, Android | sets `IP_TRANSPARENT`/`IPV6_TRANSPARENT` (needs `CAP_NET_ADMIN`) | `SO_ORIGINAL_DST` (REDIRECT/DNAT), else the local address (TPROXY) |
| FreeBSD        | sets `IP_BINDANY`/`IPV6_BINDANY`                                 | pf `DIOCNATLOOK`, else the local address                           |
| macOS, iOS     | nothing (pf `rdr` needs no socket option)                        | pf `DIOCNATLOOK` (needs root)                                      |
| Others         | `ErrListenUnsupported`                                           | `ErrOriginalDestinationUnsupported`                                |

`OriginalDestination` also reports whether the connection was redirected. A
destination on another port than the connection's local one was redirected.
One on the same port was redirected unless it is an address of this host:
Linux asks the routing table through the socket's bound device, such as a
VRF, and counts IPv6 anycast as local; FreeBSD and macOS bind the address. A
direct connection to the listener therefore reports its own address and
`false`, and so do a NAT that maps another address of this host to the
listener's own port and TPROXY delivering a connection for an address of this
host. A wrapper beneath which no socket can be reached is an error rather
than trusting its addresses. Lookup failures, such as a closed connection or no
permission to read `/dev/pf`, are returned as errors. Both unsupported errors
match `errors.ErrUnsupported`. For a plain listener use `net.Listen`.
`OriginalDestination` looks through wrappers such as `netx.TimeoutConn` with
`netx.InnermostConn`, so it can be called on a wrapped connection.

`Listen` is a `net.ListenConfig` whose `Control` is `transparent.Control`.
To combine the transparent options with your own, such as `SO_REUSEPORT`,
`SO_MARK` or keep-alive settings, call it from your own `Control`; on a
`net.Dialer` it lets a socket bind an address that is not local:

```go
lc := net.ListenConfig{
	KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second},
	Control: func(network, address string, c syscall.RawConn) error {
		if err := transparent.Control(network, address, c); err != nil {
			return err
		}
		return setReusePort(c) // your own options
	},
}
ln, err := lc.Listen(ctx, "tcp", "0.0.0.0:8080")
```

`transparent.ControlPacket` does the same for UDP and also asks for each
datagram's original destination.

On Linux and Android, `ListenPacket`, `ReadFromUDP` and `DialUDP` handle UDP
redirected by TPROXY. `ListenPacket` is a `net.ListenConfig` with
`transparent.ControlPacket` as its `Control`. `ReadFromUDP` returns, with the
datagram's length, a `PacketInfo`: its source `Src`, its original destination
`Dst`, and `Redirected`, false for a datagram sent straight to the listener,
which must not be relayed back to it. `DialUDP` opens a socket bound to `Dst`
to answer from it.

A datagram for another port, or for another address when the listener is
bound to one, was redirected. On a wildcard listener's own port the
destination is looked up as for TCP; addresses found local are remembered for
a minute. Listening on a port that redirected traffic does not use avoids the
lookup, and `DialUDP` needs it anyway.

```go
func serveRedirectedUDP(ctx context.Context) error {
	ln, err := transparent.ListenPacket(ctx, "udp", "0.0.0.0:8080")
	if err != nil {
		return err
	}
	buf := make([]byte, 65535)
	for {
		n, info, err := transparent.ReadFromUDP(ln, buf)
		if errors.Is(err, transparent.ErrControlTruncated) {
			continue // this datagram's destination is unknown
		}
		if err != nil {
			return err
		}
		if !info.Redirected {
			continue // sent to the listener itself
		}
		reply, err := transparent.DialUDP(ctx, info.Dst, info.Src)
		if err != nil {
			continue
		}
		_, _ = reply.Write(buf[:n])
		_ = reply.Close()
	}
}
```

`ListenUDPFlows` does the flow keeping instead: its `FlowListener` accepts
one `*FlowConn` per source and original destination. Each `Read` returns one
of the flow's datagrams, and `Write` answers the source from the original
destination through a `DialUDP` socket that the first `Write` opens and
`Close` closes; the source's later datagrams arrive on that socket and are
read from the flow like the first. `RemoteAddr` is the source and `LocalAddr`
the original destination. Datagrams sent straight to the listener are dropped
unless `WithFlowDirect` is given; `FlowConn.Redirected` then tells them apart,
and they are answered from the listener. `WithFlowIdleTimeout`,
`WithFlowQueue` and `WithFlowAcceptBacklog` bound idle flows, queued
datagrams and flows waiting for `Accept`; set an idle timeout for traffic
from untrusted sources. `NewFlowListener` builds one on a socket of your own
set up with `ControlPacket`.

```go
func forwardUDPFlows(ctx context.Context) error {
	l, err := transparent.ListenUDPFlows(ctx, "udp", "0.0.0.0:8080",
		transparent.WithFlowIdleTimeout(time.Minute))
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			var d net.Dialer
			upstream, err := d.DialContext(ctx, "udp", c.LocalAddr().String())
			if err != nil {
				_ = c.Close()
				return
			}
			_, _, _ = netx.Relay(ctx, c, upstream)
		}()
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
	dst, n, err := socks5.DecodeDatagram(packet)
	if err != nil {
		return nil, err
	}
	from, answer := exchange(dst.String(), packet[n:])
	return socks5.AppendDatagram(nil, socks5.AddrFromNetAddr(from), answer)
}
```

- `Addr` holds an IP address (`netip.Addr`) or a domain name, and a port.
  IPv4-mapped addresses are sent as IPv4, zones are dropped, and the zero
  `Addr` is sent as `0.0.0.0:0`.
- `ReadReply` returns a `*socks5.ReplyError` for a reply other than
  `ReplySucceeded`. `DecodeAddr` decodes an address embedded in another
  message. `DecodeDatagram` returns the address and the header length (the
  payload is `packet[n:]`), rejects fragments with `ErrFragmented` and
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

`Handshake(ctx, conn, cmd, dst)` runs the client handshake on a connection
you already have and returns the bound address of the reply; `DialContext`
is `Forward` plus `Handshake`.

`ListenPacket` opens a UDP association (SOCKS5 only). The returned
`*socks5.UDPConn` sends with `WriteTo(payload, dst)` and receives with
`ReadFrom`, accepting datagrams only from the proxy's relay. Closing it ends
the association, and the proxy closing the control connection closes it.
`AsNetPacketConn` adapts it to `net.PacketConn` for code that sends to and
receives from `net.Addr` (`*net.UDPAddr` for IP sources, a `socks5.Addr` for
names). Because it is a `socks5.PacketConn`, a `Server` can relay UDP through
another proxy:

```go
s := &socks5.Server{
	UDPSocket:  udp,
	DialPacket: func(ctx context.Context, _ *socks5.Request) (socks5.PacketConn, error) {
		return upstream.ListenPacket(ctx)
	},
}
```

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
		UDPSocket: udp, // one fixed UDP port for every association
	}
	return s.Serve(ln)
}
```

- Hooks: `Auth` (any `Authenticator`), `Allow`, `Dial` (its error picks the
  reply code through `ReplyFor`), `ConnectAddr`, `Relay` (it copies between
  `req.Conn` and the target; by default
  `netx.Relay` with `WithRelayHalfClose`, so a client that shuts down its sending
  side still gets the reply; a half-closed connection then lasts until the
  other side finishes or closes too, so relay through `netx.NewTimeoutConn` to
  bound idle ones; `RelayOptions` adds `netx.RelayOption`s such as
  `WithRelayFlows` per `req.User` to that default relay), `Handle` (serves
  commands of its own, such as BIND, inside `Serve`, see below), and for UDP
  `DialPacket` (the outbound side, a `socks5.PacketConn` that receives domain
  names unresolved, for example to forward through a tunnel), `AllowPacket`
  and `UDPAddr` (the address advertised to clients).
- `Allow` and `AllowPacket` see every IP address a client sends in
  `Dst.IP`, including IPv4-mapped IPv6 addresses and domain names that are IP
  literals, also with one trailing dot such as `127.0.0.1.`. Other names
  arrive unresolved, so an IP policy must also check the resolved address
  where `Dial` or `DialPacket` resolves it, for example with a `net.Dialer`
  `Control` function: some resolvers accept forms such as `127.1`. The
  unspecified addresses `0.0.0.0` and `::` reach the server's own host on
  many systems.
- UDP on a fixed port (`UDPSocket`): datagrams must come from the IP address
  of their association's control connection, so a client cannot claim the
  datagrams of others. Among the associations of that IP waiting for their
  first datagram, a source goes to the one that announced its port, else to
  the only one that announced no port, else to the only one; ambiguous
  sources are dropped. An announced port counts at the control connection's
  IP whatever address comes with it, as clients behind a NAT announce their
  private address and clients that do not know theirs announce `0.0.0.0` or a
  name; a client that announces the control connection's own address and a
  port gets datagrams from that exact source alone. A control connection
  without an IP address, such as a tunneled stream, must announce the
  client's IP address, or the request is refused; nothing proves that
  announcement, so such a client can claim the datagrams of any IP address,
  and only trusted clients may reach `UDPSocket` that way. `ListenUDP`
  instead gives each association its own socket, which without a known
  client IP takes the first source that sends; use it for untrusted tunneled
  clients.
  Replies from any source are relayed (full cone), and a reply that cannot be
  delivered is reported to `OnError` and dropped. An association ends with its
  control connection, or after `UDPIdleTimeout`, which closes the control
  connection; `UDPOutlivesControl` keeps it for clients that close the control
  connection early.
- `OnError` receives the errors that end connections and drop datagrams, for
  logging; the package itself does not log. A refused request is reported as
  a `*socks5.ReplyError` holding both the reply sent and its cause in `Err`
  (`socks5: connection not allowed by ruleset: no mail`).
- `UserPassAuth.Check(ctx, conn, user, password) (ok, err)` sees the
  connection for per-address rules; an error, such as an unreachable account
  backend, rejects the client and is returned instead of `ErrAuthFailed`.
  `Credentials` builds one from a fixed account map, comparing SHA-256
  digests in constant time so that timing reveals neither password lengths
  nor which users exist.
- Custom commands: set `Handle`, which runs after `Allow` and before the
  built-in commands; returning `handled` true, or having replied at all,
  means it served the request with `req.Reply` and `req.Conn`, and the
  connection still counts for `Shutdown` and `ActiveConns`. To drive the steps yourself,
  `Handshake(ctx, conn)` runs the negotiation,
  authentication and request read, also for SOCKS4, and returns the
  `*socks5.Request` without replying. Answer it with `req.Reply(code, bound)`,
  which writes SOCKS4 or SOCKS5 as the client spoke, once, or twice for BIND
  (the listening address, then the peer's; a failure reply is the last), and use
  `req.Conn`, which includes any bytes the client sent right after a SOCKS4
  request. Or hand it to `ServeRequest`, which runs `Allow`, serves CONNECT
  and UDP ASSOCIATE, and answers other commands with
  `ReplyCommandNotSupported`. `ServeConn(ctx, conn)` is the two in sequence,
  and ends the connection when ctx ends; `Serve` passes a context that `Close`
  cancels.
  `Request.User` is the authenticated identity; `Request.UserID4` is the
  unauthenticated SOCKS4 user ID.
- `Shutdown(ctx)` closes the listeners and waits for the connections being
  served, including UDP control connections, then calls `Close`; when ctx
  ends first, `Close` ends the rest. `ActiveConns` reports how many
  connections `Serve` and `ServeConn` are serving.
- The server runs over any `net.Conn`. For SOCKS over TLS, serve
  `tls.NewListener(ln, cfg)`: the TLS handshake happens within
  `HandshakeTimeout`. UDP ASSOCIATE then has a TLS control connection, and its
  datagrams stay plain UDP. To share a port with HTTP or TLS, sniff the first
  byte (5 for SOCKS5, 4 for SOCKS4, 0x16 for a TLS handshake) and pass SOCKS
  connections to `ServeConn(ctx, conn)`, after `tlsconn.Server` for TLS ones.
- For non-standard clients, a server without required authentication accepts
  an empty or mismatched method list (username/password with any
  credentials), and reserved bytes and the username/password version byte are
  not checked. A custom `MethodNoAuth` authenticator, such as an IP allowlist,
  still decides on those clients and on SOCKS4 ones.

## Upstream Proxies

`github.com/djylb/netx/proxydial` dials TCP through an HTTP CONNECT or SOCKS5
proxy. `FromURL` and `FromEnvironment` build the dialers from a URL; they are
plain structs (`HTTPDialer`, `socks5.Dialer`) that can also be configured
directly, for example with a private CA or extra request headers. A program
that only talks to SOCKS5 proxies can use `socks5.Dialer` alone and avoid the
`crypto/tls` that `https` proxies need.

```go
func corporateProxy(ca *x509.CertPool) *proxydial.HTTPDialer {
	return &proxydial.HTTPDialer{
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
	var d netx.ContextDialer
	if proxyURL != "" {
		u, err := proxydial.ParseURL(proxyURL) // also bare host:port, as http
		if err != nil {
			return nil, err
		}
		if d, err = proxydial.FromURL(u, forward, nil); err != nil {
			return nil, err
		}
	} else {
		var err error
		if d, err = proxydial.FromEnvironment(forward, nil); err != nil {
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
  against the proxy's host name. User information becomes the dialer's
  `Username` and `Password`: Basic `Proxy-Authorization` (unless `Header`
  sets that field, which then wins), SOCKS5 username/password or the SOCKS4
  user ID.
  The SOCKS5 and SOCKS4a schemes let the proxy resolve host names; `socks4`
  resolves them locally. A dialer for one proxy can be the `Forward` dialer of
  another, which chains them.
- `FromURL` and `FromEnvironment` take a `*tls.Config` for `https` and `+tls`
  proxies: `nil` verifies the proxy's host name against the system roots, and
  a config without `ServerName`, such as one carrying a private CA, is cloned
  with the proxy's host filled in. `FromURL` returns an `*proxydial.HTTPDialer`
  or a `*socks5.Dialer`; type-assert it to adjust fields such as `Header`.
- `ParseURL` parses a proxy URL leniently: `proxy:3128` or `127.0.0.1:1080`
  without a scheme is an `http` proxy, and its errors never quote the
  password.
- A refused CONNECT is a `*proxydial.ConnectError` with the status code, status
  text and reply header, so a caller can answer a `407` challenge from
  `Proxy-Authenticate` or tell `403` from `502`.
- `HTTPDialer.Handshake` runs CONNECT on a connection the caller already has
  to the proxy, such as a multiplexed stream. It returns that connection, or
  a `netx.PrefixConn` over it when the proxy sent tunnel bytes with its reply,
  and leaves the connection open on failure.
- The dialers also have a `Dial(network, address)` method, for code that
  expects a dialer without a context.
- The context bounds the dial and the proxy handshake; the returned connection
  has no deadline. Bytes the HTTP proxy sends right after its `2xx` reply are
  kept.
- `FromEnvironment` reads `ALL_PROXY` only, with `NO_PROXY`, not
  `HTTP_PROXY` or `HTTPS_PROXY`: a TCP dialer does not know whether its target
  speaks HTTP or HTTPS, so HTTP clients should use `http.ProxyFromEnvironment`
  for those. `ALL_PROXY` is parsed with `ParseURL`, and targets in `NO_PROXY`
  bypass the proxy: `*`, IP addresses (IPv6 with or without brackets), CIDR
  ranges, and domain names, which also match their subdomains (a leading `.`
  or `*.` matches subdomains only). An entry may end in `:port`.
- `FromEnvironment` returns the direct dialer when `ALL_PROXY` is unset,
  `FromURL`'s dialer when `NO_PROXY` is empty, and otherwise a
  `*proxydial.Bypass`, whose `Proxy` field holds `FromURL`'s dialer
  (`b.Proxy.(*proxydial.HTTPDialer)` to set `Header`). `Bypass` and
  `ParseNoProxy` also work with other dialers.
