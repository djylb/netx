# netx

Reusable Go networking helpers with no third-party dependencies; the one
module they use is [timeshim](https://github.com/djylb/timeshim), an
injectable clock that itself uses only the standard library.

Requires Go 1.26. Every package builds on all major Go ports, including
Windows, the BSDs, js/wasm, wasip1 and Plan 9. Platform-specific features
return an error matching `errors.ErrUnsupported` where they are not available.

| Package                               | Contents                                                                          |
|---------------------------------------|-----------------------------------------------------------------------------------|
| `github.com/djylb/netx`               | conn wrappers, `Relay`, `ConnGroup`, in-memory/UDP listeners, error helpers       |
| `github.com/djylb/netx/duplex`        | a read half and a write half as one `net.Conn`, with half-closes and hot swaps    |
| `github.com/djylb/netx/tlsconn`       | bounded TLS handshakes, TLS over any dialer, certs, pins, uploaded-cert checks    |
| `github.com/djylb/netx/proxyproto`    | PROXY protocol v1 and v2: build, decode, header-reading conn and listener         |
| `github.com/djylb/netx/transparent`   | transparent-proxy listeners (TCP, Linux TPROXY UDP), original destinations        |
| `github.com/djylb/netx/socks5`        | SOCKS5 and SOCKS4 codec, client dialer and a configurable server                  |
| `github.com/djylb/netx/httpproxy`     | HTTP proxy server: CONNECT tunnels and request forwarding                         |
| `github.com/djylb/netx/httphead`      | HTTP/1.x head reader and parser: fields, body framing, request targets            |
| `github.com/djylb/netx/forwarded`     | real client address behind trusted proxies: X-Forwarded-For, X-Real-IP, Forwarded |
| `github.com/djylb/netx/httprewrite`   | header templates and rules for reverse proxies, redirect rewriting                |
| `github.com/djylb/netx/wsconn`        | WebSocket: handshakes, messages, stream `net.Conn`, permessage-deflate            |
| `github.com/djylb/netx/wsconn/wshttp` | WebSocket for `net/http` handlers, also over HTTP/2                               |
| `github.com/djylb/netx/proxydial`     | dialing through HTTP(S), SOCKS5 and SOCKS4 proxies, `ALL_PROXY`/`NO_PROXY`        |
| `github.com/djylb/netx/safedial`      | dialing and UDP relaying limited by a destination policy, rebinding-safe          |

Each package depends only on the standard library and timeshim, and links only
what it uses.
`crypto/tls` adds a large amount of code to a binary as soon as it is
imported, so only `tlsconn`, `proxydial` (for `https` proxies), and
`httprewrite` and `wsconn/wshttp` (through `net/http`, which programs that use
them link anyway) import it; the root package, `duplex`, `proxyproto`,
`transparent`, `socks5`, `httpproxy`, `httphead`, `forwarded`, `wsconn` and
`safedial` stay small.
`forwarded` does not import `net/http`: it takes a header as the
`map[string][]string` that `http.Header` is.

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
  handshake; a positive `HandshakeTimeout` also bounds the handshake, and a
  negative one leaves the context alone to bound it, without the
  `DefaultHandshakeTimeout` fallback. Used as a proxy dialer's `Forward`, it
  reaches the proxy over TLS.

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

// reloading serves one certificate from files, picking up a renewal once
// the files change.
func reloading() *tls.Config {
	var certs tlsconn.CertFiles
	return &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certs.LoadFiles("/etc/certs/fullchain.pem", "/etc/certs/privkey.pem")
	}}
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

#### Checking uploaded certificates

For servers that take certificates from users, `tlsconn` parses and checks
them, tells which names they cover, and has the user prove that they hold
the private key:

```go
// claim checks an uploaded certificate and key against roots and returns
// the names, of those the user asks for, that it covers. The user must still
// prove possession of the key before getting them.
func claim(certData, keyData []byte, roots *x509.CertPool, domain string, asked []string) (tls.Certificate, []string, error) {
	cert, err := tlsconn.ParseKeyPair(certData, keyData)
	if err != nil {
		return tls.Certificate{}, nil, err // ErrKeyMismatch, ErrEncryptedKey, ...
	}
	chain := []*x509.Certificate{cert.Leaf}
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, nil, err
		}
		chain = append(chain, c)
	}
	// Fails unless the certificate covers domain itself: ErrOnlySubdomains
	// for one that covers only names under it, ErrExpired, ErrSelfSigned, ...
	coverage, err := tlsconn.VerifyDomain(chain, domain, tlsconn.VerifyOptions{Roots: roots})
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	var granted []string
	for _, name := range asked {
		if coverage.Covers(name) { // each name exactly, never the subtree
			granted = append(granted, name)
		}
	}
	return cert, granted, nil
}

// prove has the user sign a challenge with the certificate's key.
func prove(challenger *tlsconn.Challenger, leaf *x509.Certificate, userKey crypto.Signer) error {
	const purpose = "claim example.com for user 42"
	challenge, err := challenger.Challenge(purpose) // sent to the user
	if err != nil {
		return err
	}
	sig, err := tlsconn.SignPossession(userKey, purpose, challenge) // on the user's side
	if err != nil {
		return err
	}
	return challenger.Verify(leaf.PublicKey, purpose, challenge, sig)
}
```

- `ParseKeyPair` takes the chain, leaf first, as PEM (text around the blocks,
  such as OpenSSL's attributes, and other block types are skipped) or DER,
  and one private key in PKCS #1, PKCS #8 or SEC 1 form (RSA, ECDSA,
  Ed25519); both may be in one file. It checks that the key's public key
  equals the leaf's and returns a `tls.Certificate` with its `Leaf` set.
  `ParseCertificates`, `ParsePrivateKey` and `MatchKey` do the steps alone.
  Errors are typed: `ErrNoCertificates`, `ErrInvalidCertificate`,
  `ErrNoPrivateKey`, `ErrMultipleKeys`, `ErrEncryptedKey`, `ErrInvalidKey`,
  `ErrUnsupportedKey` and `ErrKeyMismatch`. Bound the upload's size before
  parsing.
- `VerifyChain` (or `VerifyCertificate` for a `tls.Certificate`) verifies the
  leaf against `Roots`, with the rest of the
  uploaded chain, in any order, as intermediates, at `Time` (zero for now),
  for `KeyUsages` (server authentication by default). Uploaded certificates
  are never trusted as roots. Its errors tell apart `ErrExpired`,
  `ErrNotYetValid`, `ErrSelfSigned` (which also matches
  `ErrUnknownAuthority`), `ErrUnknownAuthority`, `ErrKeyUsage` and
  `ErrInvalidChain`. `IsSelfSigned` checks one certificate.
- **Set `Roots` for uploaded certificates**, such as a CA bundle loaded with
  `AppendCertsFromPEM`. With nil `Roots`, Windows, macOS and iOS hand the
  chain to the platform verifier, which may fetch the issuer URLs
  (Authority Information Access) named in the certificate, so an uploader
  could make the server send requests to hosts of their choosing, internal
  ones included. An explicit pool runs the Go verifier, which fetches
  nothing. `x509.SystemCertPool()` does not avoid this: on those systems it
  holds no certificates and delegates to the platform verifier too.
- `Covers(cert, name)` and `CertNames(cert)` follow RFC 6125 and RFC 9525:
  only subject alternative names count, never the common name; a DNS name
  covers itself; `*.example.com` covers `a.example.com`, but neither
  `example.com` nor `a.b.example.com`; wildcards must be the whole leftmost
  label over a base of two labels or more, so `*.com`, `f*.example.com` and
  `a.*.example.com` cover nothing (and are listed in `Names.Invalid`); IP
  addresses match IP address names only. Names are compared by
  `CanonicalName`: lowercase, without a trailing dot, international labels
  as A-labels (`bücher.test` is `xn--bcher-kva.test`). `Names.Covers`
  answers by binary search; `Covers` checks a certificate without
  allocating.
- `VerifyDomain(chain, domain, opts)` verifies the chain and requires the
  certificate to cover the domain itself (`Apex`, exactly or by a wildcard
  for its parent, then with `ApexByWildcard`). One that covers only names
  under it, such as `me.example.net` asked about `example.net`, fails with
  `ErrOnlySubdomains`, and one that covers nothing with `ErrNotCovered`;
  both come with the coverage, so accepting subdomains is an explicit choice.
  `Names.Under(domain)` gives the same `DomainCoverage` without checks:
  `Apex`, exact `Subdomains` and `Wildcards`. It is a list of names, never a
  subtree: a certificate for `*.example.com` does not cover `example.com` or
  `a.b.example.com`, and one for `example.com` covers nothing else, so grant
  each name that `DomainCoverage.Covers` reports, not the domain's
  descendants. A self-signed certificate proves nothing about a domain, and
  fails `VerifyDomain` unless the roots trust it.
- A certificate is public, so a user also proves that they hold its key. A
  `Challenger` issues challenges bound to a purpose (the action, the user,
  the domain), each holding its expiry (`TTL`, 5 minutes by default) and 128
  random bits under an HMAC-SHA-256 key of its own, so issuing stores
  nothing. The user signs with `SignPossession`: RSA-PSS with SHA-256,
  ECDSA with SHA-256, SHA-384 or SHA-512 for P-256, P-384 or P-521, or
  Ed25519, over a message with a fixed context, the purpose and the
  challenge, so the signature is good for nothing else. `Verify` checks the
  challenge, its expiry and the signature against the leaf's public key,
  and accepts each challenge once: it keeps accepted ones until they expire,
  at most `MaxUsed` (65536 by default), and fails closed with
  `ErrTooManyChallenges` rather than forget one. Expiry runs on the
  `Challenger`'s own monotonic clock, so setting the wall clock back cannot
  revive a used challenge. Make one with `NewChallenger`; the zero value
  fails with `ErrNoChallenger`. A challenge verifies only on
  the `Challenger` that issued it and not after a restart; servers behind a
  load balancer route answers back, or use `VerifyPossession` with
  challenges kept in their shared store. Rate-limit proofs per user, since any
  self-signed key can make one.
- `Summarize` describes a certificate for display: subject, issuer, serial
  number, names, validity, fingerprint, key type and size, and whether it is
  self-signed or a CA.

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
- `DoWithContext(ctx, c, fn)` bounds I/O on `c` by `ctx`, and clears `c`'s
  deadline when `fn` returns. Like `Peek` and `PeekFull` it leaves `c` open on
  failure, since a read that times out need not end the connection.
  `DoHandshake` is the same for an exchange that `c` is no use without: it
  closes `c` on failure, after `CloseBeneathTLS(c)` when the exchange timed
  out or was canceled, so that a TLS connection sends no `close_notify` the
  peer cannot authenticate. Every handshake of this module follows that rule:
  `tlsconn.Client`, `Server` and `Dialer`, `socks5.Dialer.Handshake` and
  `Server.Handshake`, and `proxydial.HTTPDialer.Handshake` close the
  connection they were given when they fail, and return it, or one over it,
  when they succeed.

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
- `netx.Copy(ctx, dst, src, flow)`, with a nil `*RelayFlow` for no hooks,
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

Exchanges over connections that carry more afterwards, such as an HTTP
request and its response on a kept-alive connection, relay parts of them:

```go
// relayExchange relays a head and a body of n bytes from client to backend,
// and back the response that next returns, leaving both connections open
// for the next exchange when it ends well.
func relayExchange(ctx context.Context, client, backend net.Conn, head []byte, n int64,
	next func() (io.Reader, error), done func() error) error {
	parts := []io.Reader{bytes.NewReader(head), &io.LimitedReader{R: client, N: n}}
	request := &netx.ChainReader{Next: func() (io.Reader, error) {
		if len(parts) == 0 {
			return nil, nil
		}
		p := parts[0]
		parts = parts[1:]
		return p, nil
	}}
	_, _, err := netx.Relay(ctx,
		&netx.RelayEnd{Reader: request, Writer: client, CloseFunc: done},
		&netx.RelayEnd{Reader: &netx.ChainReader{Next: next}, Writer: backend, CloseFunc: done},
		netx.WithRelayHalfClose())
	return err
}
```

- `RelayEnd{Reader, Writer, CloseWriteFunc, CloseFunc}` is an end made of
  parts: Relay reads `Reader` and writes `Writer` as it would as ends of their
  own, and calls the functions instead of closing, which leaves the
  connections open after an exchange that ended well. A relay that stops
  early closes its ends to end blocked reads and writes, so `CloseFunc` must
  close then.
- `ChainReader{Next}` reads parts one after another, asking for the next one
  each time a part ends, so that a body can follow a head that tells its
  length. Relay and `Copy` copy each part as a source of its own.
- An `*io.LimitedReader` over a connection is copied as the connection is,
  splicing at most `N` bytes, so a body of known length moves through the
  kernel while the bytes after it stay unread.

#### How Relay copies

- On Linux and Android, a direction between two `*net.TCPConn`s, or between a
  `*net.TCPConn` and a `*net.UnixConn`, is left to the kernel with `splice`,
  through a pipe that is held only while data moves, so idle relays hold no
  pipes. Relay looks through `PrefixConn`, `AddrOverrideConn`, `TimeoutConn`,
  refreshing its idle deadline itself, and the connections of
  `ConnGroup.Track` and `NewSingleConnListener`, but not through
  `ObserveConn` or other wrappers; use `RelayFlow` to count.
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

`RaceDialer` holds the dialers and stagger of such races. Its `DialContext`
races its dialers to one address, so it is itself a `netx.ContextDialer` and
can be an `http.Transport`'s `DialContext` or a proxy dialer's `Forward`; its
`DialAny` races the addresses of a service, such as the entry points of a
cluster, each through every dialer. The zero `RaceDialer` dials with a zero
`net.Dialer` and `DefaultDialStagger`:

```go
d := &netx.RaceDialer{Dialers: []netx.ContextDialer{direct, viaProxy}, Stagger: 200 * time.Millisecond}
transport := &http.Transport{DialContext: d.DialContext}

// addr says which one connected.
conn, addr, err := (&netx.RaceDialer{}).DialAny(ctx, "tcp", "a.example:8024", "b.example:8024")
```

`DialFirst` without attempts and `DialAny` without addresses return
`netx.ErrNoDialAttempts`.

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
- The zero `ChanListener` is ready, as `NewChanListener(nil, 0)`; the zero
  `SingleConnListener` has no connection and its `Accept` waits for `Close`.
- `netx.Accept(ctx, l)` accepts from any listener, retrying the errors that
  `netx.IsAcceptRetryable` reports, such as running out of file descriptors,
  at once and then with a delay growing from 1ms to 1s; a server loop is
  `for { c, err := netx.Accept(ctx, l); if err != nil { return err }; go serve(c) }`.

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
- `WithPacketMaxConns(n)` caps the connections held at once, accepted or
  waiting; at the cap a new peer's datagram is dropped before the filter runs
  or anything is allocated. Spoofed sources can still fill the cap, so pair
  it with `WithPacketIdleTimeout` and a filter that checks a token.
- `l.Dial(peer)` makes a connection to a known peer from the same socket
  without `Accept`, as hole punching needs; it returns
  `netx.ErrPacketPeerConnected` if the peer has one and
  `netx.ErrPacketConnLimit` at the cap.
- As on a socket, a closed connection or an expired read deadline fails
  `Read` even while datagrams are queued.
- `WithPacketIdleTimeout` closes a connection that has been idle since `Accept`
  returned it; connections still waiting for `Accept` are not closed, and their
  datagrams are kept.
- On a `*net.UDPConn` the read loop, queueing and writes do not allocate per
  datagram up to 2 KiB.
- The listener owns the socket and closes it, and all connections, on `Close`.
  The zero `PacketListener` has no socket: `Accept` waits for `Close`.
- `ListenEphemeralUDP(ctx, lc)` opens a UDP socket on a free port for IPv4 and IPv6, as
  `net.ListenUDP("udp", nil)` does, except that on macOS and iOS it never takes
  a port that another socket holds on one IPv4 address, such as `127.0.0.1`,
  which would receive the replies sent there.

## Addresses

`netx.Addr` is a destination as proxy requests name it: an IP address
(`netip.Addr`) or a host name, and a port. `socks5` and `httpproxy` use it
for request destinations, so one policy serves both.

```go
dst, _ := netx.ParseAddr("LOCALHOST:443") // {Name: "localhost", Port: 443}
ip, _ := netx.ParseAddr("[::ffff:127.0.0.1]:80") // {IP: 127.0.0.1, Port: 80}
fromName := netx.HostAddr("127.0.0.1.", 80)    // {IP: 127.0.0.1, Port: 80}
```

- `HostAddr(host, port)`, `ParseAddr`, `AddrFromAddrPort` and
  `AddrFromNetAddr` normalise: every IP address goes into `IP` in one form,
  IPv4-mapped IPv6 as IPv4 and without a zone, also when it comes as a name
  that is an IP literal or one with a trailing dot; names are lowercased and
  never resolved. A policy on IP addresses must therefore also check where
  names resolve to, in the dialer, since some resolvers read `127.1` or
  `0x7f.0.0.1` as addresses.
- `String` gives `host:port` for `net.Dial`, `Host` the host alone, and the
  zero `Addr` prints as `0.0.0.0:0`.

### Address scopes

`ScopeOf` classifies an IP address by the IANA IPv4 and IPv6 Special-Purpose
Address Registries, and `IsGlobal` reports whether it is globally reachable
unicast:

```go
if !netx.IsGlobal(candidate.Addr()) {
	return // not worth offering to a peer on the Internet
}
switch netx.ScopeOf(addr) {
case netx.ScopePrivate, netx.ScopeShared, netx.ScopeLinkLocal:
	// on the local network or behind carrier-grade NAT
}
```

- Scopes: `ScopeInvalid`, `ScopeUnspecified`, `ScopeLoopback`,
  `ScopeLinkLocal`, `ScopePrivate` (RFC 1918, fc00::/7, 64:ff9b:1::/48),
  `ScopeShared` (100.64.0.0/10), `ScopeMulticast`, `ScopeBroadcast`,
  `ScopeDocumentation`, `ScopeBenchmarking`, `ScopeReserved` and
  `ScopeGlobal`.
- IPv4-mapped addresses are classified as IPv4; zones are ignored. Globally
  reachable entries inside reserved blocks, such as the PCP and TURN anycast
  addresses 192.0.0.9 and 2001:1::1, are global; IPv6 outside 2000::/3 that
  no entry names is reserved.
- 6to4 (2002::/16), Teredo (2001::/32) and NAT64 (64:ff9b::/96) addresses
  are global when the IPv4 addresses they embed are, else reserved.
- It is a table lookup indexed by the first byte: 2–7 ns for most addresses,
  no allocation.

## Clocks

What times out or expires in the background takes a `timeshim.Clock`
(`github.com/djylb/timeshim`), so that tests can move time instead of
waiting for it. `timeshim.Real` is the system clock; `timeshim.NewFake(t)`
returns a clock that moves only by `Advance`, which runs the `AfterFunc`
calls that come due in its own goroutine. A nil `Clock` means
`timeshim.Real`, so the default behaviour does not change.

- `WithRelayClock`, `WithPacketClock` and `transparent.WithFlowClock` time
  the idle timeouts of `Relay`, `PacketListener` and `FlowListener`.
- `socks5.DatagramRelay.Clock` times `IdleTimeout`, and `socks5.Server.Clock`
  the idle timeouts of UDP associations.
- `tlsconn.CertStore.Clock`, `tlsconn.CertFiles.Clock` and
  `tlsconn.ChallengerOptions.Clock` time file checks, refreshes,
  certificate validity and challenge expiry.

Socket deadlines and dial and handshake timeouts stay on the system clock.

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

## Joining halves

`duplex.Join(r, w)` makes a `net.Conn` of any reader and writer, such as the
response and request bodies of one HTTP exchange, two one-way pipes, or
standard input and output, so that code written for connections can use
them:

```go
// over runs proto over one streamed HTTP request to a server that answers
// before the request ends: what proto writes is the request body and what
// it reads the response body.
func over(ctx context.Context, url string, proto func(net.Conn) error) error {
	uplink, body := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, uplink)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	c := duplex.Join(resp.Body, body)
	defer c.Close()
	return proto(c)
}
```

- `CloseRead` stops the read half and `CloseWrite` the write half, with
  their `CloseRead` or `CloseWrite` methods, or else `Close`; `Close` closes
  both. A value that is both halves is closed once, and stays open until
  both directions are closed when it can only be closed whole. Afterwards
  reads or writes in that direction return `net.ErrClosed`.
- Deadlines go to halves with `SetReadDeadline`, `SetWriteDeadline` or
  `SetDeadline`. Setting one for a half without them returns an error
  matching `errors.ErrUnsupported`; the connection does not emulate them,
  since a read that cannot be interrupted would need a goroutine that
  outlives it.
- Addresses come from the halves that have them, else are `duplex`. A nil
  read half reads `io.EOF`, a nil write half fails writes with
  `errors.ErrUnsupported`.
- `WriteTo` and `ReadFrom` hand copies to the halves, so `io.Copy` and
  `netx.Relay` splice between sockets beneath the connection as they would
  between the sockets themselves. Read and Write do not allocate.

A `duplex.Writer` is a write half whose stream can be swapped, and a
`duplex.Reader` a read half that reads one stream after another, for a
stream that its sender moves from one channel to the next, such as from one
upload request to another or to a new connection after a reconnect. The
sender swaps; the receiver only appends each channel as it arrives:

```go
// The sender's uplink: writes go to the current upload.
up := new(duplex.Writer)
if err := up.Swap(ctx, firstUpload); err != nil {
	return err
}
c := duplex.Join(downlink, up)

// Later, from the code that rotates uploads: Swap waits for the write in
// progress, holds back the next ones, switches, and closes the first upload,
// which ends its body for the receiver.
err := up.Swap(ctx, nextUpload)
```

```go
// The receiver: each upload handler appends its body to the session and
// returns once the session has read it. Reads go on from one body to the
// next in order and wait for the next while there is none.
func (s *session) upload(w http.ResponseWriter, r *http.Request) {
	done, err := s.in.Append(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGone)
		return
	}
	select {
	case <-done:
	case <-r.Context().Done():
	}
}
```

- Every `Write` goes whole to one stream, and the old stream gets nothing
  after the swap, so a receiver that reads each channel to its end and then
  the next reads the bytes in the order they were written. The receiver
  must append the channels in the order of the swaps; a sender with several
  goroutines that swap opens each channel and swaps to it under one lock.
- Swap dials nothing: the sender opens the next channel first, while writes
  go on into the old one. When its context ends first, Swap leaves both
  streams as they were.
- The receiver learns of a swap only from the old stream ending, so each
  stream must end cleanly when closed, as a request body or a pipe does. A
  receiver that has not appended the next channel yet loses nothing: the
  sender's writes wait in that channel's transport and reads wait for the
  `Append`, so both sides should bound the wait with deadlines. A sender
  that must know the old channel was read takes that from its transport,
  such as the response to the old upload.
- `Reader` closes each stream it has read to its end and moves on. While it
  has none, reads wait for `Append`, the read deadline or `Close`; after
  `End` they return `io.EOF` once the streams appended before it are read.
  An error other than `io.EOF` is returned and leaves the stream current.
- Both own their streams: `Swap` closes the stream it replaces, and `Close`
  closes the current one, or the ones left. A `Writer` without a stream yet
  holds writes back until the first `Swap`. Deadlines apply to the waits
  and to every stream that has deadline methods.
- Their Read and Write do not allocate, and the plain `Conn` does not pay
  for them. A `Writer` copies through `Write`, so that a copy into it never
  holds up a swap; a `Reader` copies each stream through its own `WriteTo`
  or the destination's `ReadFrom`.

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
  `h.TLVs.Get` reads them back. They are as trustworthy as the peer that sent
  them, so take them from trusted peers only.
- `h.TLVs.SSL()` reads the TLS information a proxy sends (`PP2_TYPE_SSL`):
  the client flags, `Verified()`, and `Version`, `CommonName`, `Cipher`,
  `SigAlg` and `KeyAlg` from its sub-fields; `TLVs.AppendSSL` sends one.
- `h.TLVs = h.TLVs.AppendCRC32C()` adds a CRC32C field, which
  `AppendBinary` fills with the header's checksum. `Decode` and the `Conn`
  verify a CRC32C field that a header carries and fail it with
  `ErrChecksum`, which matches `ErrMalformed`, when it does not match.
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
rules redirect to a local port and recovers where they were going. It
depends only on the standard library and not on the `netx` root package.

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
`OriginalDestination` follows `NetConn` methods down to the socket, through
wrappers such as `*tls.Conn` and `netx.TimeoutConn`, so it can be called on a
wrapped connection.

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
`WithFlowQueue`, `WithFlowAcceptBacklog` and `WithFlowMaxConns` bound idle
flows, queued datagrams, flows waiting for `Accept` and flows held at once,
as the `WithPacket` options of `netx.PacketListener` do; set an idle timeout
and a cap for traffic from untrusted sources. As on a socket, an expired read
deadline fails `Read` even while datagrams are queued. `netx.Relay` and
`netx.Copy` take a flow's queued datagrams whole, copying each once. `NewFlowListener` builds one on a socket of your own
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
func handshake(c net.Conn) (netx.Addr, error) {
	methods, err := socks5.ReadMethods(c)
	if err != nil {
		return netx.Addr{}, err
	}
	if !slices.Contains(methods, socks5.MethodNoAuth) {
		_ = socks5.WriteMethod(c, socks5.MethodNoAcceptable)
		return netx.Addr{}, socks5.ErrNoAcceptableMethod
	}
	if err := socks5.WriteMethod(c, socks5.MethodNoAuth); err != nil {
		return netx.Addr{}, err
	}
	cmd, dst, err := socks5.ReadRequest(c)
	switch {
	case errors.Is(err, socks5.ErrAddrType):
		_ = socks5.WriteReply(c, socks5.ReplyAddrTypeNotSupported, netx.Addr{})
		return netx.Addr{}, err
	case err != nil:
		return netx.Addr{}, err
	case cmd != socks5.CmdConnect:
		_ = socks5.WriteReply(c, socks5.ReplyCommandNotSupported, netx.Addr{})
		return netx.Addr{}, fmt.Errorf("unsupported %v", cmd)
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
	return socks5.AppendDatagram(nil, netx.AddrFromNetAddr(from), answer)
}
```

- Addresses are `netx.Addr` values, an IP address (`netip.Addr`) or a
  domain name, and a port (see [Addresses](#addresses)). `AppendAddr`
  encodes one: IPv4-mapped addresses are sent as IPv4, zones are dropped,
  and the zero `Addr` is sent as `0.0.0.0:0`.
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
is `Forward` plus `Handshake`. On failure it closes the connection, as
`netx.DoHandshake` does, which `netx.CloseBeneathTLS` helps for exchanges of
your own.

`ListenPacket` opens a UDP association (SOCKS5 only). The returned
`*socks5.UDPConn` sends with `WriteTo(payload, dst)` and receives with
`ReadFrom`, accepting datagrams only from the proxy's relay. Closing it ends
the association, and the proxy closing the control connection closes it.
`AsNetPacketConn` adapts it to `net.PacketConn` for code that sends to and
receives from `net.Addr` (`*net.UDPAddr` for IP sources, a `netx.Addr` for
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
			socks5.Credentials(map[string]string{"alice": "secret"}),
		},
		Allow: func(ctx context.Context, req *socks5.Request) error {
			if req.Dst.Port == 25 {
				return &socks5.ReplyError{Reply: socks5.ReplyNotAllowed}
			}
			return nil
		},
		UDPSocket: udp, // one fixed UDP port for every association
	}
	return s.Serve(ln)
}
```

- Hooks: `Auth` (any `Authenticator`), `Allow`, `Dial` (its error picks the
  reply code through `ReplyFor`, and the target's `LocalAddr` is the bound
  address of the reply: wrap the target in `netx.NewAddrOverrideConn` to
  report another), `RelayOptions` (`netx.RelayOption`s for the `netx.Relay`
  between `req.Conn` and the target, such as `WithRelayFlows` per `req.User`,
  `WithRelayGroup` or `WithRelayIdleTimeout`; the relay always half-closes, so
  a client that shuts down its sending side still gets the reply, and a
  half-closed connection then lasts until the other side finishes or closes
  too, unless an idle timeout ends it), `Handle` (serves
  commands of its own, such as BIND, or takes over CONNECT, inside `Serve`,
  see below), and for UDP `DialPacket` (the outbound side, a
  `socks5.PacketConn` that receives domain names unresolved, for example to
  forward through a tunnel), `AllowPacket` and `UDPAddr` (the address
  advertised to clients).
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
  clients. `socks5.ListenAssociationUDP` is such a `ListenUDP`, on the
  address the client reached the server at.
  Replies from any source are relayed (full cone), and a reply that cannot be
  delivered is reported to `OnError` and dropped.
  Datagrams to names do not hold up the others while the names are looked
  up (see `NewPacketConn`). An association ends with its
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
  `Credentials` builds a `UserPassAuth` for a fixed account map, comparing SHA-256
  digests in constant time so that timing reveals neither password lengths
  nor which users exist.
- Custom commands: set `Handle`, which runs after `Allow` and before the
  built-in commands; returning `handled` true, or having replied at all,
  means it served the request with `req.Reply` and `req.Conn`, and the
  connection still counts for `Shutdown` and `ActiveConns`. To drive the steps yourself,
  `Handshake(ctx, conn)` runs the negotiation,
  authentication and request read, also for SOCKS4, and returns the
  `*socks5.Request` without replying, or closes `conn` when it fails. Answer it with `req.Reply(code, bound)`,
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
- `ListenAndServe(addr)` listens on a TCP address (`:1080` when empty) and
  runs `Serve`, which retries temporary `Accept` errors as `netx.Accept` does.
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

### UDP relay

`socks5.DatagramRelay` relays UDP ASSOCIATE datagrams (RFC 1928 section 7
headers) between a stream that carries them one per message, such as a
`netx.FramedConn` made with `netx.WithFramedDatagrams` over a tunnel, and a
`socks5.PacketConn` that sends them on. It is the UDP half of a server
whose clients reach it through such a stream, for example the egress end of
a tunnel:

```go
func serveUDPTunnel(ctx context.Context, tunnel net.Conn) error {
	udp, err := netx.ListenEphemeralUDP(ctx, nil)
	if err != nil {
		_ = tunnel.Close()
		return err
	}
	r := &socks5.DatagramRelay{
		Allow:       func(dst netx.Addr) bool { return dst.Port != 25 },
		IdleTimeout: 3 * time.Minute,
	}
	framed := netx.NewFramedConn(tunnel, netx.WithFramedDatagrams(), netx.WithFramedReadBuffer(16<<10))
	return r.Relay(ctx, framed, socks5.NewPacketConn(udp))
}
```

- Each datagram read from the stream is decoded and its payload sent to its
  destination; each reply is written back with one `Write`, headed by its
  source. With a `NewPacketConn` egress, one socket sends everything, so the
  relay behaves as a full-cone NAT: every destination sees the same source
  address and port, and replies from any address and port are delivered,
  including from peers that were never sent to.
- Datagrams with a fragment number other than 0 are dropped (fragmentation is
  not supported), as are truncated ones and ones longer than any UDP datagram
  (`ErrDatagramTooLarge`); `OnError` receives the reason. A failed send, or a
  reply the stream does not take, is reported and dropped without ending the
  relay.
- Hooks: `Allow` (drop by destination; names arrive unresolved), `Sent` and
  `Received` (destination or source and payload length, for counting),
  `OnError` and `IdleTimeout` (ends with `netx.ErrRelayIdle`).
- `Relay` returns when `ctx` ends (`context.Cause(ctx)`), when the stream
  reaches EOF or either side is closed (`nil`), on an error of either side,
  or when idle, and it closes both sides. Each direction reuses one buffer;
  datagrams to IP addresses are relayed without copying or allocating.
- `socks5.Server` serves its UDP associations with the same relay.

`NewPacketConn` resolves names without blocking `WriteTo`: a datagram to a
name that is not cached is held while the name is looked up and then sent,
in order with the later datagrams to that name, while datagrams to other
destinations pass meanwhile. Results are cached for a minute and failures
for five seconds, which `WriteTo` then reports. Up to 64 names are looked
up at once, each holding up to 16 datagrams and 256 KiB in all; datagrams
beyond that are dropped with `ErrLookupBusy`, as a full socket buffer would
drop them. Replies always carry the IP address they came from.

## HTTP Proxy

`github.com/djylb/netx/httpproxy` is an HTTP/1.x proxy server. It serves
`CONNECT` with a tunnel, and forwards requests for absolute `http` URIs
(`GET http://example.com/ HTTP/1.1`), streaming bodies both ways, with
several requests per client connection, also to different hosts, over
connections to targets that it keeps for later requests. On Linux, tunnels
and bodies of a known length are spliced. It parses HTTP with `httphead`
rather than `net/http`, which would add about 1.7 MB and `crypto/tls` to a
program (linux/amd64, stripped).

```go
func runHTTPProxy(ln net.Listener) error {
	s := &httpproxy.Server{
		Auth: []httpproxy.Authenticator{
			httpproxy.Credentials(map[string]string{"alice": "secret"}),
		},
		Allow: func(ctx context.Context, req *httpproxy.Request) error {
			if req.Dst.Port == 25 {
				return &httpproxy.StatusError{Code: 403}
			}
			return nil
		},
		RelayOptions: func(*httpproxy.Request) []netx.RelayOption {
			return []netx.RelayOption{netx.WithRelayIdleTimeout(5 * time.Minute)}
		},
	}
	return s.Serve(ln)
}
```

- `Server` has the shape of `socks5.Server`, so that one policy serves both
  on one port: the hooks `Auth`, `Allow`, `Handle`, `Dial`, `RelayOptions`
  and `OnError` have the same signatures over `*httpproxy.Request`, whose
  `Dst` is a `netx.Addr`, `User` the authenticated identity and `Conn` the
  client connection. `BasicAuth.Check` has the signature of
  `socks5.UserPassAuth.Check`, so one function, such as
  `socks5.Credentials(accounts).Check`, checks the clients of both.
  `StatusError{Code, Err}` and `StatusFor(err)` are the counterparts of
  `socks5.ReplyError` and `ReplyFor`: a dial timeout is `504`, a refused or
  unreachable target `502`, and an `Allow` error `403` unless it carries
  another code.
- `Auth` lists authenticators by scheme; requests without credentials get
  `407` with a `Proxy-Authenticate` challenge for each, on a connection that
  stays open for the retry, unless the list holds a `NoAuth` authenticator,
  which then decides on them. Every request is authenticated: a later
  request of a kept-alive connection without the credentials is refused, and
  only credentials identical to ones that passed are not checked again. Only
  Basic is built in; Digest and other per-request schemes can be added as an
  `Authenticator`, while connection-based ones such as NTLM are not
  supported.
- `RelayOptions` applies to the `netx.Relay` of every tunnel and of every
  forwarded request, whose relay carries the request to the target and the
  responses back, so `WithRelayFlows` paces and counts both exactly, per
  `req.User`, also where bodies are spliced, and `WithRelayIdleTimeout`
  bounds stalled bodies and the wait for a response. `OnDone(req, Result)`
  reports each request's status, bytes each way, whether its target
  connection was reused, and its error, for access logs.
- Connections to targets are kept per reuse key, `Dst` and `User` by
  default: a `Dial` that depends on more, such as a field, needs a
  `ReuseKey`, which can also return false to keep none for a request.
  `MaxIdleConnsPerKey` (16), `MaxIdleConns` (1024) and `IdleConnTimeout`
  (90 s) bound them; a negative `MaxIdleConnsPerKey` keeps none. A kept
  connection that the target closes, or that sends anything unasked, leaves
  the pool at once, and a request that finds one dead before any response
  is sent again on a new one only when it is idempotent and has no body;
  nothing else is ever sent twice. A response with `Connection: close`, or
  read until close, ends its target connection. `Shutdown` and `Close` close
  the kept connections.
- Forwarding follows RFC 9110 and 9112: the fields of one connection
  (`Connection` and those it lists, `Keep-Alive`, `Proxy-Connection`,
  `Proxy-Authorization`, `TE`, `Upgrade`) are removed, `Host` comes from the
  URI, requests go out as HTTP/1.1, and the server writes the framing
  itself, `Content-Length` or chunked, with the chunks of a chunked body
  decoded strictly and encoded again, so that the target reads the body the
  way the server did; trailers are passed on without fields that framing or
  routing depend on. `Via` adds the proxy to `Via`, and `ForwardHeader` and
  `ResponseHeader` can add fields such as `X-Forwarded-For` or `Forwarded`;
  fields that could inject a line are refused. Interim responses such as
  `100 Continue` are passed on to HTTP/1.1 clients; HTTP/1.0 clients, also
  with `Connection: keep-alive`, get chunked responses without chunking and
  responses read until close are re-chunked for HTTP/1.1 clients; transfer
  codings before `chunked` in a response, such as `gzip, chunked`, are
  passed on. `HEAD`, `1xx`, `204` and `304` responses have no body. `Upgrade`
  requests, such as WebSocket, become a relay once the target switches
  protocols. `TRACE` and `OPTIONS` with `Max-Forwards: 0` are answered by the
  proxy, which counts other values down, and `OPTIONS *` is answered too.
- `Intercept` forwards requests for a path, as clients send to the origin,
  for connections redirected to the proxy: `httpproxy.HostDst` takes the
  destination from `Host`, and a hook of your own can use the original
  destination of a redirected connection.
- Requests that could be read in two ways are refused and end the
  connection: `Content-Length` with `Transfer-Encoding`, differing lengths,
  transfer codings other than `chunked`, `Transfer-Encoding` in HTTP/1.0,
  obsolete line folding, whitespace before a colon, control characters in
  fields, two `Host` fields and user information in the URI. After a reply
  that ends a connection while the client may still be sending, the server
  reads on for up to 500 ms or 256 KiB, so that the reply is not lost to a
  reset. Heads are bounded by `MaxHeaderBytes` (64 KiB), reading them by
  `HandshakeTimeout`, idle kept-alive connections by `IdleTimeout`, and the
  wait for a response head, if set, by `ResponseHeaderTimeout` (`504`).
- For non-standard clients, `CONNECT` is also taken in lower case, without a
  `Host` field and without a port (443), lines may end in LF alone, and
  empty lines before a request are skipped.
- The zero `Server` is an open proxy, as the zero `socks5.Server` is: serve it
  only to trusted clients, or set `Auth` and `Allow`; as there, `Allow` sees
  names unresolved, so check resolved addresses in `Dial`. `CONNECT` reaches
  any port that `Allow` lets through.
- `Dial` can reach targets through another proxy, such as a
  `proxydial.HTTPDialer` or `socks5.Dialer`, which chains them.
- `ServeConn(ctx, conn)` serves any `net.Conn`, such as a TLS connection or a
  `netx.PrefixConn` from `netx.Peek`, so one port can serve SOCKS, HTTP
  proxy requests and both over TLS:

```go
func serveMixed(ctx context.Context, c net.Conn, socks *socks5.Server, web *httpproxy.Server, cfg *tls.Config) {
	c, first, err := netx.Peek(ctx, c, 1)
	if err != nil || len(first) == 0 {
		_ = c.Close()
		return
	}
	switch first[0] {
	case socks5.Version5, socks5.Version4:
		_ = socks.ServeConn(ctx, c)
	case 0x16: // TLS: an https proxy or SOCKS over TLS
		if tc, err := tlsconn.Server(ctx, c, cfg); err == nil {
			serveMixed(ctx, tc, socks, web, nil)
		}
	default:
		_ = web.ServeConn(ctx, c)
	}
}
```

### HTTP heads

`github.com/djylb/netx/httphead` reads and parses HTTP/1.x heads on its own,
for sniffers and servers, with the standard library alone:

```go
head, err := httphead.Read(br, nil, 64<<10) // up to the empty line; the body stays in br
req, err := httphead.ParseRequest(string(head), nil)
target, err := httphead.ParseTarget(req.Method, req.Target)
framing, n, err := httphead.RequestBody(req.Header, req.Minor)
```

- `Read` reads a head into a reused buffer, also with lines longer than the
  reader's buffer, skipping empty lines before it; `ParseRequest`,
  `ParseResponse` and `ParseHeader` split it into one string's substrings,
  keeping the fields' order and names. They refuse what two readers could
  read differently: CR inside a line, obsolete line folding, whitespace
  before a colon, names that are not tokens and control characters in
  values (`ErrMalformed`); versions other than 1.x give `ErrVersion`.
- `RequestBody` and `ResponseBody` tell how a body is delimited, refusing
  `Content-Length` with `Transfer-Encoding` in requests and differing
  lengths, and `ParseChunkSize` reads chunk-size lines; `ParseTarget` splits
  a request-target in any of its four forms.
- `Header` has `Get`, `Values`, `Count`, `Has`, `HasToken`, `Add`, `Set` and
  `Del`, and `AppendTo` writes it back, refusing fields that would add a
  line.

## Real client addresses

`forwarded.Resolver` finds the client of a request behind trusted proxies.
It starts at the TCP peer and, while the hop it is at is trusted, steps to
the address that hop recorded, from the right, so that addresses a client
prepends are never read:

```go
trusted, err := forwarded.ParsePrefixSet("10.0.0.0/8", "fd00::/8")
r := &forwarded.Resolver{Trusted: trusted} // X-Forwarded-For

func handler(w http.ResponseWriter, req *http.Request) {
	peer, _ := forwarded.ParseNode(req.RemoteAddr)
	c := r.Resolve(peer, req.Header)
	log.Println(c.Addr.Addr(), c.Proto, c.Host) // client, scheme and host it used
}
```

- `Header` picks the one field the proxies set: `HeaderXForwardedFor`
  (all field lines, comma lists), `HeaderForwarded` (RFC 7239: quoted values,
  IPv6 in brackets, ports, obfuscated identifiers and `unknown`) or
  `HeaderXRealIP`; `Name` reads another field with the same syntax, such as
  `Cf-Connecting-Ip`. Fields of the other kinds are ignored, as a client may
  have sent them.
- `Client` holds the address (IPv4 for IPv4-mapped, port 0 when none was
  recorded), the number of trusted hops, the scheme and host from the
  element that names the client (Forwarded) or from X-Forwarded-Proto and
  X-Forwarded-Host (only when the peer is trusted), and `Opaque` when a
  trusted proxy recorded an obfuscated or unparsable hop, in which case the
  address is that proxy's.
- Forwarded is parsed from the right as well, so that elements a trusted
  proxy appends are read even after a malformed or hostile one.
- `PrefixSet` is built once, merges overlapping prefixes and looks addresses
  up by binary search (3.5 ns in 1000 prefixes). `Resolve` does not
  allocate: 15 ns for an untrusted peer, 80–250 ns through one or more
  proxies.
- `AppendXForwardedFor`, `AppendForwarded` and `AppendElement` format the
  fields a proxy passes on.

## Header rewriting

`httprewrite` compiles templates with variables in the style of common
reverse proxies once and expands them per request, and applies rules that
set, add or delete fields:

```go
rules, err := httprewrite.ParseRules(`
X-Forwarded-For: ${proxy_add_x_forwarded_for}
X-Forwarded-Proto: ${forwarded_proto}
X-Real-IP: ${remote_addr}
X-Internal-Token: ${unset}
`, nil)
rw := &httprewrite.Rewriter{
	Request:   rules,
	Redirects: []httprewrite.Redirect{{To: httprewrite.MustCompile("${forwarded_proto}://${http_host}", nil)}},
	Resolver:  &forwarded.Resolver{Trusted: trusted},
}
proxy := &httputil.ReverseProxy{
	Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(backend)
		if err := rw.Rewrite(pr); err != nil {
			log.Print(err)
		}
	},
	ModifyResponse: rw.ModifyResponse,
}
```

- Built-in variables cover the scheme, host, method, request URI, path,
  query, client and TCP peer addresses, local address, forwarding fields
  with this hop appended, the families `http_NAME`, `upstream_http_NAME`,
  `cookie_NAME` and `arg_NAME`, the response status and the time. `Vars`
  add the program's own, reading `Context.Data`. Unknown variables are
  compile errors; `$$` is a literal `$`.
- An expansion that would put a control character such as CR, LF or NUL in a
  field value fails, so that no variable, such as the decoded path, can
  inject a field. Values are used as written, without HTML unescaping.
- A rule whose value expands to nothing deletes the field, so that
  `Upgrade: ${http_upgrade}` sends none for ordinary requests; `${unset}`
  deletes it always. Rules on `Host` set the request's Host.
- Redirects rewrite `Location` and the URL of `Refresh`; an empty `From`
  matches the backend's own origin.
- Use ReverseProxy's `Rewrite`, not `Director`: hop-by-hop fields are removed
  after `Director`, so rules on them would be lost. In `Rewrite`, variables
  read the inbound request, which still holds Connection, Upgrade and the
  client's forwarding fields.
- Expanding into a buffer does not allocate; a template that is a literal or
  a single field such as `${http_host}` expands to a string without
  allocating.

## WebSocket

`github.com/djylb/netx/wsconn` implements WebSocket (RFC 6455) for tunnels,
proxies and message channels: the opening handshake on both sides, a
message API, and `StreamConn`, a `net.Conn` that carries a byte stream over
binary messages. permessage-deflate (RFC 7692) is optional. It reads
handshakes with `httphead` and links neither `net/http` nor `crypto/tls`;
`wsconn/wshttp` upgrades the requests of a `net/http` handler, also over
HTTP/2.

```go
// serveTunnel accepts WebSocket tunnels on raw connections, such as those
// a port multiplexer hands over, and relays each to a backend.
func serveTunnel(ctx context.Context, raw net.Conn, backend string) {
	c, err := wsconn.Accept(ctx, raw, &wsconn.ServerOptions{CheckOrigin: wsconn.AnyOrigin})
	if err != nil {
		return // answered with 4xx and closed
	}
	tunnel := wsconn.NewStreamConn(c) // RemoteAddr keeps the port
	dst, err := net.Dial("tcp", backend)
	if err != nil {
		_ = c.CloseWithStatus(wsconn.StatusTryAgainLater, "backend down")
		return
	}
	_, _, _ = netx.Relay(ctx, tunnel, dst)
}

// dialTunnel reaches a wss URL through a TLS dialer that verifies the
// server, over an upstream proxy if forward is one.
func dialTunnel(ctx context.Context, url string, forward netx.ContextDialer) (net.Conn, error) {
	d := &wsconn.Dialer{
		ClientOptions: wsconn.ClientOptions{Host: "tunnel.example.com"},
		Forward:       forward,
		TLS:           &tlsconn.Dialer{Forward: forward, Config: &tls.Config{}},
	}
	c, _, err := d.Dial(ctx, url)
	if err != nil {
		return nil, err
	}
	return wsconn.NewStreamConn(c), nil
}
```

- Servers: `Accept(ctx, conn, opts)` reads the request itself;
  `AcceptRequest(ctx, conn, br, req, opts)` takes one already read with
  `httphead`, with the reader that holds what the client sent after it, so
  that one port can serve WebSocket and plain HTTP; `CheckRequest` and
  `Handshake.Accept` split the two steps, as `wshttp.Upgrade(w, r, opts)`
  does, which answers refusals through the `ResponseWriter`, hijacks on
  success, sends the fields of `w.Header()` with the 101 response and lets
  the handler return. `wshttp.Check(w, r, opts)` and
  `wshttp.Accept(w, r, hs)` are its two steps for a handler that decides
  on a valid request before anything is answered, such as by its
  subprotocol or an authorization: `Check` writes nothing, and a refusal
  or a decision against the request leaves the handler free to serve it
  as another request. Refused requests get 400, 403, 405, 426 (with
  `Sec-WebSocket-Version: 13`), 431, 500 (a response field of `Header`
  that cannot be sent) or 505, or the 4xx or 5xx status of a
  `*HandshakeError` from `CheckOrigin`. `CheckOrigin` defaults to
  same-origin and accepts requests without `Origin`; `Subprotocols` are
  chosen by the server's preference; `Conn.Request()` keeps the request,
  for authentication or the fields that carry a client address.
- Clients: `Client(ctx, conn, url, opts)` runs the handshake over a
  connection the caller dialed, such as one through a proxy, already under
  TLS for `wss`; `Dialer.Dial` dials `ws` URLs with `Forward` and `wss` URLs
  with `TLS`, such as a `tlsconn.Dialer`, whose certificate verification is
  on unless its config turns it off, and fails with `ErrNoTLSDialer`
  without one. `Host` overrides the request's Host field, and `Header` adds
  fields; the handshake's own fields are refused. A refused handshake is a
  `*HandshakeError` with the status and the response.
- Handshakes are bounded by the context, or `HandshakeTimeout` (10s), and
  close the connection on failure, as the other handshakes of this module
  do.
- Messages: `ReadMessage`, `AppendMessage` (into a reused buffer, without
  allocating), `NextReader`, `WriteMessage` and `NextWriter` (frames of up to
  32 KiB, or what a larger `Write` gets), text and binary. `ReadLimit`
  (4 MiB, after decompression) bounds messages: kept small because deflate
  inflates about 1000:1, so with compression a few kilobytes on the wire
  make a message of the limit; a `StreamConn` reads without it, as it holds
  no message in memory.
- Concurrency: one goroutine reads; writes may come from any number of
  goroutines and are serialised frame by frame, with the frames of one
  message never interleaved with another's, while control frames go out
  between them. Pings are answered while reading, without waiting for a
  write in progress: the pong is queued and sent by the writer that holds
  the connection, or, when none does, by the reader within the close
  timeout and its read deadline, so that a peer that pings and never reads
  cannot hold the reader; such a pong is dropped. `OnPing` and `OnPong`
  observe them, such as to extend a read deadline. A peer that does not
  read stalls writes until the buffers fill, so servers that write, also
  only now and then, need write deadlines as well as read deadlines.
- Close sends a close frame, waits for the peer's, reading and discarding
  messages itself when no read is in progress, and closes the connection,
  all within `CloseTimeout` (5s), also when a write is blocked, which then
  fails; so the connection does not end with a reset that could lose data
  in flight. A peer's close frame is answered at once and read as a
  `*CloseError` with its code and reason; the server then closes the
  connection beneath first. `CloseWrite` sends the close frame alone, as a
  half-close: no message can be written after it, and reads go on until
  the peer's close frame, which ends the connection.
- `StreamConn`: each `Write` is one binary message of one frame, `Read`
  crosses message bounds and also takes text messages; close codes 1000,
  1001 and none, and a peer that just closes the connection between
  frames, end the stream with `io.EOF`. Deadlines are the connection's; a
  read or write cut short by one leaves the connection usable, unless it
  wrote part of a frame, or of a fragmented message, or read part of a
  compressed message.
- Writes: a server copies at most 32 KiB of a payload, a frame that fits
  the write buffer goes out with its header in one write and a larger one
  with writev on TCP and Unix connections; a client masks into the pooled
  write buffer. Idle connections hold only their read buffer (4 KiB).
- Validation follows RFC 6455 strictly where a lax reading could be
  abused: reserved bits and opcodes, the masking direction, control frames
  of at most 125 bytes that are not fragmented, fragment order, close codes
  and UTF-8 in text messages (checked as it arrives) and close reasons fail
  the connection with 1002, 1007 or 1009. It is lenient where the RFC
  allows: non-minimal payload lengths, any letter case in handshake tokens,
  a missing Host field.
- Compression: `Compression{Level, Threshold}` offers or accepts
  permessage-deflate without context takeover in both directions, so that
  a connection keeps no compressor state between messages; offers that
  need a window smaller than 32 KiB, which compress/flate cannot produce,
  are declined. Messages under `Threshold` (128 bytes) go out uncompressed.
- WebSocket over HTTP/2 (RFC 8441): `wshttp.Upgrade` also accepts an
  extended CONNECT, answers it with 200 and runs the connection over the
  stream, many to one HTTP/2 connection. `net/http` accepts extended
  CONNECT only when the program starts with `GODEBUG=http2xconnect=1` in
  its environment; without it everything is HTTP/1.1 as before. A stream
  lives only as long as its handler, so `wshttp.Serve(w, r, opts, fn)` runs
  `fn` and closes the connection when it returns, and with `Upgrade` the
  handler waits for `wshttp.Done(c)`; the end of the stream or of the
  HTTP/2 connection closes the WebSocket connection. On a server's
  stream, an expired write deadline resets the stream and an expired read
  deadline ends its reading for good; on a client's stream either resets
  it. `wshttp.Dialer` dials over HTTP/2 with a `Transport` that can send
  the `:protocol` pseudo-field, which `net/http`'s cannot, and falls back
  to HTTP/1.1 only through its `HTTP1` dialer, within one handshake
  timeout; URL credentials go out as Basic on both. `CheckRequest`, `Handshake.ResponseHeader`, `Handshake.NewConn`,
  `ClientOptions.ExtendedConnectHeader` and `ExtendedConnectClient` serve
  other HTTP/2 stacks; `NewConn` wraps a connection whose handshake was done
  otherwise.
- The masking keys and handshake keys come from the runtime's ChaCha8
  generator, and the accept key's SHA-1 is computed in the package, as
  `crypto/sha1` would add about 176 KB of FIPS code to a program
  (linux/amd64, stripped).

## Upstream Proxies

`github.com/djylb/netx/proxydial` dials TCP through an HTTP CONNECT or SOCKS5
proxy. `FromURL`, `FromString` and `FromEnvironment` build the dialers from a URL; they are
plain structs (`HTTPDialer`, `socks5.Dialer`) that can also be configured
directly, for example with a private CA or extra request headers. A program
that only talks to SOCKS5 proxies can use `socks5.Dialer` alone and avoid the
`crypto/tls` that `https` proxies need.

```go
func corporateProxy(ca *x509.CertPool) *proxydial.HTTPDialer {
	return &proxydial.HTTPDialer{
		ProxyAddr: "proxy.corp.example:3128",
		Header:    textproto.MIMEHeader{"User-Agent": {"my-agent/1.0"}},
		// TLS to the proxy, verified against its host name.
		Forward: &tlsconn.Dialer{
			Config:  &tls.Config{RootCAs: ca},
			Forward: &net.Dialer{Timeout: 10 * time.Second},
		},
	}
}
```

```go
func dialVia(ctx context.Context, proxyURL, target string) (net.Conn, error) {
	forward := &net.Dialer{Timeout: 10 * time.Second}
	var d netx.ContextDialer
	var err error
	if proxyURL != "" {
		// ParseURL and FromURL; a bare host:port is an http proxy.
		d, err = proxydial.FromString(proxyURL, forward, nil)
	} else {
		d, err = proxydial.FromEnvironment(forward, nil)
	}
	if err != nil {
		return nil, err
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
  proxies, which they reach through a `*tlsconn.Dialer` as the dialer's
  `Forward`: `nil` verifies the proxy's host name against the system roots,
  and a config without `ServerName`, such as one carrying a private CA, is
  used with the proxy's host filled in. `FromURL` returns an
  `*proxydial.HTTPDialer` or a `*socks5.Dialer`; type-assert it to adjust
  fields such as `Header`. Both dialers reach a TLS proxy the same way: set
  `Forward` to a `tlsconn.Dialer`.
- `ParseURL` parses a proxy URL leniently: `proxy:3128` or `127.0.0.1:1080`
  without a scheme is an `http` proxy, and its errors never quote the
  password.
- A refused CONNECT is a `*proxydial.ConnectError` with the status code, status
  text and reply header, so a caller can answer a `407` challenge from
  `Proxy-Authenticate` or tell `403` from `502`.
- `HTTPDialer.Handshake` runs CONNECT on a connection the caller already has
  to the proxy, such as a multiplexed stream. It returns that connection, or
  a `netx.PrefixConn` over it when the proxy sent tunnel bytes with its reply,
  and closes the connection on failure, as `netx.DoHandshake` does.
- The dialers also have a `Dial(network, address)` method, for code that
  expects a dialer without a context.
- The context bounds the dial, the TLS handshake with the proxy and the proxy
  handshake; the returned connection has no deadline. Bytes the HTTP proxy sends right after its `2xx` reply are
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

## Destination Policies

`github.com/djylb/netx/safedial` dials, and sends datagrams to, only the
destinations a policy allows, for a program that connects on behalf of a
party it trusts less: a tunnel client that a server tells where to connect,
a proxy, or a webhook sender. The check binds to the address actually
dialed, so DNS rebinding and later re-resolution cannot get around it.

```go
d := &safedial.Dialer{
	// nil Policy: DefaultPolicy, global unicast addresses only.
	Policy: safedial.All(
		safedial.DenyPorts(25),
		safedial.Any(
			// Names under corp.example may resolve to private addresses,
			// not to loopback, link-local (metadata) or other ones.
			safedial.All(
				safedial.AllowNames("corp.example"),
				safedial.AllowScopes(netx.ScopePrivate, netx.ScopeGlobal),
			),
			safedial.DefaultPolicy(),
		),
	),
}
client := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}} // no Proxy

_, err := d.DialContext(ctx, "tcp", "127.1:6379")
var denied *safedial.DeniedError
if errors.As(err, &denied) { // errors.Is(err, safedial.ErrDenied) too
	log.Printf("refused %v: %v", denied.Target, denied.Reason) // 127.0.0.1:6379: loopback
}
```

- `Dialer` is a `netx.ContextDialer` with `Forward` (zero `net.Dialer` if
  nil), `Resolver` (`*net.Resolver` or anything with `LookupNetIP`), `Policy`,
  `Stagger` and `VerifyRemoteAddr`. It parses the target with `ParseTarget`:
  IP literals in every form, bracketed, IPv4-mapped (unmapped), zoned (the
  zone kept apart, in `Target.Zone`, and used to dial) or with a trailing
  dot, are checked as addresses, and so are the legacy IPv4 forms that
  system resolvers read as addresses (`127.1`, `2130706433`, `0x7f.0.0.1`,
  `0177.0.0.1`), parsed as `inet_aton` does (`ParseLegacyIPv4`). Hosts that
  are no plain host name, such as ones with spaces, non-ASCII bytes, a
  numeric last label or an empty host, fail with `netx.ErrInvalidAddr`
  before any resolver sees them.
- A host name is checked by name first (so `DenyNames` refuses it without a
  lookup), resolved once, and every address is unmapped and checked; only the
  allowed ones are dialed, as IP literals, interleaved by family and raced
  through `netx.RaceDialer.DialAny` as Happy Eyeballs does. A name is never
  resolved twice per dial, CNAMEs do not matter since the final addresses are
  checked, and an HTTP client's redirects dial, and are checked, again.
  `Lookup` returns the addresses `DialContext` would dial. `VerifyRemoteAddr`
  closes a connection whose `RemoteAddr` is not the address dialed, for a
  `Forward` that might connect elsewhere.
- Not covered: an upstream proxy that resolves names itself. Give an
  `http.Transport` that dials with a `Dialer` no `Proxy`; a proxy dialer as
  `Forward` receives IP addresses only, which reach what they reach from the
  proxy's network.
- A `Policy` (`Check(Target) error`, or a `PolicyFunc`) sees a name before
  it is resolved (`Addr` invalid) and each address with the name. Building
  blocks: `DefaultPolicy` (`AllowScopes(netx.ScopeGlobal)`: no loopback,
  private, link-local, shared CGNAT, unspecified, multicast, broadcast,
  documentation, benchmarking, reserved, nor NAT64/6to4/Teredo addresses
  embedding them), `AllowScopes`, `DenyScopes`, `AllowPrefixes`,
  `DenyPrefixes` (binary search over merged prefixes; an invalid prefix fails
  closed), `AllowPorts`, `DenyPorts`, `AllowPortRange`, `DenyPortRange`,
  `AllowNames` and `DenyNames` (`example.com` matches it and its subdomains,
  `*.example.com` only subdomains; internationalised patterns match in
  their punycode form, and a `DenyNames` pattern that is no host name
  refuses every name), and `All`/`Any` to combine them. An allowed name
  reaches whatever its DNS points to, so pair `AllowNames` with the scopes
  or prefixes its names may reach; name rules do not stop another name or
  an IP address that reaches the same host. A target with neither an
  address nor a name, such as a `*net.UDPAddr` without an IP, is always
  refused, as sockets send it to the local host. A
  refusal is a `*DeniedError` with the `Target` and the `Reason`
  (`ErrScope`, `ErrPrefix`, `ErrPort`, `ErrName`, `ErrRemoteMismatch` or the
  policy's own), matching `ErrDenied`.
- UDP: `DialContext` takes `udp`, `udp4` and `udp6`. For relays that send
  to many destinations, `WrapPacketConn` wraps a `net.PacketConn` (checking
  `WriteTo` and `WriteToUDPAddrPort`) and `WrapAddrPacketConn` a
  `socks5.PacketConn`-shaped connection, which the result is too, so it fits
  a `socks5.Server`'s `DialPacket` or a `DatagramRelay`. Replies from any
  source are delivered (full cone). Names are resolved by the wrapper itself,
  never by the wrapped connection: cached for a minute (failures five seconds,
  1024 names), and datagrams wait for a lookup without blocking `WriteTo`,
  within 64 lookups, 16 datagrams per name and 256 KiB (`ErrLookupBusy`
  beyond). `Close` cancels the lookups.
- Checking an IP destination, with `Dialer.Check` or a datagram through
  either wrapper, does not allocate with the policies of this package.
