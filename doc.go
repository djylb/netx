// Package netx provides reusable networking helpers for Go with no
// third-party dependencies.
//
// The root package holds portable connection helpers:
//
//   - Connection wrappers: TimeoutConn (idle timeout), FramedConn
//     (length-prefixed messages as a stream or as datagrams), PrefixConn
//     (replays bytes already read), RecordingConn (records reads),
//     AddrOverrideConn, WrapConn and ObserveConn (traffic callbacks). The
//     wrappers pass CloseWrite on, and InnermostConn and ConnAs unwrap them,
//     and any connection with a NetConn method such as *tls.Conn. Peek and
//     PeekFull read the first bytes of a connection and replay them.
//   - Relay copies between two connections in both directions until its
//     context ends, optionally passing half-closes on, ending idle relays,
//     and pacing and counting each direction through RelayFlow hooks; Copy
//     copies one direction the same way. RelayEnd and ChainReader relay
//     parts of connections, such as one exchange of a protocol, splicing an
//     *io.LimitedReader over a connection. ConnGroup closes connections and
//     relays together. DoWithContext bounds a blocking call on a connection
//     with a context, and DoHandshake an exchange that closes the
//     connection when it fails, as the handshakes of this module do.
//   - Addr is a destination as proxy requests name it, an IP address or a
//     host name and a port, normalised so that policies see one form.
//   - Dialing: DialFirst returns the first of several dial attempts that
//     connects, and RaceDialer races several dialers as a ContextDialer, or
//     the addresses of a service with DialAny.
//   - Listeners: ChanListener accepts connections that the program delivers or
//     dials in memory, NewSingleConnListener serves one connection,
//     PacketListener splits a UDP socket into one connection per peer, and
//     ListenEphemeralUDP opens a UDP socket on a free port. Accept retries
//     temporary Accept errors with a backoff.
//   - Error classification: IsTimeout, IsClosed, IsConnReset, IsConnRefused
//     and the other Is* helpers, NetErrorKind and NetErrorDetails. They match
//     platform errnos, including Winsock codes on Windows, before English
//     error text.
//
// Protocol and platform helpers live in subpackages: tlsconn runs bounded TLS
// handshakes and handles certificates, proxyproto builds, decodes and serves
// PROXY protocol headers, transparent accepts transparently redirected TCP
// connections and UDP datagrams, socks5 implements SOCKS5 and SOCKS4 with a client dialer and a
// configurable server, httpproxy is an HTTP proxy server of the same shape,
// httphead parses HTTP/1.x heads, duplex joins a read half and a write half
// into a connection, and proxydial dials through HTTP CONNECT,
// SOCKS5 and SOCKS4 proxies, also over TLS.
//
// Every package depends only on the standard library, and only tlsconn and
// proxydial import crypto/tls, which adds a large amount of code to a binary even
// when it is not used.
package netx
