// Package netx provides reusable networking helpers for Go with no
// third-party dependencies.
//
// The root package holds portable connection helpers:
//
//   - Connection wrappers: TimeoutConn (idle timeout), FramedConn
//     (length-prefixed messages with stream or datagram reads), PrefixConn
//     (replays bytes already read), TeeConn (records reads), AddrOverrideConn,
//     WrapConn and ObserveConn (traffic callbacks). The wrappers pass
//     CloseWrite on, and RawConnOf unwraps them, and any connection with a
//     NetConn method such as *tls.Conn, down to the innermost net.Conn.
//   - Relay copies between two connections in both directions, optionally
//     passing half-closes on.
//   - Listeners: ChanListener accepts connections that the program delivers or
//     dials in memory, NewSingleConnListener serves one connection, and
//     PacketListener splits a UDP socket into one connection per peer.
//   - Error classification: IsTimeout, IsClosed, IsConnReset, IsConnRefused
//     and the other Is* helpers, NetErrorKind and DescribeNetError. They match
//     platform errnos, including Winsock codes on Windows, before English
//     error text.
//
// Helpers that take a timeout use DefaultTimeout for a non-positive value.
//
// Protocol and platform helpers live in subpackages: tlsconn runs bounded TLS
// handshakes and handles certificates, proxyproto builds, parses and serves PROXY protocol headers,
// transparent accepts transparently redirected TCP connections and UDP
// datagrams, socks5 implements SOCKS5 and SOCKS4 with a client dialer and a
// configurable server, and proxy dials through HTTP CONNECT, SOCKS5 and SOCKS4
// proxies, also over TLS.
//
// Every package depends only on the standard library, and only tlsconn and
// proxy import crypto/tls, which adds about 800 KB to a binary even when it is
// not used.
package netx
