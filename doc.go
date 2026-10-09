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
//   - TLSClient and TLSServer run a bounded handshake, and Relay copies
//     between two connections in both directions, optionally passing
//     half-closes on.
//   - Listeners: ChanListener accepts connections that the program delivers or
//     dials in memory, and NewSingleConnListener serves one connection.
//   - Error classification: IsTimeout, IsClosed, IsConnReset, IsConnRefused
//     and the other Is* helpers, NetErrorKind and DescribeNetError. They match
//     platform errnos, including Winsock codes on Windows, before English
//     error text.
//
// Helpers that take a timeout use DefaultTimeout for a non-positive value.
//
// Protocol and platform helpers live in subpackages: proxyproto builds, parses
// and serves PROXY protocol headers, transparent listens for transparently
// redirected connections, socks5 reads and writes SOCKS5 messages, and proxy
// dials through HTTP CONNECT and SOCKS5 proxies.
package netx
