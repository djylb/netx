// Package netx provides reusable networking helpers for Go with no
// third-party dependencies.
//
// It keeps four groups in one package:
//
//   - Connection wrappers: TimeoutConn, FramedConn (length-prefixed messages
//     with stream or datagram reads), TLSConn, TeeConn, AddrOverrideConn,
//     WrapConn and ObserveConn. RawConnOf unwraps them, and any connection with
//     a NetConn method such as *tls.Conn, down to the innermost net.Conn.
//   - PROXY protocol v1 and v2 header builders.
//   - TCP transport helpers: ListenTCP with an optional transparent mode and
//     OriginalDestination for redirected connections.
//   - Error classification: IsTimeout, IsConnReset, IsConnRefused and the other
//     Is* helpers, NetErrorKind and DescribeNetError. They match platform
//     errnos, including Winsock codes on Windows, before English error text.
//
// Helpers that take a timeout use DefaultTimeout for a non-positive value.
package netx
