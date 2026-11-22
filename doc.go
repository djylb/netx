// Package netx provides reusable networking helpers for Go.
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
//     dials in memory, NewSingleConnListener serves one connection, and
//     ListenEphemeralUDP opens a UDP socket on a free port. Accept retries
//     temporary Accept errors with a backoff. See udpflow.ListenUDPReusePort
//     for UDP socket groups using SO_REUSEPORT.
//   - Error classification: IsTimeout, IsClosed, IsConnReset, IsConnRefused
//     and the other Is* helpers, NetErrorKind and NetErrorDetails. They match
//     platform errnos, including Winsock codes on Windows, before English
//     error text.
//
// Protocol and platform helpers live in subpackages:
//
//   - duplex joins a read half and a write half into one connection.
//   - forwarded interprets client metadata from trusted proxies.
//   - httphead parses HTTP/1.x heads and body framing.
//   - httpproxy serves HTTP forward proxies and CONNECT tunnels.
//   - httprewrite applies HTTP header and redirect rewrite rules.
//   - memnet provides in-process streams and datagrams for tests.
//   - proxydial dials through HTTP CONNECT, SOCKS5 and SOCKS4 proxies,
//     with caller-supplied TLS for encrypted proxy connections.
//   - proxyproto builds, decodes and serves PROXY protocol headers.
//   - safedial dials and relays datagrams under a destination policy.
//   - socks5 implements SOCKS5 and SOCKS4 clients and servers.
//   - tlsconn runs bounded TLS handshakes and handles certificates.
//   - transparent accepts transparently redirected TCP and UDP flows.
//   - udpflow demultiplexes packet sockets into datagram connections.
//   - wsconn handles WebSocket handshakes, frames and stream adapters.
//   - wsconn/wshttp integrates WebSockets with net/http.
//
// The module uses the standard library and github.com/djylb/timeshim,
// which itself uses only the standard library. The only packages that
// bring in crypto/tls are tlsconn directly and httprewrite and
// wsconn/wshttp through net/http.
//
// Settings use the documented default for zero fields, omitted functional
// options and optional nil constructor arguments. Defaults for timeouts
// and limits are bounded unless documented otherwise. An explicit zero
// passed to an option or constructor follows that parameter's documented
// rule. A negative timeout disables it unless the setting says otherwise.
// Other negative values require a documented meaning.
// Servers and dialers expose settings as fields. Helpers use functional
// options for optional settings and ordinary arguments for required inputs.
package netx
