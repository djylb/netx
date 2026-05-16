# netx

Reusable Go networking helpers with no third-party dependencies.

Requires Go 1.25.

## Install

```bash
go get github.com/djylb/netx
```

## Connections

```go
package main

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/djylb/netx"
)

func wrap(c net.Conn) net.Conn {
	c = netx.NewTimeoutConn(c, 30*time.Second)
	c = netx.ObserveConn(c, netx.TrafficObserver{
		OnRead:  func(n int64) error { return nil },
		OnWrite: func(n int64) error { return nil },
	})
	return netx.NewFramedConn(c)
}

func tlsClient(c net.Conn) (net.Conn, error) {
	return netx.NewTLSConn(c, 5*time.Second, &tls.Config{
		ServerName: "example.com",
	})
}
```

```go
framed := netx.NewFramedConn(conn)
_ = framed.WriteFrame(packet)
packet, err := framed.ReadFrame()
```

```go
wrapped := netx.WrapConn(rwc, conn)
wrapped = netx.WrapConn(rwc, conn, netx.WithParentClose())
```

## Address Wrapping

```go
remote, _ := netx.ParseTCPAddr("203.0.113.10:443")
local, _ := netx.ParseTCPAddr("127.0.0.1:8080")
conn := netx.NewAddrOverrideConn(rawConn, remote, local)
raw := netx.RawConnOf(conn)
```

## Proxy Protocol

```go
header := netx.ProxyProtocolHeader(conn, netx.ProxyProtocolV1)
header = netx.ProxyProtocolHeaderFromAddrs(clientAddr, targetAddr, netx.ProxyProtocolV2)
```

## TCP Transport

```go
ln, err := netx.ListenTCP("0.0.0.0:8080")
ln, err = netx.ListenTCPContext(ctx, "0.0.0.0:8080")
transparentLn, err := netx.ListenTCP("0.0.0.0:8080", netx.WithTransparent())
```

```go
tcpConn, _ := net.DialTCP("tcp", nil, addr)
err := netx.SetTCPKeepAlive(tcpConn, netx.TCPKeepAliveConfig{
	Idle:     30 * time.Second,
	Interval: 10 * time.Second,
	Count:    3,
})
```

```go
dst, err := netx.OriginalDestination(conn)
target := dst.String()
```

## Small Protocol Helpers

```go
_ = netx.WriteACK(conn, 5*time.Second)
_ = netx.ReadACK(conn, 5*time.Second)

status := netx.DialConnectResult(err)
_ = netx.WriteConnectResult(conn, status, 5*time.Second)
status, err = netx.ReadConnectResult(conn, 5*time.Second)
```

## Error Helpers

```go
if netx.IsTimeout(err) || netx.IsConnReset(err) {
	return
}

kind := netx.NetErrorKind(err)
detail := netx.DescribeNetError(err, conn)
```
