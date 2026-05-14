# netx

Reusable Go networking helpers.

## Install

```bash
go get github.com/djylb/netx
```

## Includes

- Connection adapters: framed I/O, timeout, TLS, tee, address override, traffic observer.
- Protocol helpers: ACK, connect result, Proxy Protocol v1/v2.
- Transport helpers: transparent TCP listen, original destination lookup, TCP keepalive options.

## Usage

```go
package main

import (
	"net"
	"time"

	"github.com/djylb/netx"
)

func wrapConn(c net.Conn) net.Conn {
	c = netx.NewTimeoutConn(c, 30*time.Second)
	return netx.WrapFramed(c)
}

func listen(addr string) (net.Listener, error) {
	return netx.ListenTCP(addr, false)
}
```
