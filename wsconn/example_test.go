package wsconn_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/tlsconn"
	"github.com/djylb/netx/wsconn"
)

// A server that echoes a stream over WebSocket, and a client of it.
func Example() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		c, err := wsconn.Accept(context.Background(), raw, nil)
		if err != nil {
			return
		}
		s := wsconn.NewStreamConn(c)
		_, _ = io.Copy(s, s) // echo until the client closes
		_ = s.Close()
	}()

	ctx := context.Background()
	c, _, err := (&wsconn.Dialer{}).Dial(ctx, "ws://"+ln.Addr().String()+"/tunnel")
	if err != nil {
		log.Fatal(err)
	}
	s := wsconn.NewStreamConn(c)
	_, _ = s.Write([]byte("hello"))
	buf := make([]byte, 5)
	_, _ = io.ReadFull(s, buf)
	fmt.Println(string(buf))
	_ = s.Close()
	// Output: hello
}

// Dialing wss URLs through a TLS dialer, which verifies the server's
// certificate for the URL's host, with a message channel.
func ExampleDialer() {
	d := &wsconn.Dialer{
		ClientOptions: wsconn.ClientOptions{
			Header:       httphead.Header{{Name: "Authorization", Value: "Bearer token"}},
			Subprotocols: []string{"json.v1"},
		},
		TLS: &tlsconn.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12}},
	}
	c, _, err := d.Dial(context.Background(), "wss://example.com/events")
	if err != nil {
		log.Print(err)
		return
	}
	defer func() { _ = c.Close() }()
	_ = c.WriteMessage(wsconn.Text, []byte(`{"type":"hello"}`))
	for {
		typ, msg, err := c.ReadMessage()
		if err != nil {
			return // a *wsconn.CloseError after the server's close frame
		}
		fmt.Println(typ, string(msg))
	}
}

// Serving WebSocket and other protocols on one port: the request is read
// first, and only upgrades go to AcceptRequest, with the reader that holds
// what the client sent after the request.
func ExampleAcceptRequest() {
	handle := func(ctx context.Context, raw net.Conn) {
		br := bufio.NewReader(raw)
		head, err := httphead.Read(br, nil, wsconn.DefaultMaxHeaderBytes)
		if err != nil {
			_ = raw.Close()
			return
		}
		req, err := httphead.ParseRequest(string(head), nil)
		if err != nil || !req.Header.HasToken("Upgrade", "websocket") {
			_ = raw.Close() // or serve it as plain HTTP from br
			return
		}
		c, err := wsconn.AcceptRequest(ctx, raw, br, &req, &wsconn.ServerOptions{CheckOrigin: wsconn.AnyOrigin})
		if err != nil {
			return
		}
		tunnel := wsconn.NewStreamConn(c)
		defer func() { _ = tunnel.Close() }()
		_, _ = io.Copy(io.Discard, tunnel)
	}
	_ = handle
}
