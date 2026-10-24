package netx

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A relay of two exchanges, each a head followed by a bounded part of a
// connection, copies exactly the parts, counts them in its flows, and
// leaves the connections open, positioned after them, when its ends' Close
// leaves them so.
func TestRelayEndsOfChainedParts(t *testing.T) {
	clientApp, client := tcpPair(t) // the client's side writes the request
	server, serverApp := tcpPair(t) // the server's side writes the response
	const reqBody, respBody = "request-body", "response-body"
	go func() { _, _ = io.WriteString(clientApp, reqBody+"NEXT") }()
	go func() { _, _ = io.WriteString(serverApp, respBody+"MORE") }()

	var closes atomic.Int32
	chain := func(head string, c net.Conn, n int64) *ChainReader {
		parts := []io.Reader{strings.NewReader(head), &io.LimitedReader{R: c, N: n}}
		return &ChainReader{Next: func() (io.Reader, error) {
			if len(parts) == 0 {
				return nil, nil
			}
			p := parts[0]
			parts = parts[1:]
			return p, nil
		}}
	}
	a := &RelayEnd{
		Reader:         chain("REQ ", client, int64(len(reqBody))),
		Writer:         client,
		CloseWriteFunc: func() error { return nil },
		CloseFunc:      func() error { closes.Add(1); return nil },
	}
	b := &RelayEnd{
		Reader:         chain("RESP ", server, int64(len(respBody))),
		Writer:         server,
		CloseWriteFunc: func() error { return nil },
		CloseFunc:      func() error { closes.Add(1); return nil },
	}
	var up, down atomic.Int64
	flows := WithRelayFlows(
		&RelayFlow{Done: func(n int64) error { up.Add(n); return nil }},
		&RelayFlow{Done: func(n int64) error { down.Add(n); return nil }},
	)
	aToB, bToA, err := Relay(context.Background(), a, b, WithRelayHalfClose(), flows)
	if err != nil {
		t.Fatal(err)
	}
	wantUp, wantDown := int64(len("REQ "+reqBody)), int64(len("RESP "+respBody))
	if aToB != wantUp || bToA != wantDown || up.Load() != wantUp || down.Load() != wantDown {
		t.Fatalf("copied %d/%d, counted %d/%d; want %d/%d", aToB, bToA, up.Load(), down.Load(), wantUp, wantDown)
	}
	if closes.Load() != 2 {
		t.Fatalf("Close calls = %d", closes.Load())
	}
	for _, tt := range []struct {
		c    net.Conn
		want string
	}{{serverApp, "REQ " + reqBody}, {clientApp, "RESP " + respBody}, {client, "NEXT"}, {server, "MORE"}} {
		_ = tt.c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(tt.want))
		if _, err := io.ReadFull(tt.c, got); err != nil || string(got) != tt.want {
			t.Fatalf("read %q, %v; want %q", got, err, tt.want)
		}
	}
}

// Copy of an *io.LimitedReader over a connection copies the bound and no
// more, also through a PrefixConn, with and without a flow.
func TestCopyLimitedConn(t *testing.T) {
	for _, flow := range []*RelayFlow{nil, {Done: func(int64) error { return nil }}} {
		w, r := tcpPair(t)
		dst, sink := tcpPair(t)
		go func() { _, _ = io.WriteString(w, strings.Repeat("x", 100000)+"rest") }()
		src := &io.LimitedReader{R: NewPrefixConn(r, []byte("pre")), N: 100003}
		// Read while Copy writes: a small socket buffer, as on js/wasm,
		// would otherwise block the copy.
		got := make([]byte, 100003)
		read := make(chan error, 1)
		go func() {
			_ = sink.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := io.ReadFull(sink, got)
			read <- err
		}()
		n, err := Copy(context.Background(), dst, src, flow)
		if err != nil || n != 100003 {
			t.Fatalf("Copy = %d, %v", n, err)
		}
		if err := <-read; err != nil || !bytes.HasPrefix(got, []byte("prexxx")) {
			t.Fatalf("copied %q..., %v", got[:6], err)
		}
		_ = r.SetReadDeadline(time.Now().Add(5 * time.Second))
		rest := make([]byte, 4)
		if _, err := io.ReadFull(r, rest); err != nil || string(rest) != "rest" {
			t.Fatalf("left %q, %v", rest, err)
		}
	}
}

func TestChainReaderRead(t *testing.T) {
	parts := []string{"a", "", "bc"}
	c := &ChainReader{Next: func() (io.Reader, error) {
		if len(parts) == 0 {
			return nil, nil
		}
		p := parts[0]
		parts = parts[1:]
		return strings.NewReader(p), nil
	}}
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "abc" {
		t.Fatalf("ReadAll = %q, %v", b, err)
	}
}

// An *io.LimitedReader over a TCP connection splices where the connection
// would.
func TestLimitedReaderSplices(t *testing.T) {
	a, _ := tcpPair(t)
	b, _ := tcpPair(t)
	if spliceable(b, a) != spliceable(b, &io.LimitedReader{R: a, N: 1}) {
		t.Fatal("a bounded connection does not splice as the connection does")
	}
}
