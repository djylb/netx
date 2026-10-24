package wsconn

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestPongDoesNotHoldReaderTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cl.Close() }()
	_ = cl.(*net.TCPConn).SetReadBuffer(4096)
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = sc.(*net.TCPConn).SetWriteBuffer(4096)
	srv := NewConn(sc, nil, false, nil)
	defer func() { _ = sc.Close() }()
	ping := frame(finBit|opPing, true, bytes.Repeat([]byte("x"), 125))
	go func() {
		for range 500000 {
			if _, err := cl.Write(ping); err != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() {
		_ = srv.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		_, _, err := srv.ReadMessage()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read succeeded")
		}
	case <-time.After(6 * time.Second):
		t.Errorf("server reader stuck in a pong write after its read deadline")
	}
}
