package netx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("Accept() failed")
	}
	return client, server
}

func TestRelayCopiesBothDirections(t *testing.T) {
	userA, relayA := tcpPair(t)
	relayB, userB := tcpPair(t)
	defer func() { _ = userA.Close() }()
	defer func() { _ = userB.Close() }()

	type result struct {
		aToB, bToA int64
		err        error
	}
	done := make(chan result, 1)
	go func() {
		aToB, bToA, err := Relay(relayA, relayB)
		done <- result{aToB, bToA, err}
	}()

	request := bytes.Repeat([]byte("a"), 100_000)
	response := bytes.Repeat([]byte("b"), 70_000)
	go func() { _, _ = userA.Write(request) }()
	got := make([]byte, len(request))
	if _, err := io.ReadFull(userB, got); err != nil || !bytes.Equal(got, request) {
		t.Fatalf("userB read error = %v", err)
	}
	go func() { _, _ = userB.Write(response) }()
	got = make([]byte, len(response))
	if _, err := io.ReadFull(userA, got); err != nil || !bytes.Equal(got, response) {
		t.Fatalf("userA read error = %v", err)
	}

	_ = userA.Close()
	select {
	case r := <-done:
		if r.err != nil || r.aToB != int64(len(request)) || r.bToA != int64(len(response)) {
			t.Fatalf("Relay() = %d, %d, %v", r.aToB, r.bToA, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay() did not return after one side closed")
	}
	// Relay closed relayB, so userB sees EOF.
	if _, err := userB.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("userB Read() error = %v, want EOF", err)
	}
}

type failingRWC struct {
	readErr error
	closed  chan struct{}
}

func (f *failingRWC) Read([]byte) (int, error) { return 0, f.readErr }
func (f *failingRWC) Write(b []byte) (int, error) {
	return len(b), nil
}
func (f *failingRWC) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

// blockingRWC blocks reads until closed, then fails them like a closed socket.
type blockingRWC struct {
	closed chan struct{}
}

func (b *blockingRWC) Read([]byte) (int, error) {
	<-b.closed
	return 0, net.ErrClosed
}
func (b *blockingRWC) Write(p []byte) (int, error) { return len(p), nil }
func (b *blockingRWC) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func TestRelayReportsFirstError(t *testing.T) {
	boom := errors.New("boom")
	a := &failingRWC{readErr: boom, closed: make(chan struct{})}
	b := &blockingRWC{closed: make(chan struct{})}
	_, _, err := Relay(a, b)
	if !errors.Is(err, boom) {
		t.Fatalf("Relay() error = %v, want %v", err, boom)
	}
	select {
	case <-b.closed:
	default:
		t.Fatal("Relay() did not close b")
	}
}

// With WithHalfClose a client can shut down its sending side and still read
// the answer, which the backend sends after it has seen EOF.
func TestRelayHalfClose(t *testing.T) {
	client, relayA := tcpPair(t)
	relayB, backend := tcpPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = backend.Close() }()

	go func() {
		request, _ := io.ReadAll(backend) // until the relayed EOF
		_, _ = backend.Write(append([]byte("echo:"), request...))
		_ = backend.(*net.TCPConn).CloseWrite()
	}()
	done := make(chan error, 1)
	var up, down int64
	go func() {
		var err error
		up, down, err = Relay(relayA, relayB, WithHalfClose())
		done <- err
	}()

	_, _ = client.Write([]byte("ping"))
	_ = client.(*net.TCPConn).CloseWrite()
	answer, err := io.ReadAll(client)
	if err != nil || string(answer) != "echo:ping" {
		t.Fatalf("answer = %q, %v", answer, err)
	}
	if err := <-done; err != nil || up != 4 || down != 9 {
		t.Fatalf("Relay() = %d, %d, %v", up, down, err)
	}
}

// Without CloseWrite support the half-close option falls back to closing both.
func TestRelayHalfCloseFallsBackToClose(t *testing.T) {
	client, a := net.Pipe()
	b, backend := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, backend) }()
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(a, b, WithHalfClose())
		done <- err
	}()
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Relay() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay() did not return")
	}
}
