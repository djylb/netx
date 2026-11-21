package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
)

// failingEnd is an end whose Read fails with err once its data is read.
type failingEnd struct {
	net.Conn
	err error
}

func (f failingEnd) Read([]byte) (int, error) { return 0, f.err }

func TestRelayErrorSide(t *testing.T) {
	boom := errors.New("boom")
	for _, side := range []RelaySide{RelayA, RelayB} {
		a1, a2 := net.Pipe()
		b1, b2 := net.Pipe()
		var a, b io.ReadWriteCloser = a1, b1
		if side == RelayA {
			a = failingEnd{a1, boom}
		} else {
			b = failingEnd{b1, boom}
		}
		go func() { _, _ = io.Copy(io.Discard, a2) }()
		go func() { _, _ = io.Copy(io.Discard, b2) }()
		_, _, err := Relay(context.Background(), a, b)
		var re *RelayError
		if !errors.As(err, &re) || re.From != side || !errors.Is(err, boom) {
			t.Errorf("side %v: %v", side, err)
		}
		_ = a2.Close()
		_ = b2.Close()
	}
	if RelayA.Other() != RelayB || RelayB.Other() != RelayA || RelayA.String() != "a" {
		t.Error("RelaySide methods")
	}
}

func TestRelayErrorContextNotWrapped(t *testing.T) {
	cause := errors.New("cause")
	ctx, cancel := context.WithCancelCause(context.Background())
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer func() { _ = a2.Close() }()
	defer func() { _ = b2.Close() }()
	done := make(chan error, 1)
	go func() { _, _, err := Relay(ctx, a1, b1); done <- err }()
	cancel(cause)
	err := <-done
	var re *RelayError
	// Unwrapped: the cause itself, not a RelayError or another wrapper.
	if !errors.Is(err, cause) || errors.Unwrap(err) != nil || errors.As(err, &re) {
		t.Errorf("err %v", err)
	}
}
