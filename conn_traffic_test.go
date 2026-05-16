package netx

import (
	"errors"
	"net"
	"testing"
)

var (
	errTrafficIO       = errors.New("traffic io error")
	errTrafficObserver = errors.New("traffic observer error")
)

type partialErrRWC struct{}

func (partialErrRWC) Read(p []byte) (int, error) {
	copy(p, "x")
	return 1, errTrafficIO
}

func (partialErrRWC) Write([]byte) (int, error) {
	return 1, errTrafficIO
}

func (partialErrRWC) Close() error {
	return nil
}

func TestObserveReadWriteCloserJoinsObserverAndIOErrors(t *testing.T) {
	observed := ObserveReadWriteCloser(partialErrRWC{}, TrafficObserver{
		OnRead:  func(int64) error { return errTrafficObserver },
		OnWrite: func(int64) error { return errTrafficObserver },
	})

	if _, err := observed.Read(make([]byte, 1)); !errors.Is(err, errTrafficIO) || !errors.Is(err, errTrafficObserver) {
		t.Fatalf("Read() error = %v, want both IO and observer errors", err)
	}
	if _, err := observed.Write([]byte("x")); !errors.Is(err, errTrafficIO) || !errors.Is(err, errTrafficObserver) {
		t.Fatalf("Write() error = %v, want both IO and observer errors", err)
	}
}

func TestObserveConnWithoutObserversReturnsInput(t *testing.T) {
	var conn net.Conn = &countedCloseConn{}
	if got := ObserveConn(conn, TrafficObserver{}); got != conn {
		t.Fatalf("ObserveConn() = %v, want original conn", got)
	}
}
