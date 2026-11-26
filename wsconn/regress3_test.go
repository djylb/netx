package wsconn

import (
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

// A peer that sends a ping but never reads cannot hold the reader past
// its read deadline. net.Pipe blocks on the very first pong.
func TestPongHonorsReadDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sc, peer := net.Pipe()
		defer func() { _ = sc.Close(); _ = peer.Close() }()
		srv := newTestConn(sc, nil, false, nil)
		deadline := time.Now().Add(time.Second)
		if err := srv.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = peer.Write(frame(finBit|opPing, true, []byte("x"))) }()
		if _, _, err := srv.ReadMessage(); !errors.Is(err, os.ErrDeadlineExceeded) || !time.Now().Equal(deadline) {
			t.Fatalf("ReadMessage = %v at %v, want timeout at %v", err, time.Now(), deadline)
		}
	})
}
