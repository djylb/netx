package wsconn

import (
	"errors"
	"net"
	"testing"
	"time"
)

// Abort sends no close frame: the peer reads a reset, not a *CloseError,
// and a later Close reports the connection closed.
func TestAbortSendsNoCloseFrame(t *testing.T) {
	srv, cli := pair(t, nil, nil)
	cli.Abort(errors.New("cut"))
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := srv.ReadMessage()
	if err == nil {
		t.Fatal("ReadMessage after the peer's Abort = nil error")
	}
	if ce, ok := errors.AsType[*CloseError](err); ok {
		t.Fatalf("ReadMessage after the peer's Abort = close frame %v, want a reset", ce.Code)
	}
	if err := cli.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close after Abort = %v, want net.ErrClosed", err)
	}
}

type abortRecorder struct {
	net.Conn
	cause error
}

func (a *abortRecorder) Abort(cause error) { a.cause = cause; _ = a.Close() }

// Abort passes the cause to an Abort method of the connection beneath.
func TestAbortForwardsToConnBeneath(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	rec := &abortRecorder{Conn: a}
	c := &Conn{conn: rec, done: make(chan struct{})}
	cause := errors.New("cut")
	NewStreamConn(c).Abort(cause)
	if rec.cause != cause {
		t.Fatalf("Abort beneath got %v, want %v", rec.cause, cause)
	}
}
