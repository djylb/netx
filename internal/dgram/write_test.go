package dgram

import (
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

type blockingPacket struct {
	net.PacketConn
	conn net.Conn
}

func (p blockingPacket) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }

func TestInterruptSharedWrite(t *testing.T) {
	for _, closeFlow := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			a, b := net.Pipe()
			writer := NewWriter()
			done, entered := make(chan struct{}), make(chan struct{})
			gate := NewWriteGate(blockingPacket{conn: a})
			result := make(chan error, 1)
			go func() {
				_, err := gate.Write(&writer, done, func() (int, error) { close(entered); return a.Write([]byte{1}) })
				result <- err
			}()
			<-entered
			other := NewWriter()
			next := make(chan error, 1)
			go func() {
				_, err := gate.Write(&other, nil, func() (int, error) { return a.Write([]byte{2}) })
				next <- err
			}()
			synctest.Wait()
			want := os.ErrDeadlineExceeded
			if closeFlow {
				close(done)
				writer.Close()
				want = net.ErrClosed
			} else if err := writer.SetDeadline(time.Now()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Errorf("write = %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Error("write did not wake")
			}
			var got [1]byte
			if _, err := b.Read(got[:]); err != nil || got[0] != 2 {
				t.Fatalf("second flow: %v, %v", got, err)
			}
			if err := <-next; err != nil {
				t.Fatal(err)
			}
			other.Close()
			_ = a.Close()
			_ = b.Close()
			writer.Close()
		})
	}
}

type deadlinePacket struct {
	net.PacketConn
	set func(time.Time) error
}

func (pc deadlinePacket) SetWriteDeadline(d time.Time) error { return pc.set(d) }

func TestPlainSharedWrite(t *testing.T) {
	w := NewWriter()
	defer w.Close()
	pc := deadlinePacket{set: func(time.Time) error { return errors.ErrUnsupported }}
	if n, err := NewWriteGate(pc).Write(&w, nil, func() (int, error) { return 1, nil }); err != nil || n != 1 {
		t.Fatalf("Write = %d, %v", n, err)
	}
}

func TestReentrantSharedDeadline(t *testing.T) {
	w := NewWriter()
	defer w.Close()
	_ = w.SetDeadline(time.Now().Add(time.Hour))
	pc := deadlinePacket{set: func(time.Time) error { w.Close(); return nil }}
	if _, err := NewWriteGate(pc).Write(&w, nil, func() (int, error) { t.Error("sent after close"); return 0, nil }); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write = %v", err)
	}
}

// Hold the first installation open while a second setter asks for a deadline
// the socket rejects. Each caller observes the result before it returns.
func TestConcurrentDeadlineError(t *testing.T) {
	w := NewWriter()
	defer w.Close()
	first := time.Now().Add(time.Hour)
	second := first.Add(time.Hour)
	entered, resume := make(chan struct{}), make(chan struct{})
	pc := deadlinePacket{set: func(d time.Time) error {
		switch d {
		case first:
			close(entered)
			<-resume
		case second:
			return errors.ErrUnsupported
		}
		return nil
	}}
	_ = w.SetDeadline(first)
	write := make(chan error, 1)
	go func() { _, err := NewWriteGate(pc).Write(&w, nil, func() (int, error) { return 1, nil }); write <- err }()
	<-entered
	err := w.SetDeadline(second)
	close(resume)
	if got := <-write; !errors.Is(got, errors.ErrUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("write = %v, setter = %v", got, err)
	}
}

func TestPanickingDeadlineReleasesGate(t *testing.T) {
	w := NewWriter()
	defer w.Close()
	_ = w.SetDeadline(time.Now().Add(time.Hour))
	pc := deadlinePacket{set: func(d time.Time) error {
		if !d.IsZero() {
			panic("deadline")
		}
		return nil
	}}
	g := NewWriteGate(pc)
	send := func() (int, error) { return 1, nil }
	func() {
		defer func() {
			if recover() != "deadline" {
				t.Error("missing deadline panic")
			}
		}()
		_, _ = g.Write(&w, nil, send)
	}()
	if err := w.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, err := g.Write(&w, nil, send); n != 1 || err != nil {
		t.Fatalf("next send = %d, %v", n, err)
	}
}
