package netx

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type deadlineSpyConn struct {
	net.Conn
	mu            sync.Mutex
	lastDeadline  time.Time
	deadlineCalls int
}

func (d *deadlineSpyConn) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.lastDeadline = t
	d.deadlineCalls++
	d.mu.Unlock()
	return d.Conn.SetDeadline(t)
}

func (d *deadlineSpyConn) snapshot() (time.Time, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastDeadline, d.deadlineCalls
}

type deadlineRecordConn struct {
	countedCloseConn
	mu       sync.Mutex
	deadline []time.Time
}

func (d *deadlineRecordConn) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadline = append(d.deadline, t)
	d.mu.Unlock()
	return nil
}

func (d *deadlineRecordConn) deadlines() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.deadline...)
}

func TestTimeoutConnReadWriteSetsDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	spy := &deadlineSpyConn{Conn: client}
	idle := 300 * time.Millisecond
	conn := NewTimeoutConn(spy, idle)

	start := time.Now()
	go func() {
		_, _ = server.Write([]byte("hi"))
	}()

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if got := string(buf[:n]); got != "hi" {
		t.Fatalf("read payload mismatch: got %q", got)
	}

	firstDeadline, firstCalls := spy.snapshot()
	if firstCalls == 0 {
		t.Fatal("expected SetDeadline to be called on read")
	}
	if firstDeadline.Before(start.Add(idle - 120*time.Millisecond)) {
		t.Fatalf("deadline not set close to now+idle: got %v", firstDeadline)
	}

	serverRead := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		tmp := make([]byte, 2)
		_, readErr := io.ReadFull(server, tmp)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		serverRead <- tmp
	}()

	// Wait past the refresh slack (idle/16) so the write moves the deadline.
	time.Sleep(40 * time.Millisecond)
	if _, err = conn.Write([]byte("ok")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	select {
	case readErr := <-serverErr:
		t.Fatalf("server read failed: %v", readErr)
	case got := <-serverRead:
		if string(got) != "ok" {
			t.Fatalf("write payload mismatch: got %q", string(got))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server read timed out")
	}

	secondDeadline, secondCalls := spy.snapshot()
	if secondCalls < 2 {
		t.Fatalf("expected SetDeadline called for read and write, got %d", secondCalls)
	}
	if !secondDeadline.After(firstDeadline) {
		t.Fatalf("expected write deadline to refresh, first=%v second=%v", firstDeadline, secondDeadline)
	}
}

func TestTimeoutConnRefreshDeadlineDoesNotMoveBackward(t *testing.T) {
	raw := &deadlineRecordConn{}
	conn := NewTimeoutConn(raw, time.Second)

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if err := conn.refreshDeadline(); err != nil {
				t.Errorf("refreshDeadline() error = %v", err)
			}
		}()
	}
	wg.Wait()

	got := raw.deadlines()
	if len(got) == 0 || len(got) > goroutines {
		t.Fatalf("deadline calls = %d, want 1..%d", len(got), goroutines)
	}
	for i := 1; i < len(got); i++ {
		if !got[i].After(got[i-1]) {
			t.Fatalf("deadline[%d] = %v, want after previous %v", i, got[i], got[i-1])
		}
	}
}

func TestNewTimeoutConnNormalizesNonPositiveIdle(t *testing.T) {
	tests := []struct {
		name string
		idle time.Duration
	}{
		{name: "zero", idle: 0},
		{name: "negative", idle: -time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = server.Close() }()
			spy := &deadlineSpyConn{Conn: client}
			conn := NewTimeoutConn(spy, tt.idle)
			defer func() { _ = conn.Close() }()

			started := time.Now()
			go func() {
				_, _ = server.Write([]byte("x"))
			}()

			buf := make([]byte, 1)
			if _, err := conn.Read(buf); err != nil {
				t.Fatalf("Read() error = %v", err)
			}

			firstDeadline, calls := spy.snapshot()
			if calls == 0 {
				t.Fatal("expected SetDeadline to be called")
			}
			if firstDeadline.Before(started.Add(DefaultTimeout - 250*time.Millisecond)) {
				t.Fatalf("deadline = %v, want normalized idle near now+%s", firstDeadline, DefaultTimeout)
			}
		})
	}
}

func TestTimeoutConnStructLiteralUsesDefaultTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	spy := &deadlineSpyConn{Conn: client}
	conn := &TimeoutConn{Conn: spy}
	defer func() { _ = conn.Close() }()

	started := time.Now()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = server.Write([]byte("x"))
	}()

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read() error = %v, want data despite zero idle timeout", err)
	}
	deadline, calls := spy.snapshot()
	if calls == 0 {
		t.Fatal("expected SetDeadline to be called")
	}
	if deadline.Before(started.Add(DefaultTimeout - 250*time.Millisecond)) {
		t.Fatalf("deadline = %v, want near now+%s", deadline, DefaultTimeout)
	}
}

func TestTimeoutConnHelpersHandleNilState(t *testing.T) {
	var nilConn *TimeoutConn
	assertClosedConnState(t, "nil", nilConn)

	malformed := &TimeoutConn{}
	assertClosedConnState(t, "malformed", malformed)
}

func TestTimeoutConnSkipsRedundantDeadlineUpdates(t *testing.T) {
	raw := &deadlineRecordConn{}
	conn := NewTimeoutConn(raw, time.Minute)
	for range 1000 {
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if got := len(raw.deadlines()); got != 1 {
		t.Fatalf("deadline calls = %d, want 1", got)
	}

	// A later explicit deadline is capped by the idle timeout as soon as it
	// is set, and the next read or write sets the idle deadline again.
	explicit := time.Now().Add(time.Hour)
	if err := conn.SetDeadline(explicit); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got := raw.deadlines()
	if len(got) != 3 || !got[1].Before(explicit) || !got[2].Before(explicit) {
		t.Fatalf("deadlines = %v, want idle, capped explicit, idle", got)
	}
}

// dirDeadlineConn tracks the read and write deadlines set on it.
type dirDeadlineConn struct {
	countedCloseConn
	mu     sync.Mutex
	rd, wd time.Time
}

func (d *dirDeadlineConn) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.rd, d.wd = t, t
	d.mu.Unlock()
	return nil
}

func (d *dirDeadlineConn) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.rd = t
	d.mu.Unlock()
	return nil
}

func (d *dirDeadlineConn) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.wd = t
	d.mu.Unlock()
	return nil
}

func (d *dirDeadlineConn) snapshot() (rd, wd time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rd, d.wd
}

func TestTimeoutConnKeepsUserDeadlines(t *testing.T) {
	raw := &dirDeadlineConn{}
	const idle = 160 * time.Millisecond // refresh slack 10ms
	conn := NewTimeoutConn(raw, idle)
	near := func(got time.Time) bool {
		d := time.Until(got)
		return d > idle-100*time.Millisecond && d <= idle
	}
	waitSlack := func() { time.Sleep(20 * time.Millisecond) }

	// A read deadline set to interrupt a blocked Read survives writes.
	past := time.Now().Add(-time.Second)
	if err := conn.SetReadDeadline(past); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	for range 2 {
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if rd, wd := raw.snapshot(); !rd.Equal(past) || !near(wd) {
			t.Fatalf("after Write: read deadline %v, write deadline in %v; want %v and about %v", rd, time.Until(wd), past, idle)
		}
		waitSlack()
	}

	// A later user deadline is capped by the idle timeout.
	if err := conn.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read() error = nil, want the stub's EOF")
	}
	if rd, wd := raw.snapshot(); !rd.Equal(past) || !near(wd) {
		t.Fatalf("after Read: read deadline %v, write deadline in %v; want %v and about %v", rd, time.Until(wd), past, idle)
	}

	// Clearing the user deadlines leaves the idle timeout in both directions.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if rd, wd := raw.snapshot(); !rd.Equal(wd) || !near(rd) {
		t.Fatalf("after clearing: read deadline in %v, write deadline in %v; want both about %v", time.Until(rd), time.Until(wd), idle)
	}
}

func TestTimeoutConnReadDeadlineInterruptsDuringWrites(t *testing.T) {
	for i := range 20 {
		client, server := tcpPair(t)
		go func() { _, _ = io.Copy(io.Discard, client) }()
		conn := NewTimeoutConn(server, 3*time.Second)
		stop := make(chan struct{})
		writerDone := make(chan struct{})
		go func() {
			defer close(writerDone)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := conn.Write([]byte("w")); err != nil {
					return
				}
			}
		}()
		readDone := make(chan error, 1)
		go func() {
			_, err := conn.Read(make([]byte, 1))
			readDone <- err
		}()
		time.Sleep(2 * time.Millisecond)
		if err := conn.SetReadDeadline(time.Now()); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		select {
		case err := <-readDone:
			if !IsTimeout(err) {
				t.Fatalf("round %d: Read() error = %v, want a timeout", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("round %d: Read() still blocked after SetReadDeadline while writes continue", i)
		}
		close(stop)
		_ = client.Close()
		_ = server.Close()
		<-writerDone
	}
}

func TestTimeoutConnIdleClockIsMonotonic(t *testing.T) {
	raw := &dirDeadlineConn{}
	const idle = time.Minute
	conn := NewTimeoutConn(raw, idle)
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	// The stored deadline is an offset on the monotonic clock, not a wall
	// clock reading that a clock step would move.
	if d := time.Duration(conn.deadline.Load() - clockOffset(time.Now())); d <= idle-time.Second || d > idle {
		t.Fatalf("stored idle deadline is %v ahead of the monotonic clock, want about %v", d, idle)
	}
	// The socket deadline keeps the monotonic reading too.
	if rd, _ := raw.snapshot(); !strings.Contains(rd.String(), " m=") {
		t.Fatalf("deadline %v has no monotonic clock reading", rd)
	}
}

// Clearing or moving a user deadline must not lift the idle timeout of a Read
// that is already blocked, as the HTTP/2 server does with SetReadDeadline.
func TestTimeoutConnBlockedReadKeepsIdleTimeout(t *testing.T) {
	for _, tt := range []struct {
		name string
		set  func(c *TimeoutConn) error
	}{
		{"clear read deadline", func(c *TimeoutConn) error { return c.SetReadDeadline(time.Time{}) }},
		{"clear deadline", func(c *TimeoutConn) error { return c.SetDeadline(time.Time{}) }},
		{"far deadline", func(c *TimeoutConn) error { return c.SetDeadline(time.Now().Add(time.Hour)) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := tcpPair(t)
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			conn := NewTimeoutConn(client, 100*time.Millisecond)
			errc := make(chan error, 1)
			go func() {
				_, err := conn.Read(make([]byte, 1))
				errc <- err
			}()
			time.Sleep(20 * time.Millisecond) // let Read block
			if err := tt.set(conn); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-errc:
				if !IsTimeout(err) {
					t.Fatalf("Read() error = %v, want a timeout", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked Read lost its idle timeout")
			}
		})
	}
}
