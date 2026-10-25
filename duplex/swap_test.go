package duplex_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/duplex"
)

// closeCounter is a stream that counts its Close calls.
type closeCounter struct {
	io.Reader
	io.Writer
	closes int
	mu     sync.Mutex
}

func (c *closeCounter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	return nil
}

func (c *closeCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// waitBlocked gives a goroutine time to block. Tests use it only where a
// late block changes nothing but the path taken.
func waitBlocked() { time.Sleep(5 * time.Millisecond) }

// enteredWriter signals each Write before passing it on.
type enteredWriter struct {
	io.Writer
	entered chan struct{}
}

func (w *enteredWriter) Write(p []byte) (int, error) {
	w.entered <- struct{}{}
	return w.Writer.Write(p)
}

func readString(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

// The streams are read in order, each closed once at its end, and reads
// wait for the next one until End.
func TestReaderSequence(t *testing.T) {
	noLeaks(t)
	var in duplex.Reader
	first := &closeCounter{Reader: strings.NewReader("ab")}
	done, err := in.Append(first)
	if err != nil {
		t.Fatal(err)
	}
	if got := readString(t, &in, 2); got != "ab" {
		t.Fatalf("read %q", got)
	}
	got := make(chan string, 1)
	go func() {
		b, err := io.ReadAll(&in)
		if err != nil {
			t.Error(err)
		}
		got <- string(b)
	}()
	<-done // the next read found the end of first
	if first.count() != 1 {
		t.Fatalf("first closed %d times", first.count())
	}
	if _, err := in.Append(strings.NewReader("cd")); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Append(strings.NewReader("ef")); err != nil {
		t.Fatal(err)
	}
	_ = in.End()
	if s := <-got; s != "cdef" {
		t.Fatalf("read %q after the first", s)
	}
	if _, err := in.Append(strings.NewReader("")); err == nil {
		t.Fatal("Append after End succeeded")
	}
	if n, err := in.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("Read after the end = %d, %v", n, err)
	}
}

// The deadline and Close end reads that wait for a stream; Close closes
// the streams left, once each.
func TestReaderWait(t *testing.T) {
	noLeaks(t)
	var in duplex.Reader
	if err := in.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %v", err)
	}
	_ = in.SetReadDeadline(time.Time{})
	read := make(chan error, 1)
	go func() { _, err := in.Read(make([]byte, 1)); read <- err }()
	waitBlocked()
	_ = in.SetReadDeadline(time.Now().Add(10 * time.Millisecond)) // wakes the read
	if err := <-read; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after a later deadline = %v", err)
	}
	_ = in.SetReadDeadline(time.Time{})

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	stalled := &closeCounter{Reader: pr}
	queued := &closeCounter{Reader: strings.NewReader("x")}
	d1, _ := in.Append(stalled)
	d2, _ := in.Append(queued)
	go func() { _, err := in.Read(make([]byte, 1)); read <- err }()
	waitBlocked()
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	<-d1
	<-d2
	if stalled.count() != 1 || queued.count() != 1 {
		t.Fatalf("closed %d and %d times", stalled.count(), queued.count())
	}
	_ = pw.CloseWithError(net.ErrClosed) // the counter does not close the pipe
	if err := <-read; err == nil {
		t.Fatal("Read after Close succeeded")
	}
	if _, err := in.Read(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read = %v", err)
	}
	if _, err := in.Append(strings.NewReader("")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Append = %v", err)
	}
	if err := in.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close = %v", err)
	}
}

// Deadlines go on the current stream and on each stream as it becomes
// current.
func TestReaderDeadlines(t *testing.T) {
	var in duplex.Reader
	rc1, rc2 := new(calls), new(calls)
	_, _ = in.Append(&deadlineHalf{Reader: strings.NewReader("a"), calls: rc1})
	_, _ = in.Append(&deadlineHalf{Reader: strings.NewReader("b"), calls: rc2})
	dl := time.Now().Add(time.Hour)
	if err := in.SetReadDeadline(dl); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, &in, 2); got != "ab" {
		t.Fatalf("read %q", got)
	}
	if n := len(rc1.readDeadlines); n != 2 || !rc1.readDeadlines[1].Equal(dl) {
		t.Fatalf("first stream deadlines %v", rc1.readDeadlines)
	}
	if n := len(rc2.readDeadlines); n != 1 || !rc2.readDeadlines[0].Equal(dl) {
		t.Fatalf("second stream deadlines %v", rc2.readDeadlines)
	}
	var plain duplex.Reader
	_, _ = plain.Append(strings.NewReader(""))
	if err := plain.SetReadDeadline(dl); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("SetReadDeadline of a plain stream = %v", err)
	}
}

// WriteTo copies each stream through its own WriteTo.
func TestReaderWriteTo(t *testing.T) {
	var in duplex.Reader
	for _, s := range []string{"a", "bc", "", "d"} {
		_, _ = in.Append(strings.NewReader(s))
	}
	_ = in.End()
	var out bytes.Buffer
	if n, err := io.Copy(&out, &in); n != 4 || err != nil || out.String() != "abcd" {
		t.Fatalf("Copy = %d, %v, %q", n, err, out.String())
	}
}

// Writes wait for the first stream; the deadline and Close end the wait.
func TestWriterWait(t *testing.T) {
	noLeaks(t)
	var up duplex.Writer
	_ = up.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := up.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write = %v", err)
	}
	_ = up.SetWriteDeadline(time.Time{})
	wrote := make(chan error, 1)
	go func() { _, err := up.Write([]byte("x")); wrote <- err }()
	waitBlocked()
	var out bytes.Buffer
	if err := up.Swap(t.Context(), &out); err != nil {
		t.Fatal(err)
	}
	if err := <-wrote; err != nil || out.String() != "x" {
		t.Fatalf("Write = %v, %q", err, out.String())
	}

	var closing duplex.Writer
	go func() { _, err := closing.Write([]byte("x")); wrote <- err }()
	waitBlocked()
	_ = closing.Close()
	if err := <-wrote; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v", err)
	}
	if err := closing.Swap(t.Context(), &out); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Swap after Close = %v", err)
	}
}

// Swap waits for the write in progress, closes the old stream once, and
// leaves both streams alone when its context ends first.
func TestWriterSwap(t *testing.T) {
	noLeaks(t)
	pr, pw := io.Pipe()
	entered := make(chan struct{}, 1)
	old := &closeCounter{Writer: &enteredWriter{pw, entered}}
	var up duplex.Writer
	_ = up.Swap(t.Context(), old)
	wrote := make(chan error, 1)
	go func() { _, err := up.Write([]byte("abc")); wrote <- err }()
	<-entered

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	var next bytes.Buffer
	if err := up.Swap(ctx, &next); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Swap = %v", err)
	}
	if got := readString(t, pr, 3); got != "abc" {
		t.Fatalf("old stream got %q", got)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if old.count() != 0 {
		t.Fatal("a failed Swap closed the old stream")
	}

	go func() { _, err := up.Write([]byte("de")); wrote <- err }()
	swapped := make(chan error, 1)
	<-entered
	go func() { swapped <- up.Swap(t.Context(), &next) }()
	// The swap may wait for the write or find it ended; either way the
	// write goes to the old stream.
	waitBlocked()
	if got := readString(t, pr, 2); got != "de" {
		t.Fatalf("old stream got %q", got)
	}
	if err := <-swapped; err != nil {
		t.Fatal(err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if old.count() != 1 {
		t.Fatalf("old closed %d times", old.count())
	}
	_, _ = up.Write([]byte("f"))
	if next.String() != "f" {
		t.Fatalf("new stream got %q", next.String())
	}
	same := &closeCounter{Writer: io.Discard}
	_ = up.Swap(t.Context(), same)
	_ = up.Swap(t.Context(), same)
	if same.count() != 0 {
		t.Fatal("swapping in the current stream closed it")
	}
	_ = pr.Close()
}

// A Conn of a Reader and a Writer half-closes and closes them.
func TestConnOfSwitchables(t *testing.T) {
	var in duplex.Reader
	var up duplex.Writer
	part := &closeCounter{Reader: strings.NewReader("x")}
	_, _ = in.Append(part)
	stream := &closeCounter{Writer: io.Discard}
	_ = up.Swap(t.Context(), stream)
	c := duplex.Join(&in, &up)
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	_ = c.CloseRead()
	if part.count() != 1 {
		t.Fatal("CloseRead did not close the Reader")
	}
	_ = c.Close()
	if stream.count() != 1 {
		t.Fatal("Close did not close the Writer")
	}
}

// TestSwapStream moves a stream across many channels while it is written
// and read, and checks that every byte arrives once and in order.
func TestSwapStream(t *testing.T) {
	noLeaks(t)
	const total = 1 << 17
	want := make([]byte, total)
	for i := range want {
		want[i] = byte(i % 251)
	}
	var in duplex.Reader
	var up duplex.Writer
	// swap opens a channel, which arrives at the receiver, and swaps to
	// it, holding the lock, so that the channels arrive in the order of
	// the swaps, as a sender must make them do.
	var swapMu sync.Mutex
	swap := func() error {
		swapMu.Lock()
		defer swapMu.Unlock()
		r, w := io.Pipe()
		if _, err := in.Append(r); err != nil {
			return err
		}
		return up.Swap(t.Context(), w)
	}
	if err := swap(); err != nil {
		t.Fatal(err)
	}
	sender, receiver := duplex.Join(nil, &up), duplex.Join(&in, nil)

	var wg sync.WaitGroup
	var got []byte
	wg.Go(func() {
		var err error
		got, err = io.ReadAll(receiver)
		if err != nil {
			t.Error(err)
		}
	})
	written := make(chan struct{})
	var swaps sync.WaitGroup
	for range 2 {
		swaps.Go(func() {
			for range 100 {
				select {
				case <-written:
					return
				default:
				}
				if err := swap(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	for b := want; len(b) > 0; b = b[min(len(b), 999):] {
		if _, err := sender.Write(b[:min(len(b), 999)]); err != nil {
			t.Fatal(err)
		}
	}
	close(written)
	swaps.Wait()
	_ = sender.Close() // ends the last channel
	_ = in.End()
	wg.Wait()
	if !bytes.Equal(got, want) {
		t.Fatalf("received %d bytes that differ from the %d sent", len(got), len(want))
	}
}

// lockedStream holds a lock through each Read and Write, which its deadline
// methods take too, as a stream that guards its state with one mutex does:
// its deadline methods wait for a blocked Read or Write to end.
type lockedStream struct {
	mu      sync.Mutex
	pr      *io.PipeReader
	pw      *io.PipeWriter
	entered chan struct{}
	setting chan struct{}
}

func newLockedStream() *lockedStream {
	pr, pw := io.Pipe()
	return &lockedStream{pr: pr, pw: pw, entered: make(chan struct{}, 1), setting: make(chan struct{}, 1)}
}

func (s *lockedStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered <- struct{}{}
	return s.pr.Read(p)
}

func (s *lockedStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered <- struct{}{}
	return s.pw.Write(p)
}

func (s *lockedStream) setDeadline() error {
	s.setting <- struct{}{}
	s.mu.Lock()
	defer s.mu.Unlock()
	return nil
}

func (s *lockedStream) SetReadDeadline(time.Time) error  { return s.setDeadline() }
func (s *lockedStream) SetWriteDeadline(time.Time) error { return s.setDeadline() }

// Close ends a blocked Read or Write without the lock.
func (s *lockedStream) Close() error {
	_ = s.pr.Close()
	return s.pw.Close()
}

// A deadline call that waits for a blocked Read or Write in the stream does
// not hold up Close, which ends that Read or Write.
func TestDeadlineCallNotUnderLock(t *testing.T) {
	noLeaks(t)
	check := func(t *testing.T, s *lockedStream, use func(), set func(), closeAll func() error) {
		t.Helper()
		<-s.setting // the deadline that the stream got when it became current
		used := make(chan struct{})
		go func() { use(); close(used) }()
		<-s.entered
		setDone := make(chan struct{})
		go func() { set(); close(setDone) }()
		<-s.setting // the deadline call waits for the stream's lock
		closed := make(chan error, 1)
		go func() { closed <- closeAll() }()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			_ = s.Close() // unblock everything before failing
			t.Fatal("Close waited for the stream's deadline method")
		}
		<-used
		<-setDone
	}
	t.Run("Reader", func(t *testing.T) {
		s := newLockedStream()
		var in duplex.Reader
		if _, err := in.Append(s); err != nil {
			t.Fatal(err)
		}
		check(t, s,
			func() { _, _ = in.Read(make([]byte, 1)) },
			func() { _ = in.SetReadDeadline(time.Now().Add(time.Hour)) },
			in.Close)
	})
	t.Run("Writer", func(t *testing.T) {
		s := newLockedStream()
		var up duplex.Writer
		if err := up.Swap(t.Context(), s); err != nil {
			t.Fatal(err)
		}
		check(t, s,
			func() { _, _ = up.Write([]byte("x")) },
			func() { _ = up.SetWriteDeadline(time.Now().Add(time.Hour)) },
			up.Close)
	})
}
