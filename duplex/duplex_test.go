package duplex_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/duplex"
)

// noLeaks fails t when goroutines started during it outlive it.
func noLeaks(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for goroutines() > before {
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<16)
				t.Errorf("%d goroutines leaked:\n%s", goroutines()-before, buf[:runtime.Stack(buf, true)])
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
}

// goroutines counts the goroutines, without the one that js/wasm starts
// for the first timer.
func goroutines() int {
	buf := make([]byte, 1<<20)
	stacks := string(buf[:runtime.Stack(buf, true)])
	return strings.Count("\n"+stacks, "\ngoroutine ") - strings.Count(stacks, "\nruntime.handleEvent(")
}

// calls counts the close and deadline calls of a test half.
type calls struct {
	mu                                     sync.Mutex
	close, closeRead, closeWrite           int
	readDeadlines, writeDeadlines, anyDead []time.Time
}

func (c *calls) count(n *int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*n++
	return nil
}

func (c *calls) get(n *int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return *n
}

func (c *calls) record(ts *[]time.Time, t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*ts = append(*ts, t)
	return nil
}

// closerHalf has Close only.
type closerHalf struct {
	io.Reader
	io.Writer
	*calls
}

func (h *closerHalf) Close() error { return h.count(&h.calls.close) }

// tcpHalf has CloseRead, CloseWrite and Close, as a *net.TCPConn does.
type tcpHalf struct{ closerHalf }

func (h *tcpHalf) CloseRead() error  { return h.count(&h.calls.closeRead) }
func (h *tcpHalf) CloseWrite() error { return h.count(&h.calls.closeWrite) }

// tlsHalf has CloseWrite and Close, as a *tls.Conn does.
type tlsHalf struct{ closerHalf }

func (h *tlsHalf) CloseWrite() error { return h.count(&h.calls.closeWrite) }

// valueHalf is a half of a type that is not comparable.
type valueHalf struct {
	b []byte
	n *int
}

func (v valueHalf) Read([]byte) (int, error)    { return 0, io.EOF }
func (v valueHalf) Write(p []byte) (int, error) { return len(p), nil }
func (v valueHalf) Close() error                { *v.n++; return nil }

func TestNilConn(t *testing.T) {
	var c *duplex.Conn
	if _, err := c.Read(nil); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read = %v", err)
	}
	if _, err := c.Write(nil); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write = %v", err)
	}
	if _, err := c.WriteTo(io.Discard); !errors.Is(err, net.ErrClosed) {
		t.Errorf("WriteTo = %v", err)
	}
	if _, err := c.ReadFrom(strings.NewReader("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("ReadFrom = %v", err)
	}
	for name, f := range map[string]func() error{
		"Close":            c.Close,
		"CloseRead":        c.CloseRead,
		"CloseWrite":       c.CloseWrite,
		"SetDeadline":      func() error { return c.SetDeadline(time.Time{}) },
		"SetReadDeadline":  func() error { return c.SetReadDeadline(time.Time{}) },
		"SetWriteDeadline": func() error { return c.SetWriteDeadline(time.Time{}) },
	} {
		if err := f(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s = %v", name, err)
		}
	}
	if c.LocalAddr() == nil || c.RemoteAddr() == nil {
		t.Error("nil address")
	}
}

func TestNilHalves(t *testing.T) {
	for _, c := range []*duplex.Conn{duplex.Join(nil, nil), new(duplex.Conn)} {
		if n, err := c.Read(make([]byte, 4)); n != 0 || err != io.EOF {
			t.Errorf("Read = %d, %v", n, err)
		}
		if _, err := c.Write([]byte("x")); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("Write = %v", err)
		}
		if n, err := c.WriteTo(io.Discard); n != 0 || err != nil {
			t.Errorf("WriteTo = %d, %v", n, err)
		}
		if _, err := c.ReadFrom(strings.NewReader("x")); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("ReadFrom = %v", err)
		}
		if err := c.SetDeadline(time.Now()); err != nil {
			t.Errorf("SetDeadline = %v", err)
		}
		if a := c.LocalAddr(); a.Network() != "duplex" || a.String() != "duplex" {
			t.Errorf("LocalAddr = %v", a)
		}
		if err := c.CloseRead(); err != nil {
			t.Errorf("CloseRead = %v", err)
		}
		if err := c.Close(); err != nil {
			t.Errorf("Close = %v", err)
		}
		if err := c.Close(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("second Close = %v", err)
		}
	}
}

func TestReadWrite(t *testing.T) {
	var out bytes.Buffer
	c := duplex.Join(strings.NewReader("hello"), &out)
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	if n, err := c.Write([]byte("world")); n != 5 || err != nil || out.String() != "world" {
		t.Fatalf("Write = %d, %v, %q", n, err, out.String())
	}
}

func TestHalfClose(t *testing.T) {
	t.Run("separate closers", func(t *testing.T) {
		rc, wc := new(calls), new(calls)
		c := duplex.Join(&closerHalf{Reader: strings.NewReader("x"), calls: rc}, &closerHalf{Writer: io.Discard, calls: wc})
		if err := c.CloseRead(); err != nil || rc.get(&rc.close) != 1 {
			t.Fatalf("CloseRead = %v, reader closed %d", err, rc.get(&rc.close))
		}
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read after CloseRead = %v", err)
		}
		if err := c.CloseRead(); err != nil {
			t.Fatalf("second CloseRead = %v", err)
		}
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatalf("Write after CloseRead = %v", err)
		}
		if err := c.Close(); err != nil || rc.get(&rc.close) != 1 || wc.get(&wc.close) != 1 {
			t.Fatalf("Close = %v, closed %d and %d", err, rc.get(&rc.close), wc.get(&wc.close))
		}
		if err := c.CloseWrite(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("CloseWrite after Close = %v", err)
		}
	})
	t.Run("half closers", func(t *testing.T) {
		rc, wc := new(calls), new(calls)
		c := duplex.Join(&tcpHalf{closerHalf{Reader: strings.NewReader(""), calls: rc}}, &tcpHalf{closerHalf{Writer: io.Discard, calls: wc}})
		_ = c.CloseRead()
		_ = c.CloseWrite()
		if rc.get(&rc.closeRead) != 1 || wc.get(&wc.closeWrite) != 1 || rc.get(&rc.close)+wc.get(&wc.close) != 0 {
			t.Fatalf("half-closes: %+v %+v", rc, wc)
		}
		if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after CloseWrite = %v", err)
		}
		_ = c.Close() // still releases both
		if rc.get(&rc.close) != 1 || wc.get(&wc.close) != 1 || rc.get(&rc.closeRead) != 1 {
			t.Fatalf("Close: %+v %+v", rc, wc)
		}
	})
	t.Run("one closer for both", func(t *testing.T) {
		cc := new(calls)
		h := &closerHalf{Reader: strings.NewReader("x"), Writer: io.Discard, calls: cc}
		c := duplex.Join(h, h)
		_ = c.CloseRead()
		if cc.get(&cc.close) != 0 {
			t.Fatal("CloseRead closed the open write half")
		}
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatalf("Write after CloseRead = %v", err)
		}
		_ = c.CloseWrite()
		_ = c.Close()
		if n := cc.get(&cc.close); n != 1 {
			t.Fatalf("closed %d times", n)
		}
	})
	t.Run("one closer, Close", func(t *testing.T) {
		cc := new(calls)
		h := &tcpHalf{closerHalf{Reader: strings.NewReader("x"), Writer: io.Discard, calls: cc}}
		c := duplex.Join(h, h)
		_ = c.Close()
		if cc.get(&cc.close) != 1 || cc.get(&cc.closeRead)+cc.get(&cc.closeWrite) != 0 {
			t.Fatalf("calls %+v", cc)
		}
	})
	t.Run("one value with CloseWrite", func(t *testing.T) {
		for _, readFirst := range []bool{true, false} {
			cc := new(calls)
			h := &tlsHalf{closerHalf{Reader: strings.NewReader(""), Writer: io.Discard, calls: cc}}
			c := duplex.Join(h, h)
			if readFirst {
				_ = c.CloseRead()
				_ = c.CloseWrite()
			} else {
				_ = c.CloseWrite()
				_ = c.CloseRead()
			}
			_ = c.Close()
			if cc.get(&cc.close) != 1 {
				t.Fatalf("read first %v: closed %d times", readFirst, cc.get(&cc.close))
			}
			if !readFirst && cc.get(&cc.closeWrite) != 1 {
				t.Fatal("CloseWrite was not passed on")
			}
		}
	})
	t.Run("not comparable", func(t *testing.T) {
		var n int
		h := valueHalf{n: &n}
		c := duplex.Join(h, h)
		_ = c.CloseRead()
		_ = c.Close()
		if n != 2 { // two values, each closed once
			t.Fatalf("closed %d times", n)
		}
	})
}

// deadlineHalf records the deadlines set on it.
type deadlineHalf struct {
	io.Reader
	io.Writer
	*calls
}

func (h *deadlineHalf) SetReadDeadline(t time.Time) error {
	return h.record(&h.readDeadlines, t)
}
func (h *deadlineHalf) SetWriteDeadline(t time.Time) error {
	return h.record(&h.writeDeadlines, t)
}

// anyDeadlineHalf has SetDeadline only.
type anyDeadlineHalf struct {
	io.Reader
	io.Writer
	*calls
}

func (h *anyDeadlineHalf) SetDeadline(t time.Time) error { return h.record(&h.anyDead, t) }

func TestDeadlines(t *testing.T) {
	t1 := time.Now().Add(time.Hour)
	t.Run("forwarded", func(t *testing.T) {
		rc, wc := new(calls), new(calls)
		c := duplex.Join(&deadlineHalf{Reader: strings.NewReader(""), calls: rc}, &deadlineHalf{Writer: io.Discard, calls: wc})
		if err := c.SetDeadline(t1); err != nil {
			t.Fatal(err)
		}
		if len(rc.readDeadlines) != 1 || len(wc.writeDeadlines) != 1 || len(rc.writeDeadlines)+len(wc.readDeadlines) != 0 {
			t.Fatalf("calls %+v %+v", rc, wc)
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		c := duplex.Join(strings.NewReader(""), io.Discard)
		for _, err := range []error{c.SetDeadline(t1), c.SetReadDeadline(t1), c.SetWriteDeadline(t1)} {
			if !errors.Is(err, errors.ErrUnsupported) {
				t.Fatalf("err = %v", err)
			}
		}
		if err := c.SetDeadline(time.Time{}); err != nil {
			t.Fatalf("clearing = %v", err)
		}
	})
	t.Run("SetDeadline", func(t *testing.T) {
		rc, wc := new(calls), new(calls)
		c := duplex.Join(&anyDeadlineHalf{Reader: strings.NewReader(""), calls: rc}, &anyDeadlineHalf{Writer: io.Discard, calls: wc})
		if err := c.SetReadDeadline(t1); err != nil || len(rc.anyDead) != 1 || len(wc.anyDead) != 0 {
			t.Fatalf("SetReadDeadline = %v, %+v %+v", err, rc, wc)
		}
		cc := new(calls)
		h := &anyDeadlineHalf{Reader: strings.NewReader(""), Writer: io.Discard, calls: cc}
		c = duplex.Join(h, h)
		if err := c.SetReadDeadline(t1); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("SetReadDeadline of a shared half = %v", err)
		}
		if err := c.SetDeadline(t1); err != nil || len(cc.anyDead) != 1 {
			t.Fatalf("SetDeadline = %v, %+v", err, cc)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		noLeaks(t)
		a, b := net.Pipe()
		defer func() { _ = a.Close() }()
		c := duplex.Join(b, b)
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read = %v", err)
		}
		_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
		if _, err := c.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write = %v", err)
		}
	})
	t.Run("closed", func(t *testing.T) {
		c := duplex.Join(nil, nil)
		_ = c.Close()
		if err := c.SetDeadline(t1); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("SetDeadline = %v", err)
		}
	})
}

type addrHalf struct {
	io.Reader
	local, remote net.Addr
}

func (h addrHalf) LocalAddr() net.Addr  { return h.local }
func (h addrHalf) RemoteAddr() net.Addr { return h.remote }

func TestAddrs(t *testing.T) {
	l1, r1 := &net.TCPAddr{Port: 1}, &net.TCPAddr{Port: 2}
	c := duplex.Join(addrHalf{local: l1}, struct {
		io.Writer
		addrHalf
	}{io.Discard, addrHalf{remote: r1}})
	if c.LocalAddr() != l1 || c.RemoteAddr() != r1 {
		t.Fatalf("addrs %v %v", c.LocalAddr(), c.RemoteAddr())
	}
}

// writerToHalf and readerFromSink record how a copy reached them.
type writerToHalf struct{ io.Reader }

type readerFromSink struct {
	bytes.Buffer
	src io.Reader
}

func (s *readerFromSink) ReadFrom(r io.Reader) (int64, error) {
	s.src = r
	return s.Buffer.ReadFrom(r)
}

func TestCopyForwarding(t *testing.T) {
	var sink readerFromSink
	if n, err := duplex.Join(strings.NewReader("data"), nil).WriteTo(&sink); n != 4 || err != nil || sink.src != nil {
		t.Fatalf("WriteTo of an io.WriterTo = %d, %v, ReadFrom of %T", n, err, sink.src)
	}
	plain := writerToHalf{strings.NewReader("data")}
	sink = readerFromSink{}
	if n, err := io.Copy(&sink, duplex.Join(plain, nil)); n != 4 || err != nil || sink.src == nil || sink.src == io.Reader(plain) {
		t.Fatalf("WriteTo of a plain half = %d, %v, ReadFrom of %T", n, err, sink.src)
	}
	var out readerFromSink
	src := writerToHalf{strings.NewReader("data")}
	if n, err := duplex.Join(nil, &out).ReadFrom(src); n != 4 || err != nil || out.src != io.Reader(src) {
		t.Fatalf("ReadFrom = %d, %v, source %T", n, err, out.src)
	}
}

func TestZeroAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	var in duplex.Reader
	var up duplex.Writer
	_, _ = in.Append(zeroReader{})
	_ = up.Swap(t.Context(), io.Discard)
	buf := make([]byte, 64)
	for _, c := range []*duplex.Conn{duplex.Join(zeroReader{}, io.Discard), duplex.Join(&in, &up)} {
		if n := testing.AllocsPerRun(1000, func() {
			_, _ = c.Read(buf)
			_, _ = c.Write(buf)
		}); n != 0 {
			t.Fatalf("%v allocations per Read and Write", n)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

// TestConcurrent reads, writes, sets deadlines and closes at once.
func TestConcurrent(t *testing.T) {
	noLeaks(t)
	for range 20 {
		ra, rb := net.Pipe()
		wa, wb := net.Pipe()
		c := duplex.Join(rb, wa)
		var wg sync.WaitGroup
		wg.Go(func() { _, _ = io.Copy(io.Discard, wb) })
		wg.Go(func() {
			for {
				if _, err := ra.Write([]byte("abcdef")); err != nil {
					return
				}
			}
		})
		for range 2 {
			wg.Go(func() { _, _ = io.Copy(io.Discard, c) })
			wg.Go(func() {
				for {
					if _, err := c.Write([]byte("012345")); err != nil {
						return
					}
				}
			})
		}
		wg.Go(func() { _ = c.SetDeadline(time.Now().Add(time.Hour)) })
		time.Sleep(time.Millisecond)
		_ = c.Close()
		_ = ra.Close()
		_ = wb.Close()
		wg.Wait()
	}
}
