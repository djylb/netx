package wsconn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// countConn is a memConn that counts its writes and can fail them.
type countConn struct {
	memConn
	writes  int
	failAt  int // fail the write that would pass this many bytes; 0 for none
	failErr error
}

func (c *countConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	if c.failAt > 0 && c.out.Len()+len(p) > c.failAt {
		n := c.failAt - c.out.Len()
		c.out.Write(p[:n])
		c.mu.Unlock()
		return n, c.failErr
	}
	defer c.mu.Unlock()
	return c.out.Write(p)
}

// unmaskFrames returns frames with their masking keys zeroed and their
// payloads unmasked, so that the frames of two writers compare.
func unmaskFrames(t *testing.T, b []byte) []byte {
	t.Helper()
	var out []byte
	for len(b) > 0 {
		if len(b) < 2 {
			t.Fatalf("short header")
		}
		hl := 2
		n := uint64(b[1] & 0x7f)
		switch n {
		case 126:
			n = uint64(binary.BigEndian.Uint16(b[2:]))
			hl += 2
		case 127:
			n = binary.BigEndian.Uint64(b[2:])
			hl += 8
		}
		masked := b[1]&maskBit != 0
		var key uint32
		if masked {
			key = binary.LittleEndian.Uint32(b[hl:])
			hl += 4
		}
		end := hl + int(n)
		if end > len(b) {
			t.Fatalf("frame of %d bytes past %d", end, len(b))
		}
		out = append(out, b[:hl]...)
		if masked {
			clear(out[len(out)-4:])
		}
		m := len(out)
		out = append(out, b[hl:end]...)
		if masked {
			mask(out[m:], key, 0)
		}
		b = b[end:]
	}
	return out
}

func batchMessages() [][]byte {
	r := rand.New(rand.NewPCG(1, 2))
	random := make([]byte, 100<<10)
	for i := range random {
		random[i] = byte(r.Uint32())
	}
	return [][]byte{
		{},
		[]byte("x"),
		bytes.Repeat([]byte("a"), 125),
		bytes.Repeat([]byte("b"), 126),
		bytes.Repeat([]byte("c"), 0xffff),
		bytes.Repeat([]byte("d"), 0x10000),
		[]byte(strings.Repeat("0123456789abcdef", 8<<10)),
		random,
		random[:writeBufSize-len(syncTail)],
		random[:writeBufSize+1],
	}
}

// The frames that WriteMessages sends, in one write, are those that
// WriteMessage sends for each message.
func TestWriteMessagesFrames(t *testing.T) {
	msgs := batchMessages()
	for _, client := range []bool{false, true} {
		for _, comp := range []*Compression{nil, {}, {Threshold: 1, Level: 9}} {
			for _, writev := range []bool{false, true} {
				opts := &Options{Compression: comp}
				one := &countConn{memConn: memConn{r: strings.NewReader("")}}
				batch := &countConn{memConn: memConn{r: strings.NewReader("")}}
				a := newTestConn(one, nil, client, opts)
				b := newTestConn(batch, nil, client, opts)
				a.writev, b.writev = writev, writev
				for _, p := range msgs {
					if err := a.WriteMessage(Binary, p); err != nil {
						t.Fatal(err)
					}
				}
				if err := b.WriteMessages(Binary, msgs); err != nil {
					t.Fatal(err)
				}
				name := func() string {
					return strings.Join([]string{map[bool]string{false: "server", true: "client"}[client],
						map[bool]string{false: "plain", true: "deflate"}[comp != nil],
						map[bool]string{false: "", true: "writev"}[writev]}, " ")
				}
				if !bytes.Equal(unmaskFrames(t, one.written()), unmaskFrames(t, batch.written())) {
					t.Errorf("%s: frames differ", name())
				}
				if (!writev || client) && batch.writes != 1 {
					t.Errorf("%s: %d writes", name(), batch.writes)
				}
			}
		}
	}
}

// A batch arrives as its messages, also compressed, in order.
func TestWriteMessagesRoundTrip(t *testing.T) {
	msgs := batchMessages()
	for _, comp := range []*Compression{nil, {}} {
		srv, cli := pair(t, &ServerOptions{Options: Options{Compression: comp}},
			&ClientOptions{Options: Options{Compression: comp}})
		for _, pr := range [][2]*Conn{{srv, cli}, {cli, srv}} {
			w, r := pr[0], pr[1]
			errc := make(chan error, 1)
			go func() { errc <- w.WriteMessages(Binary, msgs) }()
			for i, want := range msgs {
				typ, got, err := r.ReadMessage()
				if err != nil {
					t.Fatal(err)
				}
				if typ != Binary || !bytes.Equal(got, want) {
					t.Fatalf("message %d: %v of %d bytes", i, typ, len(got))
				}
			}
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestWriteMessagesEmptyAndType(t *testing.T) {
	c := &countConn{memConn: memConn{r: strings.NewReader("")}}
	w := newTestConn(c, nil, true, nil)
	if err := w.WriteMessages(Binary, nil); err != nil || c.writes != 0 {
		t.Fatal(err, c.writes)
	}
	if err := w.WriteMessages(MessageType(opPing), [][]byte{{1}}); err == nil {
		t.Fatal("ping batch")
	}
}

// After a close frame, batches fail with net.ErrClosed.
func TestWriteMessagesAfterClose(t *testing.T) {
	c := &countConn{memConn: memConn{r: strings.NewReader("")}}
	w := newTestConn(c, nil, false, nil)
	if err := w.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteMessages(Binary, [][]byte{{1}}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

// A batch that failed after part of it went out fails later writes.
func TestWriteMessagesPartial(t *testing.T) {
	boom := errors.New("boom")
	c := &countConn{memConn: memConn{r: strings.NewReader("")}, failAt: 10, failErr: boom}
	w := newTestConn(c, nil, false, nil)
	if err := w.WriteMessages(Binary, [][]byte{make([]byte, 8), make([]byte, 8)}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	c.failAt = 0
	if err := w.WriteMessage(Binary, []byte{1}); !errors.Is(err, boom) {
		t.Fatal("not sticky:", err)
	}
}

// A batch whose write deadline passes before it starts fails with a
// timeout and leaves the connection usable.
func TestWriteMessagesTimeout(t *testing.T) {
	srv, cli := pair(t, nil, nil)
	if err := srv.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := srv.WriteMessages(Binary, [][]byte{{1}}); !isTimeout(err) {
		t.Fatal(err)
	}
	_ = srv.SetWriteDeadline(time.Time{})
	if err := srv.WriteMessages(Binary, [][]byte{{2}}); err != nil {
		t.Fatal(err)
	}
	if _, p, err := cli.ReadMessage(); err != nil || !bytes.Equal(p, []byte{2}) {
		t.Fatal(p, err)
	}
}

// Concurrent batches and messages keep each batch together.
func TestWriteMessagesConcurrent(t *testing.T) {
	srv, cli := pair(t, &ServerOptions{Options: Options{Compression: &Compression{Threshold: 1}}},
		&ClientOptions{Options: Options{Compression: &Compression{}}})
	const writers, rounds, per = 4, 50, 5
	var wg sync.WaitGroup
	for g := range writers {
		wg.Go(func() {
			batch := make([][]byte, per)
			for r := range rounds {
				for i := range batch {
					batch[i] = []byte{byte(g), byte(i), byte(r)}
				}
				if err := cli.WriteMessages(Binary, batch); err != nil {
					t.Error(err)
					return
				}
				if err := cli.WriteMessage(Binary, []byte{byte(g), 0xff}); err != nil {
					t.Error(err)
					return
				}
				_ = cli.Ping(nil)
			}
		})
	}
	for got := 0; got < writers*rounds*(per+1); got++ {
		_, p, err := srv.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) == 3 && p[1] == 0 {
			for i := 1; i < per; i++ {
				_, q, err := srv.ReadMessage()
				if err != nil {
					t.Fatal(err)
				}
				got++
				if len(q) != 3 || q[0] != p[0] || q[1] != byte(i) || q[2] != p[2] {
					t.Fatalf("batch broken: %v after %v", q, p)
				}
			}
		}
	}
	wg.Wait()
}

func TestWriteMessagesAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector drops pooled deflaters")
	}
	msgs := [][]byte{make([]byte, 100), make([]byte, 1000), make([]byte, 40<<10)}
	for _, client := range []bool{false, true} {
		for _, comp := range []*Compression{nil, {}} {
			w := newTestConn(&discardConn{}, nil, client, &Options{Compression: comp})
			w.writev = true
			n := testing.AllocsPerRun(100, func() {
				if err := w.WriteMessages(Binary, msgs); err != nil {
					t.Fatal(err)
				}
			})
			if n != 0 {
				t.Errorf("client %v compressed %v: %v allocations", client, comp != nil, n)
			}
		}
	}
}
