package wsconn

import (
	"bytes"
	"compress/flate"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/httphead"
)

// A client that pings and never reads cannot hold the server's reader in
// the pong write past its read deadline.
func TestPongDoesNotHoldReader(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	srv := NewConn(a, nil, false, nil)
	go func() {
		// Attacker: sends one ping, never reads.
		_, _ = b.Write(frame(finBit|opPing, true, []byte("x")))
	}()
	_ = srv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	done := make(chan error, 1)
	go func() {
		_, _, err := srv.ReadMessage()
		done <- err
	}()
	select {
	case err := <-done:
		t.Logf("ReadMessage returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Errorf("ReadMessage still blocked 2s after a 200ms read deadline: the reader writes the pong itself without a write deadline")
	}
}

// deflateBomb returns a compressed message payload (sync tail removed) that
// inflates to n zero bytes.
func deflateBomb(n int) []byte {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	zero := make([]byte, 1<<20)
	for n > 0 {
		k := min(n, len(zero))
		_, _ = fw.Write(zero[:k])
		n -= k
	}
	_ = fw.Flush()
	p := buf.Bytes()
	return p[:len(p)-4]
}

func TestDeflateBombHitsLimit(t *testing.T) {
	bomb := deflateBomb(64 << 20)
	t.Logf("bomb: %d bytes compressed", len(bomb))
	in := frame(finBit|rsv1Bit|opBinary, true, bomb)
	mc := &memConn{r: bytes.NewReader(in)}
	c := NewConn(mc, nil, false, &Options{ReadLimit: 1 << 20, Compression: &Compression{}})
	var ms0, ms1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms0)
	start := time.Now()
	_, msg, err := c.ReadMessage()
	runtime.ReadMemStats(&ms1)
	t.Logf("err=%v len=%d after %v, TotalAlloc +%d KB", err, len(msg), time.Since(start), (ms1.TotalAlloc-ms0.TotalAlloc)>>10)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if lastClose(t, mc) != StatusMessageTooBig {
		t.Fatal("no 1009")
	}
}

// RFC 8441 does not use Sec-WebSocket-Key; one on an extended CONNECT is
// ignored.
func TestExtendedConnectIgnoresKey(t *testing.T) {
	req := &httphead.Request{Method: "CONNECT", Target: "/", Proto: "HTTP/2.0", Header: httphead.Header{
		{Name: ":protocol", Value: "websocket"},
		{Name: "Sec-WebSocket-Version", Value: "13"},
		{Name: "Sec-WebSocket-Key", Value: "dGhlIHNhbXBsZSBub25jZQ=="},
	}}
	if hs, err := CheckRequest(req, nil); err != nil || !hs.ExtendedConnect {
		t.Fatalf("%+v %v", hs, err)
	}
}

// Concurrent writers, pings, a NextWriter and Close, over TCP, under -race.
func TestCloseStress(t *testing.T) {
	for iter := range 30 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srvCh := make(chan *Conn, 1)
		go func() {
			nc, err := ln.Accept()
			if err != nil {
				srvCh <- nil
				return
			}
			c, err := Accept(t.Context(), nc, &ServerOptions{Options: Options{CloseTimeout: time.Second, Compression: &Compression{Threshold: -1}}})
			if err != nil {
				srvCh <- nil
				return
			}
			srvCh <- c
		}()
		d := &Dialer{ClientOptions: ClientOptions{Options: Options{CloseTimeout: time.Second, Compression: &Compression{Threshold: -1}}}}
		cli, _, err := d.Dial(t.Context(), "ws://"+ln.Addr().String()+"/")
		if err != nil {
			t.Fatal(err)
		}
		srv := <-srvCh
		_ = ln.Close()
		if srv == nil {
			t.Fatal("accept failed")
		}
		var wg sync.WaitGroup
		// server reads
		wg.Go(func() {
			for {
				if _, _, err := srv.ReadMessage(); err != nil {
					return
				}
			}
		})
		wg.Go(func() {
			for {
				if _, _, err := cli.ReadMessage(); err != nil {
					return
				}
			}
		})
		payload := bytes.Repeat([]byte("abc"), 20000)
		for range 4 {
			wg.Go(func() {
				for range 50 {
					if cli.WriteMessage(Binary, payload) != nil {
						return
					}
				}
			})
			wg.Go(func() {
				for range 50 {
					if srv.WriteMessage(Text, payload) != nil {
						return
					}
				}
			})
			wg.Go(func() {
				for range 200 {
					if cli.Ping([]byte("p")) != nil || srv.Ping([]byte("q")) != nil {
						return
					}
				}
			})
		}
		wg.Go(func() {
			w, err := srv.NextWriter(Binary)
			if err != nil {
				return
			}
			for range 20 {
				if _, err := w.Write(payload[:5000]); err != nil {
					break
				}
			}
			_ = w.Close()
		})
		time.Sleep(time.Duration(iter%5) * time.Millisecond)
		var cwg sync.WaitGroup
		cwg.Go(func() { _ = cli.Close() })
		cwg.Go(func() { _ = srv.Close() })
		ch := make(chan struct{})
		go func() { cwg.Wait(); wg.Wait(); close(ch) }()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("iteration %d: deadlock\n%s", iter, buf[:n])
		}
	}
}
