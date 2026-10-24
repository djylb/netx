package wsconn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// memConn is a net.Conn that reads a fixed input and records what is
// written.
type memConn struct {
	r      io.Reader
	mu     sync.Mutex
	out    bytes.Buffer
	closed int
}

func (c *memConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *memConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}
func (c *memConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}
func (c *memConn) LocalAddr() net.Addr              { return &net.TCPAddr{Port: 1} }
func (c *memConn) RemoteAddr() net.Addr             { return &net.TCPAddr{Port: 2} }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

func (c *memConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.out.Bytes())
}

// frame encodes a frame, masked with a fixed key when masked is set.
func frame(first byte, masked bool, payload []byte) []byte {
	var hb [maxHeaderLen]byte
	const key = 0x9abcdef0
	off := putHeader(&hb, first, len(payload), masked, key)
	b := append([]byte(nil), hb[off:]...)
	p := bytes.Clone(payload)
	if masked {
		mask(p, key, 0)
	}
	return append(b, p...)
}

type testFrame struct {
	first   byte
	payload []byte
}

// parseFrames parses the frames that a connection wrote.
func parseFrames(t *testing.T, b []byte) []testFrame {
	t.Helper()
	var fs []testFrame
	for len(b) > 0 {
		if len(b) < 2 {
			t.Fatalf("truncated frame % x", b)
		}
		first, masked, n := b[0], b[1]&maskBit != 0, int(b[1]&0x7f)
		b = b[2:]
		switch n {
		case 126:
			n, b = int(binary.BigEndian.Uint16(b)), b[2:]
		case 127:
			n, b = int(binary.BigEndian.Uint64(b)), b[8:]
		}
		var key uint32
		if masked {
			key, b = binary.LittleEndian.Uint32(b), b[4:]
		}
		p := bytes.Clone(b[:n])
		if masked {
			mask(p, key, 0)
		}
		fs = append(fs, testFrame{first, p})
		b = b[n:]
	}
	return fs
}

// lastClose returns the status code of the last frame written, which must
// be a close frame, or 0 for one without a code.
func lastClose(t *testing.T, c *memConn) StatusCode {
	t.Helper()
	fs := parseFrames(t, c.written())
	if len(fs) == 0 || fs[len(fs)-1].first != finBit|opClose {
		t.Fatalf("no close frame written: %v", fs)
	}
	p := fs[len(fs)-1].payload
	if len(p) < 2 {
		return 0
	}
	return StatusCode(binary.BigEndian.Uint16(p))
}

func serverOver(input []byte, opts *Options) (*Conn, *memConn) {
	mc := &memConn{r: bytes.NewReader(input)}
	return NewConn(mc, nil, false, opts), mc
}

func cat(frames ...[]byte) []byte { return bytes.Join(frames, nil) }

func TestReadMessages(t *testing.T) {
	var pings, pongs []string
	opts := &Options{
		OnPing: func(_ *Conn, d []byte) { pings = append(pings, string(d)) },
		OnPong: func(_ *Conn, d []byte) { pongs = append(pongs, string(d)) },
	}
	in := cat(
		frame(finBit|opText, true, []byte("hello")),
		frame(opBinary, true, []byte{1, 2}),
		frame(finBit|opPing, true, []byte("p1")),
		frame(opContinuation, true, nil),
		frame(finBit|opPong, true, []byte("q")),
		frame(finBit|opContinuation, true, []byte{3}),
		// A 16-bit length for 5 bytes is not minimal, and accepted.
		append([]byte{finBit | opText, maskBit | 126, 0, 5, 0, 0, 0, 0}, "abcde"...),
		frame(finBit|opClose, true, append([]byte{0x03, 0xe8}, "bye"...)),
	)
	c, mc := serverOver(in, opts)
	typ, p, err := c.ReadMessage()
	if err != nil || typ != Text || string(p) != "hello" {
		t.Fatalf("first: %v %q %v", typ, p, err)
	}
	typ, p, err = c.ReadMessage()
	if err != nil || typ != Binary || !bytes.Equal(p, []byte{1, 2, 3}) {
		t.Fatalf("fragmented: %v %v %v", typ, p, err)
	}
	if typ, p, err = c.ReadMessage(); err != nil || string(p) != "abcde" {
		t.Fatalf("non-minimal length: %v %q %v", typ, p, err)
	}
	_, _, err = c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != StatusNormalClosure || ce.Reason != "bye" {
		t.Fatalf("close: %v", err)
	}
	if strings.Join(pings, ",") != "p1" || strings.Join(pongs, ",") != "q" {
		t.Fatalf("pings %v pongs %v", pings, pongs)
	}
	fs := parseFrames(t, mc.written())
	if len(fs) != 2 || fs[0].first != finBit|opPong || string(fs[0].payload) != "p1" {
		t.Fatalf("written frames %v", fs)
	}
	if lastClose(t, mc) != StatusNormalClosure || mc.closed != 1 {
		t.Fatalf("close echo %d, closed %d", lastClose(t, mc), mc.closed)
	}
	if _, _, err := c.ReadMessage(); !errors.As(err, &ce) {
		t.Fatalf("read after close: %v", err)
	}
	if err := c.WriteMessage(Text, []byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestReadEmptyClose(t *testing.T) {
	c, mc := serverOver(frame(finBit|opClose, true, nil), nil)
	_, _, err := c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != StatusNoStatusReceived {
		t.Fatalf("close: %v", err)
	}
	if lastClose(t, mc) != 0 {
		t.Fatal("empty close not echoed empty")
	}
}

func TestProtocolViolations(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 126)
	tests := []struct {
		name string
		in   []byte
		code StatusCode
		err  error
	}{
		{"unmasked", frame(finBit|opText, false, []byte("a")), StatusProtocolError, ErrProtocol},
		{"rsv2", frame(finBit|rsv2Bit|opText, true, nil), StatusProtocolError, ErrProtocol},
		{"rsv3", frame(finBit|rsv3Bit|opBinary, true, nil), StatusProtocolError, ErrProtocol},
		{"rsv1 without deflate", frame(finBit|rsv1Bit|opText, true, nil), StatusProtocolError, ErrProtocol},
		{"opcode 3", frame(finBit|0x3, true, nil), StatusProtocolError, ErrProtocol},
		{"opcode 0xb", frame(finBit|0xb, true, nil), StatusProtocolError, ErrProtocol},
		{"long ping", frame(finBit|opPing, true, long), StatusProtocolError, ErrProtocol},
		{"fragmented ping", frame(opPing, true, nil), StatusProtocolError, ErrProtocol},
		{"ping rsv1", frame(finBit|rsv1Bit|opPing, true, nil), StatusProtocolError, ErrProtocol},
		{"lone continuation", frame(finBit|opContinuation, true, nil), StatusProtocolError, ErrProtocol},
		{"text inside fragments", cat(frame(opText, true, []byte("a")), frame(finBit|opText, true, nil)), StatusProtocolError, ErrProtocol},
		{"invalid utf8", frame(finBit|opText, true, []byte("a\xff")), StatusInvalidPayload, ErrInvalidUTF8},
		{"split invalid utf8", cat(frame(opText, true, []byte("\xe2\x82")), frame(finBit|opContinuation, true, []byte("x"))), StatusInvalidPayload, ErrInvalidUTF8},
		{"truncated utf8", frame(finBit|opText, true, []byte("\xe2\x82")), StatusInvalidPayload, ErrInvalidUTF8},
		{"close 1 byte", frame(finBit|opClose, true, []byte{3}), StatusProtocolError, ErrProtocol},
		{"close 1005", frame(finBit|opClose, true, []byte{0x03, 0xed}), StatusProtocolError, ErrProtocol},
		{"close 999", frame(finBit|opClose, true, []byte{0x03, 0xe7}), StatusProtocolError, ErrProtocol},
		{"close 5000", frame(finBit|opClose, true, []byte{0x13, 0x88}), StatusProtocolError, ErrProtocol},
		{"close reason", frame(finBit|opClose, true, []byte{0x03, 0xe8, 0xff}), StatusInvalidPayload, ErrInvalidUTF8},
		{"length msb", []byte{finBit | opBinary, maskBit | 127, 0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}, StatusProtocolError, ErrProtocol},
		{"too large", frame(finBit|opBinary, true, make([]byte, 101)), StatusMessageTooBig, ErrMessageTooLarge},
		{"too large in fragments", cat(frame(opBinary, true, make([]byte, 60)), frame(finBit|opContinuation, true, make([]byte, 60))), StatusMessageTooBig, ErrMessageTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, mc := serverOver(tt.in, &Options{ReadLimit: 100})
			_, _, err := c.ReadMessage()
			if !errors.Is(err, tt.err) {
				t.Fatalf("err %v, want %v", err, tt.err)
			}
			if code := lastClose(t, mc); code != tt.code {
				t.Fatalf("close code %d, want %d", code, tt.code)
			}
			if mc.closed != 1 {
				t.Fatalf("closed %d times", mc.closed)
			}
			if _, _, err2 := c.ReadMessage(); !errors.Is(err2, tt.err) {
				t.Fatalf("second read %v", err2)
			}
		})
	}
}

func TestClientRefusesMaskedFrames(t *testing.T) {
	mc := &memConn{r: bytes.NewReader(frame(finBit|opText, true, []byte("a")))}
	c := NewConn(mc, nil, true, nil)
	if _, _, err := c.ReadMessage(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err %v", err)
	}
	fs := parseFrames(t, mc.written())
	if len(fs) != 1 || binary.BigEndian.Uint16(fs[0].payload) != uint16(StatusProtocolError) {
		t.Fatalf("frames %v", fs)
	}
}

func TestEOF(t *testing.T) {
	c, _ := serverOver(nil, nil)
	if _, _, err := c.ReadMessage(); err != io.EOF {
		t.Fatalf("EOF between frames: %v", err)
	}
	c, _ = serverOver(frame(finBit|opBinary, true, []byte("abc"))[:5], nil)
	if _, _, err := c.ReadMessage(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("EOF in a frame: %v", err)
	}
	c, _ = serverOver(frame(opBinary, true, []byte("abc")), nil)
	if _, _, err := c.ReadMessage(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("EOF in a message: %v", err)
	}
	c, _ = serverOver(frame(finBit|opBinary, true, []byte("abc"))[:1], nil)
	if _, _, err := c.ReadMessage(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("EOF in a header: %v", err)
	}
}

func TestNextReader(t *testing.T) {
	in := cat(
		frame(opBinary, true, []byte("abc")),
		frame(finBit|opContinuation, true, []byte("def")),
		frame(finBit|opText, true, []byte("next")),
	)
	c, _ := serverOver(in, nil)
	_, r, err := c.NextReader()
	if err != nil {
		t.Fatal(err)
	}
	var b [2]byte
	if n, err := r.Read(b[:]); n != 2 || err != nil {
		t.Fatalf("read %d %v", n, err)
	}
	// The next message discards the rest of this one.
	typ, r2, err := c.NextReader()
	if err != nil || typ != Text {
		t.Fatalf("next %v %v", typ, err)
	}
	if _, err := r.Read(b[:]); !errors.Is(err, errStaleReader) {
		t.Fatalf("stale reader: %v", err)
	}
	if p, err := io.ReadAll(r2); err != nil || string(p) != "next" {
		t.Fatalf("second message %q %v", p, err)
	}
}

func TestStreamConnReads(t *testing.T) {
	in := cat(
		frame(finBit|opBinary, true, []byte("ab")),
		frame(finBit|opBinary, true, nil),
		frame(opText, true, []byte("c")),
		frame(finBit|opPing, true, nil),
		frame(finBit|opContinuation, true, []byte("de")),
		frame(finBit|opClose, true, []byte{0x03, 0xe9}),
	)
	c, _ := serverOver(in, &Options{ReadLimit: 1})
	s := NewStreamConn(c)
	p, err := io.ReadAll(s)
	if err != nil || string(p) != "abcde" {
		t.Fatalf("stream %q %v", p, err)
	}
	// Other close codes are errors of the stream.
	c, _ = serverOver(frame(finBit|opClose, true, []byte{0x03, 0xf3}), nil)
	var ce *CloseError
	if _, err := NewStreamConn(c).Read(make([]byte, 1)); !errors.As(err, &ce) || ce.Code != StatusInternalError {
		t.Fatalf("1011: %v", err)
	}
	// A peer that ends the connection without a close frame ends the
	// stream.
	c, _ = serverOver(frame(finBit|opBinary, true, []byte("x")), nil)
	if p, err := io.ReadAll(NewStreamConn(c)); err != nil || string(p) != "x" {
		t.Fatalf("no close frame: %q %v", p, err)
	}
	if got := NewStreamConn(c).RemoteAddr().(*net.TCPAddr).Port; got != 2 {
		t.Fatalf("remote port %d", got)
	}
}

func TestWriteFrames(t *testing.T) {
	for _, client := range []bool{false, true} {
		mc := &memConn{r: bytes.NewReader(nil)}
		c := NewConn(mc, nil, client, nil)
		big := bytes.Repeat([]byte("0123456789"), 10000)
		if err := c.WriteMessage(Binary, big); err != nil {
			t.Fatal(err)
		}
		if err := c.WriteMessage(Text, []byte("hi")); err != nil {
			t.Fatal(err)
		}
		w, _ := c.NextWriter(Text)
		for range 5000 {
			_, _ = io.WriteString(w, "abcdefghijklmnopqrstuvwxyz")
		}
		_ = w.Close()
		w, _ = c.NextWriter(Binary)
		_ = w.Close()
		if err := c.Ping([]byte("p")); err != nil {
			t.Fatal(err)
		}
		fs := parseFrames(t, mc.written())
		if !bytes.Equal(fs[0].payload, big) || fs[0].first != finBit|opBinary {
			t.Fatalf("client=%v: big frame", client)
		}
		if string(fs[1].payload) != "hi" {
			t.Fatalf("hi: %q", fs[1].payload)
		}
		var msg []byte
		i := 2
		for ; ; i++ {
			msg = append(msg, fs[i].payload...)
			if want := byte(opText); i == 2 && fs[i].first&0xf != want || i > 2 && fs[i].first&0xf != opContinuation {
				t.Fatalf("frame %d first %#x", i, fs[i].first)
			}
			if fs[i].first&finBit != 0 {
				break
			}
		}
		if i == 2 || string(msg) != strings.Repeat("abcdefghijklmnopqrstuvwxyz", 5000) {
			t.Fatalf("NextWriter message: %d frames, %d bytes", i-1, len(msg))
		}
		if f := fs[i+1]; f.first != finBit|opBinary || len(f.payload) != 0 {
			t.Fatalf("empty message %v", f)
		}
		if f := fs[i+2]; f.first != finBit|opPing || string(f.payload) != "p" {
			t.Fatalf("ping %v", f)
		}
		raw := mc.written()
		if client != (raw[1]&maskBit != 0) {
			t.Fatalf("client=%v: mask bit %#x", client, raw[1])
		}
	}
}

func TestCloseCodes(t *testing.T) {
	c, mc := serverOver(nil, &Options{CloseTimeout: -1})
	if err := c.CloseWithStatus(1005, ""); err == nil {
		t.Fatal("1005 sent")
	}
	if err := c.CloseWithStatus(StatusGoingAway, strings.Repeat("x", 124)); err == nil {
		t.Fatal("long reason sent")
	}
	if err := c.CloseWithStatus(4000, "app"); err != nil {
		t.Fatal(err)
	}
	if lastClose(t, mc) != 4000 || mc.closed != 1 {
		t.Fatalf("close %d, closed %d", lastClose(t, mc), mc.closed)
	}
	if err := c.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close: %v", err)
	}
}

// Close of a connection that nobody reads waits for the peer's close frame,
// reading itself.
func TestCloseAwaitsPeer(t *testing.T) {
	in := cat(
		frame(finBit|opBinary, true, []byte("unread")),
		frame(finBit|opClose, true, []byte{0x03, 0xe8}),
	)
	c, mc := serverOver(in, nil)
	start := time.Now()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Close waited for the timeout")
	}
	if lastClose(t, mc) != StatusNormalClosure || mc.closed != 1 {
		t.Fatal("no close frame")
	}
	var ce *CloseError
	if _, _, err := c.ReadMessage(); !errors.As(err, &ce) {
		t.Fatalf("read after close: %v", err)
	}
}
