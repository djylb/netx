package wsconn

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"
	"unicode/utf8"
)

func deflated(p []byte) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.BestSpeed)
	_, _ = w.Write(p)
	_ = w.Flush()
	return bytes.TrimSuffix(b.Bytes(), []byte(syncTail))
}

// FuzzReadFrames reads arbitrary input as frames from a client, or from a
// server, with and without permessage-deflate: reads must fail cleanly,
// deliver valid UTF-8 in text messages and respect the read limit.
func FuzzReadFrames(f *testing.F) {
	f.Add(frame(finBit|opText, true, []byte("hello")), false, false)
	f.Add(cat(frame(opBinary, true, []byte("a")), frame(finBit|opPing, true, nil), frame(finBit|opContinuation, true, []byte("b"))), false, false)
	f.Add(frame(finBit|rsv1Bit|opText, true, deflated([]byte("compressed text"))), false, true)
	f.Add(cat(frame(rsv1Bit|opBinary, false, deflated(bytes.Repeat([]byte("xy"), 300))[:5]), frame(finBit|opContinuation, false, deflated(bytes.Repeat([]byte("xy"), 300))[5:])), true, true)
	f.Add(frame(finBit|opClose, true, []byte{0x03, 0xe8, 'o', 'k'}), false, false)
	f.Add([]byte{0x81, 0xfe, 0x00, 0x05}, false, false)
	f.Fuzz(func(t *testing.T, data []byte, client, compressed bool) {
		opts := &Options{ReadLimit: 1 << 16, CloseTimeout: -1}
		if compressed {
			opts.Compression = &Compression{}
		}
		mc := &memConn{r: bytes.NewReader(data)}
		c := NewConn(mc, nil, client, opts)
		for range 64 {
			typ, p, err := c.ReadMessage()
			if err != nil {
				break
			}
			if len(p) > 1<<16 {
				t.Fatalf("message of %d bytes over the limit", len(p))
			}
			if typ == Text && !utf8.Valid(p) {
				t.Fatalf("invalid UTF-8 delivered: %q", p)
			}
		}
		// The same input as a stream.
		mc = &memConn{r: bytes.NewReader(data)}
		_, _ = io.Copy(io.Discard, NewStreamConn(NewConn(mc, nil, client, opts)))
	})
}
