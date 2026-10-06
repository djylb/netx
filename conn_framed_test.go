package netx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type byteBufferConn struct {
	bytes.Buffer
}

func (c *byteBufferConn) Close() error                     { return nil }
func (c *byteBufferConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *byteBufferConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *byteBufferConn) SetDeadline(time.Time) error      { return nil }
func (c *byteBufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *byteBufferConn) SetWriteDeadline(time.Time) error { return nil }

type writeFailConn struct {
	byteBufferConn
	err error
}

func (c *writeFailConn) Write([]byte) (int, error) { return 0, c.err }

// countingWriteConn records every underlying Write call.
type countingWriteConn struct {
	byteBufferConn
	writes int
}

func (c *countingWriteConn) Write(p []byte) (int, error) {
	c.writes++
	return c.byteBufferConn.Write(p)
}

// partialWriteConn accepts limit bytes in total and then fails with err.
type partialWriteConn struct {
	byteBufferConn
	limit int
	err   error
}

func (c *partialWriteConn) Write(p []byte) (int, error) {
	n := min(len(p), c.limit)
	c.limit -= n
	_, _ = c.byteBufferConn.Write(p[:n])
	if n < len(p) {
		return n, c.err
	}
	return n, nil
}

// fullWriteErrConn writes everything and still reports err, like an observer
// that rejects bytes after they were sent.
type fullWriteErrConn struct {
	byteBufferConn
	err error
}

func (c *fullWriteErrConn) Write(p []byte) (int, error) {
	n, _ := c.byteBufferConn.Write(p)
	return n, c.err
}

type framedReadStep struct {
	data []byte
	err  error
}

// framedScriptConn returns its steps in order: data chunks may be split by
// small reads, and an error step is returned once with no data.
type framedScriptConn struct {
	byteBufferConn
	steps []framedReadStep
}

func (c *framedScriptConn) Read(p []byte) (int, error) {
	if len(c.steps) == 0 {
		return 0, io.EOF
	}
	step := &c.steps[0]
	if step.err != nil {
		c.steps = c.steps[1:]
		return 0, step.err
	}
	n := copy(p, step.data)
	step.data = step.data[n:]
	if len(step.data) == 0 {
		c.steps = c.steps[1:]
	}
	return n, nil
}

func framedTimeoutError() error {
	return &net.OpError{Op: "read", Net: "pipe", Err: os.ErrDeadlineExceeded}
}

func frameBytes(payload string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(payload))), payload...)
}

func TestFramedConnWriteRejectsOversizedPayload(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	payload := bytes.Repeat([]byte("a"), MaxFramePayload+123)

	n, err := fc.Write(payload)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Write() error = %v, want %v", err, ErrFrameTooLarge)
	}
	if n != 0 {
		t.Fatalf("Write() n = %d, want 0", n)
	}
	if raw.Len() != 0 {
		t.Fatalf("wire len = %d, want 0", raw.Len())
	}
}

func TestFramedConnWriteReturnsZeroOnUnderlyingError(t *testing.T) {
	writeErr := errors.New("write failed")
	fc := NewFramedConn(&writeFailConn{err: writeErr})

	n, err := fc.Write([]byte("payload"))
	if !errors.Is(err, writeErr) {
		t.Fatalf("Write() error = %v, want %v", err, writeErr)
	}
	if n != 0 {
		t.Fatalf("Write() n = %d, want 0", n)
	}
}

func TestFramedConnReadKeepsFrameTailForSmallBuffer(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	if err := fc.WriteFrame([]byte("abcdef")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	buf := make([]byte, 2)
	n, err := fc.Read(buf)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "ab" {
		t.Fatalf("first Read() = %q, want %q", got, "ab")
	}
	n, err = fc.Read(buf)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "cd" {
		t.Fatalf("second Read() = %q, want %q", got, "cd")
	}
	n, err = fc.Read(buf)
	if err != nil {
		t.Fatalf("third Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "ef" {
		t.Fatalf("third Read() = %q, want %q", got, "ef")
	}
}

func TestFramedConnReadFrameReturnsPendingTail(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	if err := fc.WriteFrame([]byte("abcdef")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	buf := make([]byte, 2)
	n, err := fc.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "ab" {
		t.Fatalf("Read() = %q, want %q", got, "ab")
	}
	frame, err := fc.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if got := string(frame); got != "cdef" {
		t.Fatalf("ReadFrame() = %q, want %q", got, "cdef")
	}
}

func TestFramedConnReadWriteFrame(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	if err := fc.WriteFrame([]byte("hello")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if got := int(binary.BigEndian.Uint16(raw.Bytes()[:2])); got != 5 {
		t.Fatalf("wire frame len = %d, want 5", got)
	}
	frame, err := fc.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if string(frame) != "hello" {
		t.Fatalf("ReadFrame() = %q, want %q", string(frame), "hello")
	}

	if err := fc.WriteFrame(nil); err != nil {
		t.Fatalf("WriteFrame(nil) error = %v", err)
	}
	frame, err = fc.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame(empty) error = %v", err)
	}
	if len(frame) != 0 {
		t.Fatalf("ReadFrame(empty) len = %d, want 0", len(frame))
	}
}

func TestFramedConnHelpersHandleNilUnderlyingConn(t *testing.T) {
	var nilConn *FramedConn
	if _, err := nilConn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := nilConn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Close() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if got := nilConn.LocalAddr(); got != nil {
		t.Fatalf("nil LocalAddr() = %v, want nil", got)
	}
	if got := nilConn.RemoteAddr(); got != nil {
		t.Fatalf("nil RemoteAddr() = %v, want nil", got)
	}

	malformed := &FramedConn{}
	if _, err := malformed.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := malformed.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Close() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if got := malformed.LocalAddr(); got != nil {
		t.Fatalf("malformed LocalAddr() = %v, want nil", got)
	}
	if got := malformed.RemoteAddr(); got != nil {
		t.Fatalf("malformed RemoteAddr() = %v, want nil", got)
	}
}

func TestFramedConnDatagramReadsDiscardFrameTail(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw, WithDatagramReads())
	for _, frame := range []string{"abcdef", "gh", "", "ijk", "lmnop"} {
		if err := fc.WriteFrame([]byte(frame)); err != nil {
			t.Fatalf("WriteFrame(%q) error = %v", frame, err)
		}
	}

	buf := make([]byte, 2)
	for _, want := range []string{"ab", "gh", ""} {
		n, err := fc.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("Read() = %q, want %q", got, want)
		}
	}
	// An empty buffer consumes one frame, like a UDP read into an empty buffer.
	if n, err := fc.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v, want 0, nil", n, err)
	}
	frame, err := fc.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if got := string(frame); got != "lmnop" {
		t.Fatalf("ReadFrame() = %q, want %q", got, "lmnop")
	}
	if _, err := fc.Read(buf); err != io.EOF {
		t.Fatalf("Read() at end error = %v, want %v", err, io.EOF)
	}
}

func TestFramedConnStreamReadsKeepFrameTailAcrossFrames(t *testing.T) {
	raw := &byteBufferConn{}
	fc := NewFramedConn(raw)
	for _, frame := range []string{"abcde", "fg"} {
		if err := fc.WriteFrame([]byte(frame)); err != nil {
			t.Fatalf("WriteFrame(%q) error = %v", frame, err)
		}
	}
	if n, err := fc.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v, want 0, nil", n, err)
	}

	buf := make([]byte, 2)
	for _, want := range []string{"ab", "cd", "e", "fg"} {
		n, err := fc.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("Read() = %q, want %q", got, want)
		}
	}
}

func TestFramedConnMidFrameReadErrorIsStickyDesync(t *testing.T) {
	tests := []struct {
		name     string
		datagram bool
		bufLen   int
		steps    []framedReadStep
		wantEOF  bool
	}{
		{
			name:  "timeout inside header",
			steps: []framedReadStep{{data: []byte{0}}, {err: framedTimeoutError()}},
		},
		{
			name:  "timeout after header",
			steps: []framedReadStep{{data: []byte{0, 10}}, {err: framedTimeoutError()}},
		},
		{
			name:  "timeout inside payload",
			steps: []framedReadStep{{data: []byte{0, 10, 'x', 'y', 'z'}}, {err: framedTimeoutError()}},
		},
		{
			name:   "timeout inside stream tail",
			bufLen: 2,
			steps:  []framedReadStep{{data: []byte{0, 10, 'x', 'y', 'z'}}, {err: framedTimeoutError()}},
		},
		{
			name:     "timeout inside datagram tail",
			datagram: true,
			bufLen:   2,
			steps:    []framedReadStep{{data: []byte{0, 10, 'x', 'y', 'z'}}, {err: framedTimeoutError()}},
		},
		{
			name:    "eof inside header",
			steps:   []framedReadStep{{data: []byte{0}}},
			wantEOF: true,
		},
		{
			name:    "eof after header",
			steps:   []framedReadStep{{data: []byte{0, 10}}},
			wantEOF: true,
		},
		{
			name:    "eof inside payload",
			steps:   []framedReadStep{{data: []byte{0, 10, 'x', 'y', 'z'}}},
			wantEOF: true,
		},
		{
			name:     "eof inside datagram tail",
			datagram: true,
			bufLen:   2,
			steps:    []framedReadStep{{data: []byte{0, 10, 'x', 'y', 'z'}}},
			wantEOF:  true,
		},
	}

	for _, tt := range tests {
		for _, useReadFrame := range []bool{false, true} {
			name := tt.name + "/Read"
			if useReadFrame {
				name = tt.name + "/ReadFrame"
			}
			t.Run(name, func(t *testing.T) {
				steps := append([]framedReadStep(nil), tt.steps...)
				if tt.wantEOF {
					steps = append(steps, framedReadStep{err: io.EOF})
				}
				// A complete frame after the failure must not be decoded from the desynced stream.
				steps = append(steps, framedReadStep{data: frameBytes("abc")})
				var opts []FramedOption
				if tt.datagram {
					opts = append(opts, WithDatagramReads())
				}
				fc := NewFramedConn(&framedScriptConn{steps: steps}, opts...)
				bufLen := tt.bufLen
				if bufLen == 0 {
					bufLen = 64
				}

				read := func() error {
					if useReadFrame {
						_, err := fc.ReadFrame()
						return err
					}
					n, err := fc.Read(make([]byte, bufLen))
					if n != 0 {
						t.Fatalf("Read() n = %d, want 0 on a partial frame", n)
					}
					return err
				}

				err := read()
				assertFrameDesync(t, err)
				if tt.wantEOF {
					if !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
						t.Fatalf("error = %v, want io.ErrUnexpectedEOF and not io.EOF", err)
					}
				} else if !strings.Contains(err.Error(), "timeout") {
					t.Fatalf("error = %q, want the timeout cause in the message", err)
				}
				if err2 := read(); err2 != err {
					t.Fatalf("second read error = %v, want sticky %v", err2, err)
				}
			})
		}
	}
}

// IsTimeout matches the ETIMEDOUT errno table before net.Error.Timeout, so a
// desync caused by a kernel-reported timeout must hide that errno as well.
func TestFramedConnMidFrameErrnoTimeoutIsNotTimeout(t *testing.T) {
	cause := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", timedOutErrnos[0])}
	if !IsTimeout(cause) {
		t.Fatalf("IsTimeout(%v) = false, want true", cause)
	}
	fc := NewFramedConn(&framedScriptConn{steps: []framedReadStep{{data: []byte{0, 10, 'x'}}, {err: cause}}})
	_, err := fc.ReadFrame()
	assertFrameDesync(t, err)
	if errorIsAny(err, timedOutErrnos) {
		t.Fatalf("error = %v matches the timeout errno, want it hidden", err)
	}
	if kind := NetErrorKind(err); kind == "timeout" {
		t.Fatalf("NetErrorKind(%v) = %q, want a non-timeout kind", err, kind)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		t.Fatalf("errors.As(%v, *net.OpError) = true, want the timeout cause hidden", err)
	}
}

// A desync wraps a cause that is not a timeout, so errors.Is, errors.As and
// the classifiers still see it.
func TestFramedConnDesyncKeepsNonTimeoutCause(t *testing.T) {
	if len(connResetErrnos) == 0 {
		t.Skip("no connection reset errno on this platform")
	}
	cause := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", connResetErrnos[0])}
	check := func(t *testing.T, err error) {
		t.Helper()
		assertFrameDesync(t, err)
		if !errors.Is(err, connResetErrnos[0]) {
			t.Fatalf("errors.Is(%v, %v) = false, want the cause matched", err, connResetErrnos[0])
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr != cause {
			t.Fatalf("errors.As(%v, *net.OpError) = %v, want the cause", err, opErr)
		}
		if kind := NetErrorKind(err); kind != "rst" {
			t.Fatalf("NetErrorKind(%v) = %q, want rst", err, kind)
		}
	}

	t.Run("read", func(t *testing.T) {
		fc := NewFramedConn(&framedScriptConn{steps: []framedReadStep{{data: []byte{0, 10, 'x'}}, {err: cause}}})
		_, err := fc.ReadFrame()
		check(t, err)
	})
	t.Run("write", func(t *testing.T) {
		fc := NewFramedConn(&partialWriteConn{limit: 3, err: cause})
		_, err := fc.Write([]byte("payload"))
		check(t, err)
	})
}

func assertFrameDesync(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrFrameDesync) {
		t.Fatalf("error = %v, want %v", err, ErrFrameDesync)
	}
	if IsTimeout(err) {
		t.Fatalf("IsTimeout(%v) = true, want false so retry loops stop", err)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("errors.Is(%v, os.ErrDeadlineExceeded) = true, want false", err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || ne.Timeout() {
		t.Fatalf("error = %v, want a net.Error that is not a timeout", err)
	}
}

func TestFramedConnBoundaryReadErrorsStayRetryable(t *testing.T) {
	for _, datagram := range []bool{false, true} {
		var opts []FramedOption
		if datagram {
			opts = append(opts, WithDatagramReads())
		}
		raw := &framedScriptConn{steps: []framedReadStep{
			{err: framedTimeoutError()},
			{data: frameBytes("ok")},
			{err: framedTimeoutError()},
			{data: frameBytes("again")},
		}}
		fc := NewFramedConn(raw, opts...)

		buf := make([]byte, 16)
		if _, err := fc.Read(buf); !IsTimeout(err) || errors.Is(err, ErrFrameDesync) {
			t.Fatalf("datagram=%t first Read() error = %v, want plain timeout", datagram, err)
		}
		n, err := fc.Read(buf)
		if err != nil || string(buf[:n]) != "ok" {
			t.Fatalf("datagram=%t Read() after timeout = %q, %v, want %q", datagram, buf[:n], err, "ok")
		}
		if _, err := fc.ReadFrame(); !IsTimeout(err) || errors.Is(err, ErrFrameDesync) {
			t.Fatalf("datagram=%t ReadFrame() error = %v, want plain timeout", datagram, err)
		}
		frame, err := fc.ReadFrame()
		if err != nil || string(frame) != "again" {
			t.Fatalf("datagram=%t ReadFrame() after timeout = %q, %v, want %q", datagram, frame, err, "again")
		}
		if _, err := fc.Read(buf); err != io.EOF {
			t.Fatalf("datagram=%t Read() at end error = %v, want clean %v", datagram, err, io.EOF)
		}
	}
}

func TestFramedConnPipeDeadlineMidFrameDesyncs(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	fc := NewFramedConn(client)

	// A deadline between frames leaves the stream usable.
	if err := fc.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := fc.ReadFrame(); !IsTimeout(err) {
		t.Fatalf("ReadFrame() error = %v, want timeout", err)
	}
	if err := fc.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	go func() { _, _ = server.Write(frameBytes("ok")) }()
	if frame, err := fc.ReadFrame(); err != nil || string(frame) != "ok" {
		t.Fatalf("ReadFrame() = %q, %v, want %q", frame, err, "ok")
	}

	// A deadline inside a frame desyncs it for good.
	go func() { _, _ = server.Write([]byte{0, 10, 'x', 'y', 'z'}) }()
	if err := fc.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	_, err := fc.Read(make([]byte, 64))
	assertFrameDesync(t, err)
	if err := fc.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := fc.ReadFrame(); !errors.Is(err, ErrFrameDesync) {
		t.Fatalf("ReadFrame() after desync error = %v, want %v", err, ErrFrameDesync)
	}
}

func TestFramedConnPartialWriteIsStickyDesync(t *testing.T) {
	writeErr := framedTimeoutError()
	raw := &partialWriteConn{limit: 3, err: writeErr}
	fc := NewFramedConn(raw)

	n, err := fc.Write([]byte("payload"))
	if n != 0 {
		t.Fatalf("Write() n = %d, want 0", n)
	}
	assertFrameDesync(t, err)
	if !strings.Contains(err.Error(), writeErr.Error()) {
		t.Fatalf("Write() error = %q, want cause %q in the message", err, writeErr)
	}

	raw.limit = 1 << 20
	if err2 := fc.WriteFrame([]byte("next")); err2 != err {
		t.Fatalf("WriteFrame() after desync error = %v, want sticky %v", err2, err)
	}
	if got := raw.Len(); got != 3 {
		t.Fatalf("wire len = %d, want 3 (nothing written after desync)", got)
	}
}

func TestFramedConnWriteErrorBeforeAnyByteStaysRetryable(t *testing.T) {
	raw := &partialWriteConn{limit: 0, err: framedTimeoutError()}
	fc := NewFramedConn(raw)

	if err := fc.WriteFrame([]byte("payload")); !IsTimeout(err) || errors.Is(err, ErrFrameDesync) {
		t.Fatalf("WriteFrame() error = %v, want plain timeout", err)
	}
	raw.limit = 1 << 20
	if err := fc.WriteFrame([]byte("payload")); err != nil {
		t.Fatalf("WriteFrame() retry error = %v", err)
	}
	frame, err := NewFramedConn(&raw.byteBufferConn).ReadFrame()
	if err != nil || string(frame) != "payload" {
		t.Fatalf("decoded frame = %q, %v, want %q", frame, err, "payload")
	}
}

func TestFramedConnCompleteWriteWithErrorDoesNotDesync(t *testing.T) {
	observeErr := errors.New("observer rejected bytes")
	raw := &fullWriteErrConn{err: observeErr}
	fc := NewFramedConn(raw)

	if err := fc.WriteFrame([]byte("one")); !errors.Is(err, observeErr) || errors.Is(err, ErrFrameDesync) {
		t.Fatalf("WriteFrame() error = %v, want %v without desync", err, observeErr)
	}
	raw.err = nil
	if err := fc.WriteFrame([]byte("two")); err != nil {
		t.Fatalf("WriteFrame() after complete frame error = %v", err)
	}
}

func TestFramedConnWritesOneUnderlyingWritePerFrame(t *testing.T) {
	raw := &countingWriteConn{}
	fc := NewFramedConn(raw)
	large := bytes.Repeat([]byte("z"), MaxFramePayload)

	if _, err := fc.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := fc.WriteFrame(nil); err != nil {
		t.Fatalf("WriteFrame(nil) error = %v", err)
	}
	if err := fc.WriteFrame(large); err != nil {
		t.Fatalf("WriteFrame(large) error = %v", err)
	}
	if _, err := fc.Write([]byte("bye")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if raw.writes != 4 {
		t.Fatalf("underlying Write calls = %d, want 4", raw.writes)
	}

	peer := NewFramedConn(&raw.byteBufferConn)
	for _, want := range [][]byte{[]byte("hello"), {}, large, []byte("bye")} {
		frame, err := peer.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() error = %v", err)
		}
		if !bytes.Equal(frame, want) {
			t.Fatalf("ReadFrame() len = %d, want %d", len(frame), len(want))
		}
	}
}

func TestFramedConnTCPWritesDecode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = client.Close() }()
	server := <-accepted
	if server == nil {
		t.Fatal("Accept() failed")
	}
	defer func() { _ = server.Close() }()
	if _, ok := client.(*net.TCPConn); !ok {
		t.Fatalf("client conn = %T, want *net.TCPConn", client)
	}

	frames := [][]byte{[]byte("hello"), {}, bytes.Repeat([]byte("q"), MaxFramePayload)}
	writeErr := make(chan error, 1)
	go func() {
		fc := NewFramedConn(client)
		for _, frame := range frames {
			if err := fc.WriteFrame(frame); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	peer := NewFramedConn(server)
	for _, want := range frames {
		frame, err := peer.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() error = %v", err)
		}
		if !bytes.Equal(frame, want) {
			t.Fatalf("ReadFrame() len = %d, want %d", len(frame), len(want))
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
}

func TestFramedConnConcurrentReadWrite(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()
	a := NewFramedConn(left)
	b := NewFramedConn(right, WithDatagramReads())

	const frames = 200
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	send := func(fc *FramedConn, tag byte) {
		defer wg.Done()
		for i := range frames {
			if _, err := fc.Write([]byte{tag, byte(i)}); err != nil {
				errs <- err
				return
			}
		}
	}
	recv := func(fc *FramedConn, tag byte) {
		defer wg.Done()
		buf := make([]byte, 8)
		for i := range frames {
			n, err := fc.Read(buf)
			if err != nil {
				errs <- err
				return
			}
			if n != 2 || buf[0] != tag || buf[1] != byte(i) {
				errs <- errors.New("unexpected frame " + string(buf[:n]))
				return
			}
		}
	}
	wg.Add(4)
	go send(a, 'a')
	go recv(b, 'a')
	go send(b, 'b')
	go recv(a, 'b')
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

var _ net.Error = (*frameDesyncError)(nil)
