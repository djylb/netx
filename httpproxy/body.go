package httpproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/djylb/netx/httphead"
)

// chunkState is where a chunked body is.
type chunkState uint8

const (
	chunkSize    chunkState = iota // before a chunk-size line
	chunkData                      // in a chunk's data
	chunkDataEnd                   // before the CRLF after a chunk's data
	chunkTrailer                   // before the trailer section
)

// crlf ends a chunk.
var crlf = []byte("\r\n")

// stream reads a body that must be decoded or encoded on its way, a
// chunked one or one read until close that goes on chunked, from r, and
// returns it as the receiver reads it. A chunked body is decoded strictly
// and, when sent on chunked, encoded again with the same chunk sizes but
// without extensions, so that the receiver sees one reading of it whatever
// leniency the sender relied on; a body sent on without chunking is its
// data alone. Its Read returns what is already there instead of blocking
// for more once it has some. Bodies of a known length, which need neither,
// are not read through a stream but spliced.
type stream struct {
	r *bufio.Reader
	// pending is sent before anything else: a chunk header, the CRLF after
	// a chunk, or the last chunk with the trailer section.
	pending []byte
	// n is what is left of a chunk.
	n int64
	// outN is what is left of the chunk being sent of a body read until
	// close and sent on chunked.
	outN int64
	err  error
	// maxTrailer bounds the trailer section.
	maxTrailer int
	trailer    []byte
	scratch    [20]byte
	in         httphead.Framing
	state      chunkState
	// out tells whether the body is sent on chunked.
	out bool
	// eof is set when the body has been read to its end; what is pending
	// still goes out.
	eof bool
}

// reset sets s up for a body from r delimited by in, Chunked or
// UntilClose, which is sent on chunked when out is set.
func (s *stream) reset(r *bufio.Reader, in httphead.Framing, out bool, maxTrailer int) {
	*s = stream{r: r, in: in, out: out, maxTrailer: maxTrailer, trailer: s.trailer[:0]}
}

func (s *stream) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(s.pending) > 0 {
			k := copy(p[n:], s.pending)
			s.pending = s.pending[k:]
			n += k
			continue
		}
		if s.eof || s.err != nil || n > 0 && !s.ready() {
			break
		}
		k, err := s.step(p[n:])
		n += k
		if err != nil {
			s.err = err
		}
	}
	switch {
	case n > 0:
		return n, nil
	case s.err != nil:
		return 0, s.err
	case s.eof:
		return 0, io.EOF
	}
	return 0, nil
}

// ready reports whether the next step can be taken without waiting for the
// sender.
func (s *stream) ready() bool {
	buffered := s.r.Buffered()
	if buffered == 0 {
		return false
	}
	if s.in == httphead.Chunked && s.state != chunkData {
		b, _ := s.r.Peek(buffered)
		return bytes.IndexByte(b, '\n') >= 0
	}
	return true
}

// step reads the next piece of the body into p, or sets up what is pending.
func (s *stream) step(p []byte) (int, error) {
	if s.in == httphead.Chunked {
		return s.stepChunked(p)
	}
	return s.stepClose(p)
}

// stepClose reads a body that ends when the connection closes.
func (s *stream) stepClose(p []byte) (int, error) {
	if !s.out {
		k, err := s.r.Read(p)
		if err == io.EOF {
			s.eof = true
			err = nil
		}
		return k, err
	}
	if s.outN == 0 {
		// A chunk of what has arrived.
		if s.r.Buffered() == 0 {
			if _, err := s.r.Peek(1); err != nil {
				if err != io.EOF {
					return 0, err
				}
				s.pending = append(s.scratch[:0], "0\r\n\r\n"...)
				s.eof = true
				return 0, nil
			}
		}
		s.outN = int64(s.r.Buffered())
		s.pending = s.chunkHeader(s.outN)
		return 0, nil
	}
	k, err := s.r.Read(p[:min(int64(len(p)), s.outN)])
	s.outN -= int64(k)
	if s.outN == 0 {
		s.pending = crlf
	}
	return k, err
}

func (s *stream) chunkHeader(n int64) []byte {
	b := strconv.AppendInt(s.scratch[:0], n, 16)
	return append(b, '\r', '\n')
}

// stepChunked decodes a chunked body (RFC 9112, section 7.1).
func (s *stream) stepChunked(p []byte) (int, error) {
	switch s.state {
	case chunkSize:
		line, err := readLine(s.r)
		if err != nil {
			return 0, err
		}
		size, err := httphead.ParseChunkSize(line)
		if err != nil {
			return 0, err
		}
		if size == 0 {
			s.state = chunkTrailer
			return 0, nil
		}
		s.n, s.state = size, chunkData
		if s.out {
			s.pending = s.chunkHeader(size)
		}
		return 0, nil
	case chunkData:
		k, err := s.r.Read(p[:min(int64(len(p)), s.n)])
		s.n -= int64(k)
		if s.n == 0 {
			s.state = chunkDataEnd
			err = nil
		} else if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return k, err
	case chunkDataEnd:
		line, err := readLine(s.r)
		if err != nil {
			return 0, err
		}
		if len(line) != 0 {
			return 0, errors.New("httpproxy: malformed chunk")
		}
		s.state = chunkSize
		if s.out {
			s.pending = crlf
		}
		return 0, nil
	case chunkTrailer:
		// After the last chunk: the trailer section, below.
	}
	return 0, s.readTrailer()
}

// readTrailer reads the trailer section and sets up the last chunk with the
// trailer fields that are passed on.
func (s *stream) readTrailer() error {
	t := s.trailer[:0]
	if s.out {
		t = append(t, "0\r\n"...)
	}
	read := 0
	for {
		line, err := readLine(s.r)
		if err != nil {
			return err
		}
		if read += len(line) + 2; read > s.maxTrailer {
			return httphead.ErrTooLarge
		}
		if len(line) == 0 {
			break
		}
		fields, err := httphead.ParseHeader(string(line)+"\n", nil)
		if err != nil {
			return err
		}
		if f := fields[0]; s.out && !forbiddenTrailer(f.Name) {
			t = append(t, f.Name...)
			t = append(t, ": "...)
			t = append(t, f.Value...)
			t = append(t, '\r', '\n')
		}
	}
	if s.out {
		t = append(t, '\r', '\n')
	}
	s.trailer, s.pending, s.eof = t, t, true
	return nil
}

// forbiddenTrailer reports whether a trailer field is one that framing,
// routing or the connection depend on, which a trailer must not carry
// (RFC 9110, section 6.5.1) and which is not sent on.
func forbiddenTrailer(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding", "host", "connection", "keep-alive",
		"proxy-connection", "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate":
		return true
	}
	return false
}

// readLine reads a line of a chunked body, ending in CRLF or LF, at most the
// size of r's buffer, and returns it without the line ending; it is valid
// until the next read of r.
func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, errors.New("httpproxy: chunk line too long")
	case err == io.EOF:
		return nil, io.ErrUnexpectedEOF
	case err != nil:
		return nil, err
	}
	line = line[:len(line)-1]
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	if bytes.IndexByte(line, '\r') >= 0 {
		return nil, errors.New("httpproxy: CR inside a chunk line")
	}
	return line, nil
}

// headPart reads a head and then, up to n bytes, what a reader buffered
// after it, the start of a body that the next part reads beneath the buffer.
// It reads nothing that is not buffered already.
type headPart struct {
	head    []byte
	br      *bufio.Reader
	n       int64
	drained int64
}

func (h *headPart) Read(p []byte) (int, error) {
	if len(h.head) > 0 {
		k := copy(p, h.head)
		h.head = h.head[k:]
		return k, nil
	}
	left := h.n - h.drained
	if left <= 0 || h.br == nil || h.br.Buffered() == 0 {
		return 0, io.EOF
	}
	k, err := h.br.Read(p[:min(int64(len(p)), left, int64(h.br.Buffered()))])
	h.drained += int64(k)
	return k, err
}
