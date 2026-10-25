package duplex

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Reader is a read half that reads one stream after another, such as the
// channels of an uplink that its sender moves from one connection or
// request to the next. Append adds a stream after the others; each is read
// to its io.EOF and then closed, and the next one goes on where it ended.
// When the streams run out, reads wait for the next Append, or return
// io.EOF after End. The zero value is ready to use. A Reader owns its
// streams: it closes each one it finishes, and Close closes the rest.
//
// An error other than io.EOF from a stream is returned and leaves that
// stream current, since the bytes after it are then unknown.
//
// The streams are read in the order they are appended, so append them in
// the order the sender swapped to them. A stream appended early waits its
// turn, and a sender that swapped before the next stream was appended loses
// nothing: its writes wait in that stream's transport, and reads wait for
// the Append. A read deadline that expires while reads wait for it returns
// a timeout that leaves the Reader usable.
//
// Read may be called concurrently with Append, End, SetReadDeadline and
// Close, and does not allocate.
type Reader struct {
	mu       sync.Mutex
	parts    []*part // parts[0] is read
	ended    bool
	closed   bool
	deadline time.Time
	// gen counts the changes of deadline and of the current stream, so
	// that applyDeadline, which runs unlocked, sets the latest deadline on
	// the latest stream.
	gen     uint64
	changed waiter
}

type part struct {
	r    io.Reader
	done chan struct{}
}

var (
	errEnded   = errors.New("duplex: Append after End")
	errNilPart = errors.New("duplex: Append of a nil stream")
)

// Append adds r to the streams, to be read after those before it, and
// returns a channel that is closed once the Reader has finished r and
// closed it, or closed it with Close: an HTTP handler that appends its
// request body waits on it before it returns. When the Reader is closed or
// ended, Append returns an error and leaves r with the caller.
func (rd *Reader) Append(r io.Reader) (<-chan struct{}, error) {
	if rd == nil {
		return nil, net.ErrClosed
	}
	if r == nil {
		return nil, errNilPart
	}
	rd.mu.Lock()
	switch {
	case rd.closed:
		rd.mu.Unlock()
		return nil, net.ErrClosed
	case rd.ended:
		rd.mu.Unlock()
		return nil, errEnded
	}
	p := &part{r: r, done: make(chan struct{})}
	rd.parts = append(rd.parts, p)
	current := len(rd.parts) == 1
	if current {
		rd.gen++
		rd.changed.broadcast()
	}
	rd.mu.Unlock()
	if current {
		_ = rd.applyDeadline()
	}
	return p.done, nil
}

// End marks the streams appended so far as the last: once they are read,
// reads return io.EOF.
func (rd *Reader) End() error {
	if rd == nil {
		return net.ErrClosed
	}
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if rd.closed {
		return net.ErrClosed
	}
	rd.ended = true
	rd.changed.broadcast()
	return nil
}

// current returns the stream to read, waiting for one, or io.EOF after End.
func (rd *Reader) current() (*part, error) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	for !rd.closed && len(rd.parts) == 0 && !rd.ended {
		if err := rd.changed.wait(&rd.mu, rd.deadline, nil); err != nil {
			return nil, err
		}
	}
	switch {
	case rd.closed:
		return nil, net.ErrClosed
	case len(rd.parts) == 0:
		return nil, io.EOF
	}
	return rd.parts[0], nil
}

// finish moves on from p, at its end, and closes it.
func (rd *Reader) finish(p *part) {
	rd.mu.Lock()
	if rd.closed || len(rd.parts) == 0 || rd.parts[0] != p {
		rd.mu.Unlock()
		return // closed by Close, or finished by a concurrent read
	}
	rd.parts[0] = nil
	rd.parts = rd.parts[1:]
	next := len(rd.parts) > 0
	if next {
		rd.gen++
	}
	rd.mu.Unlock()
	if cl, ok := p.r.(io.Closer); ok {
		_ = cl.Close()
	}
	close(p.done)
	if next {
		_ = rd.applyDeadline()
	}
}

// Read reads the current stream, and at its end the next.
func (rd *Reader) Read(b []byte) (int, error) {
	if rd == nil {
		return 0, net.ErrClosed
	}
	for {
		p, err := rd.current()
		if err != nil {
			return 0, err
		}
		n, err := p.r.Read(b)
		if err != io.EOF {
			return n, err
		}
		rd.finish(p)
		if n > 0 {
			return n, nil
		}
	}
}

// WriteTo copies the streams to w until io.EOF after End, each through
// its own WriteTo or w's ReadFrom, so that sockets and files keep their
// fast paths.
func (rd *Reader) WriteTo(w io.Writer) (int64, error) {
	if rd == nil {
		return 0, net.ErrClosed
	}
	var total int64
	for {
		p, err := rd.current()
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
		n, err := copyTo(w, p.r, p.r)
		total += n
		if err != nil {
			return total, err
		}
		rd.finish(p)
	}
}

// SetReadDeadline sets the deadline for reads and their waits for a
// stream, and on the current stream and those after it, which get it, the
// zero time included, as they become current. It returns an
// error matching errors.ErrUnsupported when the current stream has no
// SetReadDeadline method, but keeps the deadline for the waits and the
// streams to come.
func (rd *Reader) SetReadDeadline(t time.Time) error {
	if rd == nil {
		return net.ErrClosed
	}
	rd.mu.Lock()
	if rd.closed {
		rd.mu.Unlock()
		return net.ErrClosed
	}
	rd.deadline = t
	rd.gen++
	rd.changed.broadcast()
	rd.mu.Unlock()
	return rd.applyDeadline()
}

// applyDeadline sets the read deadline on the current stream, without
// holding rd.mu, since the stream's method is the caller's code and may
// wait for a read that only Close ends. When the deadline or the stream
// changed meanwhile, it sets the new one, so that the last call made sets
// the latest deadline on the latest stream. It returns the error of the
// stream, or one matching errors.ErrUnsupported for a stream without
// SetReadDeadline and a deadline that is not zero.
func (rd *Reader) applyDeadline() error {
	for {
		rd.mu.Lock()
		if rd.closed || len(rd.parts) == 0 {
			rd.mu.Unlock()
			return nil
		}
		p, t, gen := rd.parts[0], rd.deadline, rd.gen
		rd.mu.Unlock()
		var err error
		if d, ok := p.r.(readDeadliner); ok {
			err = d.SetReadDeadline(t)
		} else {
			err = noDeadline(t, errNoReadDeadline)
		}
		rd.mu.Lock()
		latest := rd.gen == gen
		rd.mu.Unlock()
		if latest {
			return err
		}
	}
}

// Close closes the streams that are left and ends the reads that wait.
// Later reads and appends return net.ErrClosed, as does a second Close.
func (rd *Reader) Close() error {
	if rd == nil {
		return net.ErrClosed
	}
	rd.mu.Lock()
	if rd.closed {
		rd.mu.Unlock()
		return net.ErrClosed
	}
	rd.closed = true
	parts := rd.parts
	rd.parts = nil
	rd.changed.broadcast()
	rd.mu.Unlock()
	var errs []error
	for _, p := range parts {
		if cl, ok := p.r.(io.Closer); ok {
			errs = append(errs, cl.Close())
		}
		close(p.done)
	}
	return errors.Join(errs...)
}
