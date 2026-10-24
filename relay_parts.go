package netx

import (
	"context"
	"errors"
	"io"
	"net"
)

// RelayEnd is an end of a Relay made of a reader and a writer, such as one
// side of a protocol exchange on a connection that carries more afterwards:
// Relay reads Reader and writes Writer as it would read and write them as
// ends of their own, looking through them for splice and its other fast
// paths, so that a part of a connection, such as an *io.LimitedReader over
// it or the parts of a ChainReader, is spliced where the connection would
// be. Reads, writes and closes go to the fields; it is not safe to change
// them while a Relay uses the end.
type RelayEnd struct {
	Reader io.Reader
	Writer io.Writer
	// CloseWriteFunc is called by CloseWrite, as with WithRelayHalfClose
	// when the direction into this end ends; nil calls the CloseWrite
	// method of Writer, if it has one.
	CloseWriteFunc func() error
	// CloseFunc is called by Close, as when the relay ends; nil closes
	// Reader and Writer where they are io.Closers. A relay that stops early,
	// on an error or because its context ended, closes its ends to end the
	// reads and writes that block on them, so CloseFunc must do that then.
	CloseFunc func() error
}

func (e *RelayEnd) Read(p []byte) (int, error) {
	if e == nil || e.Reader == nil {
		return 0, io.EOF
	}
	return e.Reader.Read(p)
}

func (e *RelayEnd) Write(p []byte) (int, error) {
	if e == nil || e.Writer == nil {
		return 0, net.ErrClosed
	}
	return e.Writer.Write(p)
}

// CloseWrite calls CloseWriteFunc, or the CloseWrite method of Writer.
func (e *RelayEnd) CloseWrite() error {
	switch {
	case e == nil:
		return nil
	case e.CloseWriteFunc != nil:
		return e.CloseWriteFunc()
	}
	return closeWrite(e.Writer)
}

// Close calls CloseFunc, or closes Reader and Writer.
func (e *RelayEnd) Close() error {
	switch {
	case e == nil:
		return nil
	case e.CloseFunc != nil:
		return e.CloseFunc()
	}
	var errs []error
	if c, ok := e.Reader.(io.Closer); ok {
		errs = append(errs, c.Close())
	}
	if c, ok := e.Writer.(io.Closer); ok && any(e.Writer) != any(e.Reader) {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// ChainReader reads the parts that Next returns one after another, as
// io.MultiReader does, but lazily: Next is called for the first part, and
// for the next one each time a part reaches EOF, until it returns a nil
// part, so that what follows can depend on what came before, as an HTTP
// body depends on its head. Relay and Copy copy each part as they would
// copy it as a source of its own, so that a part that is a connection, or
// an *io.LimitedReader over one, is spliced where the connection would be.
// An error of Next ends the reading with it. A ChainReader is not safe for
// concurrent use.
type ChainReader struct {
	Next func() (io.Reader, error)
	cur  io.Reader
	done bool
	err  error
}

// part returns the part being read, taking the next when there is none, or
// nil at the end.
func (c *ChainReader) part() (io.Reader, error) {
	for c.cur == nil {
		if c.done || c.err != nil || c.Next == nil {
			return nil, c.err
		}
		c.cur, c.err = c.Next()
		if c.err != nil {
			c.cur = nil
			return nil, c.err
		}
		if c.cur == nil {
			c.done = true
		}
	}
	return c.cur, nil
}

func (c *ChainReader) Read(p []byte) (int, error) {
	for {
		r, err := c.part()
		if err != nil {
			return 0, err
		}
		if r == nil {
			return 0, io.EOF
		}
		n, err := r.Read(p)
		if err == io.EOF {
			c.cur = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

// copyChain copies the parts of c to dst, each as a source of its own.
func copyChain(ctx context.Context, dst io.Writer, c *ChainReader, f *RelayFlow) (int64, error) {
	var total int64
	for {
		part, err := c.part()
		if err != nil || part == nil {
			return total, err
		}
		n, err := relayDirection(ctx, dst, part, f)
		total += n
		if err != nil {
			return total, err
		}
		c.cur = nil
		if n > 0 && f != nil && f.First != nil {
			// First saw this part's first bytes.
			rest := *f
			rest.First = nil
			f = &rest
		}
	}
}
