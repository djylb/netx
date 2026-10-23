package netx

import (
	"context"
	"io"
)

// relayDirection copies src to dst for Relay and Copy, through f when it is
// active.
func relayDirection(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, error) {
	e := newRelayEnds(dst, src)
	s, d := &e.src, &e.dst
	if !f.active() {
		return relayCopy(d, s)
	}
	var prefix int64
	if f.First != nil && !s.readsDatagrams() {
		// A stream's first read goes through the buffer, for First, which
		// the copy of the rest, however it goes, then never sees.
		n, over, err := copyFirstPiece(ctx, d.w, s, f)
		if over {
			return n, err
		}
		prefix = n
		rest := *f
		rest.First = nil
		f = &rest
	}
	if canSplice(d, s) {
		n, ok, err := spliceCopy(ctx, d, s, f)
		if ok {
			return prefix + n, err
		}
		prefix += n
	}
	if s.readsDatagrams() {
		n, err := copyDatagrams(ctx, d.w, s, f)
		return prefix + n, err
	}
	n, err := copyStream(ctx, d.w, s, f)
	return prefix + n, err
}

// relayCopy copies s to d without a flow.
func relayCopy(d *relaySink, s *relaySource) (int64, error) {
	if canSplice(d, s) {
		n, ok, err := spliceCopy(context.Background(), d, s, nil)
		if !ok {
			var m int64
			m, err = io.Copy(d.w, s.r)
			n += m
		}
		return n, err
	}
	if wt, ok := s.ownWriterTo(); ok {
		return wt.WriteTo(d.w)
	}
	// Before the writing end's ReadFrom, which would copy datagrams through
	// a buffer of its own, perhaps cutting them, and drop empty ones.
	if s.readsDatagrams() {
		return copyDatagrams(context.Background(), d.w, s, nil)
	}
	if rf, ok := d.w.(io.ReaderFrom); ok && !isStdConn(d.w) {
		return rf.ReadFrom(s.r)
	}
	return copyStream(context.Background(), d.w, s, nil)
}

// relaySocket is a source that Relay can wait on without a buffer; see
// socketSource.
type relaySocket interface {
	// wait waits until the source has data, an end or an error, reports
	// an end, and returns the error of a failed wait as a read would.
	wait() (end bool, err error)
	// readNow reads what the source holds without waiting, or reports
	// blocked.
	readNow(b []byte) (n int, blocked bool, err error)
}

// eofNil returns err, or nil for io.EOF, which ends a copy without an error.
func eofNil(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}

// copyOnce reads src once, for at most n bytes of a pooled buffer, gives
// what it read to first, if not nil, and writes it to dst. It reports
// whether the copy is over: at the end of src, with a nil error, or on an
// error.
func copyOnce(dst io.Writer, src io.Reader, n int64, f *RelayFlow, first func([]byte)) (int64, bool, error) {
	pool := poolFor(int(min(n, relayBufSize)))
	bp := pool.Get()
	defer pool.Put(bp)
	r, rerr := src.Read((*bp)[:min(n, relayBufSize)])
	var written int64
	if r > 0 {
		if first != nil {
			first((*bp)[:r])
		}
		var err error
		if written, err = f.write(dst, (*bp)[:r]); err != nil {
			return written, true, err
		}
	}
	return written, rerr != nil, eofNil(rerr)
}

// copyFirstPiece copies the first non-empty read of src to dst through
// Relay's buffer, giving it to f.First first, and reports whether the copy
// is over.
func copyFirstPiece(ctx context.Context, dst io.Writer, s *relaySource, f *RelayFlow) (int64, bool, error) {
	sock := s.socket()
	for {
		end := false
		if sock != nil {
			var err error
			if end, err = sock.wait(); err != nil {
				return 0, true, err
			}
		}
		n := int64(relayBufSize)
		if !end {
			var err error
			if n, err = f.wait(ctx, relayBufSize); err != nil {
				return 0, true, err
			}
		}
		if written, over, err := copyOnce(dst, s.r, n, f, f.First); over || written > 0 {
			return written, over, err
		}
	}
}

// copyStream copies s to dst through a pooled buffer. A source read
// straight from a socket is waited on until it is readable without the
// buffer; without Wait, a read after one that filled the buffer takes only
// what is already there instead, waiting only when there is nothing. A
// blocked Wait holds no buffer either. Other sources keep the buffer, as
// their reads hold it anyway.
func copyStream(ctx context.Context, dst io.Writer, s *relaySource, f *RelayFlow) (int64, error) {
	sock := s.socket()
	paced := f != nil && f.Wait != nil
	var (
		written int64
		bp      *[]byte
		full    bool
	)
	release := func() {
		if bp != nil {
			relayBufs.Put(bp)
			bp = nil
		}
	}
	defer release()
	for {
		end := false
		// With Wait, always: Wait then paces what is there, and the end
		// passes without it.
		if sock != nil && (!full || paced) {
			release()
			var err error
			if end, err = sock.wait(); err != nil {
				return written, err
			}
		}
		n := int64(relayBufSize)
		if !end {
			// At the end there is nothing for Wait to pace.
			if paced {
				release()
			}
			var err error
			if n, err = f.wait(ctx, relayBufSize); err != nil {
				return written, err
			}
		}
		if bp == nil {
			bp = relayBufs.Get()
		}
		buf := (*bp)[:n]
		var (
			r    int
			rerr error
		)
		if sock != nil && full && !paced {
			var blocked bool
			if r, blocked, rerr = sock.readNow(buf); blocked {
				full = false // wait for it without the buffer
				continue
			}
		} else {
			r, rerr = s.r.Read(buf)
		}
		full = r == len(buf)
		if r > 0 {
			m, err := f.write(dst, buf[:r])
			written += m
			if err != nil {
				return written, err
			}
		}
		if rerr != nil {
			return written, eofNil(rerr)
		}
	}
}

// copyDatagrams copies each datagram that a Read of s returns to dst with
// one Write, empty datagrams included, which io.Copy would drop.
func copyDatagrams(ctx context.Context, dst io.Writer, s *relaySource, f *RelayFlow) (int64, error) {
	if s.datagrams != nil && !s.prefixPending() {
		return copySourceDatagrams(ctx, dst, s.datagrams, s.timeouts, f)
	}
	paced := f != nil && f.Wait != nil
	first := f.firstHook()
	var bp *[]byte
	defer func() {
		if bp != nil {
			largeBufs.Put(bp)
		}
	}()
	var written int64
	for {
		if paced && bp != nil {
			// A blocked Wait holds no buffer.
			largeBufs.Put(bp)
			bp = nil
		}
		if _, err := f.wait(ctx, datagramWaitSize); err != nil {
			return written, err
		}
		if bp == nil {
			bp = largeBufs.Get()
		}
		buf := *bp
		n, err := s.r.Read(buf)
		if n > 0 || err == nil {
			if first != nil {
				first(buf[:n])
				first = nil
			}
			m, werr := f.write(dst, buf[:n])
			written += m
			if werr != nil {
				return written, werr
			}
		}
		if err != nil {
			return written, eofNil(err)
		}
	}
}

// copySourceDatagrams copies the datagrams of src to dst with one Write
// each, in the buffers that src hands over, refreshing the deadlines of the
// TimeoutConns ts around src before each.
func copySourceDatagrams(ctx context.Context, dst io.Writer, src datagramSource, ts relayTimeouts, f *RelayFlow) (int64, error) {
	first := f.firstHook()
	var written int64
	for {
		if _, err := f.wait(ctx, datagramWaitSize); err != nil {
			return written, err
		}
		if err := ts.refresh(); err != nil {
			return written, err
		}
		bp, err := src.nextDatagram()
		if err != nil {
			return written, eofNil(err)
		}
		if first != nil {
			first(*bp)
			first = nil
		}
		m, err := f.write(dst, *bp)
		putBuf(bp)
		written += m
		if err != nil {
			return written, err
		}
	}
}
