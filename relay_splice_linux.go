package netx

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"syscall"
)

const (
	spliceMove     = 0x1 // SPLICE_F_MOVE
	spliceNonblock = 0x2 // SPLICE_F_NONBLOCK
	fGetPipeSize   = 1032
	// maxSpliceSize is the most one piece asks Wait for; a piece moves at
	// most what its pipe holds.
	maxSpliceSize = 1 << 20
)

// splicePipe is a pipe that splice moves data through. It is empty while in
// splicePipePool; the pool's dropped pipes are closed by a cleanup.
type splicePipe struct {
	fds     [2]int // read end, write end
	size    int    // what the pipe holds
	cleanup runtime.Cleanup
}

var splicePipePool = sync.Pool{
	New: func() any {
		var fds [2]int
		if err := syscall.Pipe2(fds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
			return nil
		}
		// The pipe keeps its default size, as the standard library's do: a
		// larger one would count against the user's pipe page limit while
		// pooled, and once that is used up new pipes, also of other
		// processes of the user, are cut to two pages.
		size, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fds[0]), fGetPipeSize, 0)
		if errno != 0 || size == 0 {
			size = 64 << 10
		}
		p := &splicePipe{fds: fds, size: int(size)}
		p.cleanup = runtime.AddCleanup(p, closePipe, fds)
		return p
	},
}

func closePipe(fds [2]int) {
	_ = syscall.Close(fds[0])
	_ = syscall.Close(fds[1])
}

// spliceCopy copies src to dst, which canSplice accepts, with splice
// through a pipe taken from the pool only while data moves, so that an idle
// relay holds none, and reports each piece to f. A piece for which no pipe
// can be had, as when descriptors run out, goes through Relay's buffer. It
// returns false when splice cannot be used, before it moved anything but the
// prefix, whose bytes it counts, so that the caller copies the rest
// otherwise.
func spliceCopy(ctx context.Context, d *relaySink, s *relaySource, f *RelayFlow) (int64, bool, error) {
	srcConn, _ := s.base.(net.Conn)
	srcSys, ok1 := srcConn.(syscall.Conn)
	dstConn, _ := d.base.(net.Conn)
	dstSys, ok2 := dstConn.(syscall.Conn)
	sock := s.socket()
	if !ok1 || !ok2 || dstConn == nil || sock == nil {
		return 0, false, nil
	}
	srcRaw, err := srcSys.SyscallConn()
	if err != nil {
		return 0, false, nil
	}
	dstRaw, err := dstSys.SyscallConn()
	if err != nil {
		return 0, false, nil
	}
	// The prefix is read through the source, before the connection beneath.
	written, over, err := copyPrefix(ctx, d.w, s, f)
	if over {
		return written, true, err
	}

	// The state of one piece, which the callbacks below share, so that they
	// are made once.
	var (
		p         *splicePipe
		want      int // bytes the piece may take
		inPipe    int
		out       int64
		noPipe    bool
		spliceErr error
	)
	defer func() {
		if p == nil {
			return
		}
		if inPipe == 0 {
			splicePipePool.Put(p)
		} else {
			// Bytes that could not be written are left in it.
			p.cleanup.Stop()
			closePipe(p.fds)
		}
	}()
	fill := func(fd uintptr) bool {
		for {
			if p == nil {
				if p, _ = splicePipePool.Get().(*splicePipe); p == nil {
					noPipe = true
					return true
				}
			}
			// A full pipe is a full read, which the next piece reads
			// without waiting.
			want = int(s.limited(int64(min(want, p.size))))
			m, err := syscall.Splice(int(fd), nil, p.fds[1], nil, want, spliceMove|spliceNonblock)
			switch err {
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				// Wait for data without the pipe.
				splicePipePool.Put(p)
				p = nil
				return false
			}
			inPipe, spliceErr = max(int(m), 0), err
			s.consumed(inPipe)
			return true
		}
	}
	drain := func(fd uintptr) bool {
		for inPipe > 0 {
			m, err := syscall.Splice(p.fds[0], nil, int(fd), nil, inPipe, spliceMove|spliceNonblock)
			switch err {
			case nil:
				inPipe -= int(m)
				out += int64(m)
			case syscall.EINTR:
			case syscall.EAGAIN:
				return false
			default:
				spliceErr = err
				return true
			}
		}
		return true
	}

	full := false
	for spliced := false; ; spliced = true {
		end := false
		if !full || f != nil && f.Wait != nil {
			// Wait for data first, so that Wait paces what is there and the
			// end passes without it, and without the pipe, which is empty,
			// so that neither this wait nor a blocked Wait holds it.
			if p != nil {
				splicePipePool.Put(p)
				p = nil
			}
			if end, err = sock.wait(); err != nil {
				return written, true, err
			}
		}
		n := int64(maxSpliceSize)
		if !end {
			if n, err = f.wait(ctx, maxSpliceSize); err != nil {
				return written, true, err
			}
		}
		if s.exhausted() {
			return written, true, nil // the bound ends the source
		}
		want, noPipe, spliceErr = int(n), false, nil
		if err := s.timeouts.refresh(); err != nil {
			return written, true, err
		}
		if err := srcRaw.Read(fill); err != nil {
			return written, true, rawOpError(err, "read")
		}
		if noPipe {
			// Through the wrappers, whose reads and writes refresh their
			// deadlines.
			m, over, err := copyOnce(d.w, s.r, n, f, nil)
			written += m
			if over {
				return written, true, err
			}
			full = false
			continue
		}
		if spliceErr != nil {
			if !spliced && unsupportedSplice(spliceErr) {
				return written, false, nil
			}
			return written, true, sockOpError(srcConn, "splice", "splice", spliceErr)
		}
		if inPipe == 0 {
			return written, true, nil // EOF
		}
		full = inPipe == want
		out = 0
		writeErr := d.timeouts.refresh()
		if writeErr == nil {
			writeErr = rawOpError(dstRaw.Write(drain), "write")
		}
		written += out
		if writeErr == nil && spliceErr != nil {
			writeErr = sockOpError(dstConn, "splice", "splice", spliceErr)
		}
		if derr := f.done(out); writeErr == nil {
			writeErr = derr
		}
		if writeErr != nil {
			return written, true, writeErr
		}
	}
}

// unsupportedSplice reports whether err means that splice does not work for
// the sockets at all, so that the data is copied otherwise.
func unsupportedSplice(err error) bool {
	switch err {
	case syscall.EINVAL, syscall.ENOSYS, syscall.EOPNOTSUPP, syscall.EPERM, syscall.EMFILE, syscall.ENFILE:
		return true
	}
	return false
}

// copyPrefix copies the prefix bytes that PrefixConns around the source
// still hold to dst, reading them through the source, which returns them
// without reading the connection beneath, and reports whether the copy is
// over.
func copyPrefix(ctx context.Context, dst io.Writer, s *relaySource, f *RelayFlow) (int64, bool, error) {
	var written int64
	for s.prefixPending() {
		n, err := f.wait(ctx, relayBufSize)
		if err != nil {
			return written, true, err
		}
		m, over, err := copyOnce(dst, s.r, n, f, nil)
		written += m
		if over {
			return written, true, err
		}
	}
	return written, false, nil
}
