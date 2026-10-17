package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
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
func spliceCopy(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, bool, error) {
	srcConn, _ := unwrapPrefix(src).(net.Conn)
	srcSys, ok1 := srcConn.(syscall.Conn)
	dstConn, _ := unwrapConn(dst).(net.Conn)
	dstSys, ok2 := dstConn.(syscall.Conn)
	srcTimeouts, dstTimeouts := timeoutsOf(src), timeoutsOf(dst)
	sock := socketSource(src)
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
	// The prefix is read through src, before the connection beneath.
	written, err := copyPrefix(ctx, dst, src, f)
	if err != nil {
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
			want = min(want, p.size)
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
		want, noPipe, spliceErr = int(n), false, nil
		if err := srcTimeouts.refresh(); err != nil {
			return written, true, err
		}
		if err := srcRaw.Read(fill); err != nil {
			return written, true, asReadError(err)
		}
		if noPipe {
			// Through the wrappers, whose reads and writes refresh their
			// deadlines.
			m, done, err := copyPiece(dst, src, n, f)
			written += m
			if done || err != nil {
				return written, true, err
			}
			full = false
			continue
		}
		if spliceErr != nil {
			if !spliced && unsupportedSplice(spliceErr) {
				return written, false, nil
			}
			return written, true, spliceOpError(srcConn, spliceErr)
		}
		if inPipe == 0 {
			return written, true, nil // EOF
		}
		full = inPipe == want
		out = 0
		writeErr := dstTimeouts.refresh()
		if writeErr == nil {
			writeErr = asWriteError(dstRaw.Write(drain))
		}
		written += out
		if writeErr == nil && spliceErr != nil {
			writeErr = spliceOpError(dstConn, spliceErr)
		}
		if derr := f.done(out); writeErr == nil {
			writeErr = derr
		}
		if writeErr != nil {
			return written, true, writeErr
		}
	}
}

// copyPiece copies one read of at most n bytes from src to dst through
// Relay's buffer, and reports whether the copy is over.
func copyPiece(dst io.Writer, src io.Reader, n int64, f *RelayFlow) (int64, bool, error) {
	bp := relayBufPool.Get().(*[]byte)
	defer relayBufPool.Put(bp)
	r, rerr := src.Read((*bp)[:min(n, relayBufSize)])
	var written int64
	if r > 0 {
		m, werr := dst.Write((*bp)[:r])
		written = int64(m)
		if werr == nil && m != r {
			werr = io.ErrShortWrite
		}
		if derr := f.done(written); werr == nil {
			werr = derr
		}
		if werr != nil {
			return written, true, werr
		}
	}
	if rerr == io.EOF {
		return written, true, nil
	}
	return written, rerr != nil, rerr
}

// asWriteError reports an error of RawConn.Write as one of Write.
func asWriteError(err error) error {
	if err == nil {
		return nil
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "raw-write" {
		e := *oe
		e.Op = "write"
		return &e
	}
	return err
}

// spliceOpError reports a splice error of c as its I/O errors are reported.
func spliceOpError(c net.Conn, err error) error {
	return &net.OpError{Op: "splice", Net: c.LocalAddr().Network(), Source: c.LocalAddr(),
		Addr: c.RemoteAddr(), Err: os.NewSyscallError("splice", err)}
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

// copyPrefix copies the prefix bytes that PrefixConns around src still hold
// to dst, reading them through src, which returns them without reading the
// connection beneath.
func copyPrefix(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, error) {
	var written int64
	for prefixPending(src) {
		n, err := f.wait(ctx, relayBufSize)
		if err != nil {
			return written, err
		}
		bp := relayBufPool.Get().(*[]byte)
		r, rerr := src.Read((*bp)[:n])
		if r == 0 {
			// The source ended or failed: a PrefixConn whose prefix is gone
			// reads the connection beneath.
			relayBufPool.Put(bp)
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
		m, werr := dst.Write((*bp)[:r])
		relayBufPool.Put(bp)
		written += int64(m)
		if werr == nil && m != r {
			werr = io.ErrShortWrite
		}
		if derr := f.done(int64(m)); werr == nil {
			werr = derr
		}
		if werr != nil {
			return written, werr
		}
	}
	return written, nil
}
