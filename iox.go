package netx

import (
	"io"
	"net"
)

// writeOnce writes p to w with one Write, which io.Writer requires to write
// all of p unless it fails, and reports a short write as io.ErrShortWrite,
// as it does a count out of range.
func writeOnce(w io.Writer, p []byte) (n int, err error) {
	if n, err = w.Write(p); n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return
}

// writeBuffers writes every buffer of bufs to w, consuming bufs.
func writeBuffers(w io.Writer, bufs *net.Buffers) (int64, error) {
	var want int64
	for _, b := range *bufs {
		want += int64(len(b))
	}
	n, err := bufs.WriteTo(w)
	if err == nil && n != want {
		err = io.ErrShortWrite
	}
	return n, err
}
