package httpproxy

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/djylb/netx/httphead"
)

// FuzzForwardedHead checks that a request the server accepts is forwarded
// with a head that reads back as one request of the same method, path and
// body framing, with the Host of its target and without the credentials
// for the proxy, whatever the client sent.
func FuzzForwardedHead(f *testing.F) {
	for _, seed := range []string{
		"GET http://example.com/a?b HTTP/1.1\r\nHost: x\r\nConnection: x-a, close\r\nX-A: 1\r\n\r\n",
		"POST http://[::1]:8080 HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTrailer: x\r\n\r\n",
		"PUT http://EXAMPLE.com:81/ HTTP/1.0\nContent-Length: 5, 5\n\n",
		"GET http://a/ HTTP/1.1\r\nConnection: Content-Length, Host\r\nContent-Length: 3\r\nProxy-Authorization: Basic YTpi\r\n\r\n",
		"\r\nOPTIONS http://a HTTP/1.1\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
	} {
		f.Add(seed, false)
	}
	f.Fuzz(func(t *testing.T, raw string, pooled bool) {
		br := bufio.NewReaderSize(strings.NewReader(raw), readerSize)
		buf, err := httphead.Read(br, nil, DefaultMaxHeaderBytes)
		if err != nil {
			return
		}
		sc := &serverConn{s: &Server{Via: "fuzz"}, br: br}
		req, err := sc.parseRequest(string(buf))
		if err != nil || req.tgt.Form != httphead.AbsoluteForm || req.Dst.IsZero() {
			return
		}
		x := &exchange{sc: sc, req: req, pooled: pooled}
		out, err := x.requestHead()
		if err != nil {
			t.Fatalf("requestHead: %v", err)
		}
		again, err := httphead.Read(bufio.NewReader(bytes.NewReader(out)), nil, len(out))
		if err != nil || len(again) != len(out) {
			t.Fatalf("forwarded head %q does not read back: %v", out, err)
		}
		h, err := httphead.ParseRequest(string(again), nil)
		if err != nil {
			t.Fatalf("forwarded head %q does not parse: %v", out, err)
		}
		if h.Method != req.Method || h.Target != req.tgt.Path || h.Minor != 1 {
			t.Fatalf("forwarded %q %q %d, want %q %q", h.Method, h.Target, h.Minor, req.Method, req.tgt.Path)
		}
		body, length, err := httphead.RequestBody(h.Header, h.Minor)
		if err != nil || body != req.body || body == httphead.Length && length != req.length {
			t.Fatalf("forwarded framing %v %d %v, want %v %d", body, length, err, req.body, req.length)
		}
		if hosts := h.Header.Values("Host"); len(hosts) != 1 || hosts[0] != req.tgt.Authority {
			t.Fatalf("forwarded Host %q, want %q", hosts, req.tgt.Authority)
		}
		if h.Header.Has("Proxy-Authorization") || h.Header.Has("Proxy-Connection") || h.Header.Has("Keep-Alive") {
			t.Fatalf("hop-by-hop fields forwarded: %q", out)
		}
	})
}

// FuzzChunked checks that a chunked body the stream accepts is sent on as
// a chunked body that decodes to the same data, which is what the target
// then reads.
func FuzzChunked(f *testing.F) {
	for _, seed := range []string{
		"5\r\nhello\r\n0\r\n\r\n",
		"3;ext=1\r\nabc\r\nA \r\n0123456789\r\n0\r\nX-T: 1\r\n\r\n",
		"1\nx\n0\n\n",
		"0\r\nContent-Length: 5\r\n\r\n",
	} {
		f.Add(seed)
	}
	decode := func(in string, out bool) (string, error) {
		var s stream
		s.reset(bufio.NewReaderSize(strings.NewReader(in), readerSize), httphead.Chunked, out, DefaultMaxHeaderBytes)
		var w bytes.Buffer
		buf := make([]byte, 7) // small reads, as a paced relay makes
		for {
			n, err := s.Read(buf)
			w.Write(buf[:n])
			if err == io.EOF {
				return w.String(), nil
			}
			if err != nil {
				return "", err
			}
		}
	}
	f.Fuzz(func(t *testing.T, in string) {
		wire, err := decode(in, true)
		if err != nil {
			return
		}
		plain, err := decode(in, false)
		if err != nil {
			t.Fatalf("decodes when sent chunked but not plain: %v", err)
		}
		again, err := decode(wire, false)
		if err != nil || again != plain {
			t.Fatalf("sent on as %q, which decodes to %q, %v; want %q", wire, again, err, plain)
		}
		if rewire, err := decode(wire, true); err != nil || rewire != wire {
			t.Fatalf("encoding is not stable: %q, then %q, %v", wire, rewire, err)
		}
	})
}
