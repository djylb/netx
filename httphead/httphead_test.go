package httphead_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/djylb/netx/httphead"
)

func read(s string) (string, error) {
	b, err := httphead.Read(bufio.NewReaderSize(strings.NewReader(s), 16), nil, 1<<10)
	return string(b), err
}

func TestRead(t *testing.T) {
	for _, tt := range []struct {
		in, head string
		err      error
	}{
		{"GET / HTTP/1.1\r\nA: b\r\n\r\nbody", "GET / HTTP/1.1\r\nA: b\r\n\r\n", nil},
		{"\r\n\nGET / HTTP/1.1\n\n", "GET / HTTP/1.1\n\n", nil},
		{"GET / HTTP/1.1\r\nX: " + strings.Repeat("y", 100) + "\r\n\r\n", "GET / HTTP/1.1\r\nX: " + strings.Repeat("y", 100) + "\r\n\r\n", nil}, // lines over the buffer
		{"", "", io.EOF},
		{"GET / HTTP/1.1\r\n", "", io.ErrUnexpectedEOF},
		{"GET / HTTP/1.1\r\nX: " + strings.Repeat("y", 2000) + "\r\n\r\n", "", httphead.ErrTooLarge},
	} {
		head, err := read(tt.in)
		if !errors.Is(err, tt.err) || err == nil && head != tt.head {
			t.Errorf("Read(%.30q) = %q, %v; want %q, %v", tt.in, head, err, tt.head, tt.err)
		}
	}
}

func TestParseRequestRejects(t *testing.T) {
	for _, tt := range []struct {
		head string
		err  error
	}{
		{"GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n", httphead.ErrMalformed},
		{"GET / HTTP/1.1\r\nX : a\r\n\r\n", httphead.ErrMalformed},
		{"GET / HTTP/1.1\r\nX: a\rb\r\n\r\n", httphead.ErrMalformed},
		{"GET / HTTP/1.1\r\nX: a\x00\r\n\r\n", httphead.ErrMalformed},
		{"GET /a b HTTP/1.1\r\n\r\n", httphead.ErrMalformed},
		{"GET / HTTP/2.0\r\n\r\n", httphead.ErrVersion},
		{"GET / http/1.1\r\n\r\n", httphead.ErrMalformed},
		{"G(T / HTTP/1.1\r\n\r\n", httphead.ErrMalformed},
	} {
		if _, err := httphead.ParseRequest(tt.head, nil); !errors.Is(err, tt.err) {
			t.Errorf("ParseRequest(%q) = %v, want %v", tt.head, err, tt.err)
		}
	}
}

func TestBodies(t *testing.T) {
	h := func(fields ...string) httphead.Header {
		var h httphead.Header
		for i := 0; i < len(fields); i += 2 {
			h.Add(fields[i], fields[i+1])
		}
		return h
	}
	for _, tt := range []struct {
		h      httphead.Header
		minor  int
		framed httphead.Framing
		n      int64
		err    error
	}{
		{h("Content-Length", "5"), 1, httphead.Length, 5, nil},
		{h("Content-Length", "5, 5", "Content-Length", "5"), 1, httphead.Length, 5, nil},
		{h("Content-Length", "0"), 1, httphead.NoBody, 0, nil},
		{h("Content-Length", "5, 6"), 1, 0, 0, httphead.ErrMalformed},
		{h("Content-Length", "-1"), 1, 0, 0, httphead.ErrMalformed},
		{h("Transfer-Encoding", "Chunked"), 1, httphead.Chunked, 0, nil},
		{h("Transfer-Encoding", "chunked", "Content-Length", "3"), 1, 0, 0, httphead.ErrMalformed},
		{h("Transfer-Encoding", "gzip, chunked"), 1, 0, 0, httphead.ErrTransferCoding},
		{h("Transfer-Encoding", "chunked"), 0, 0, 0, httphead.ErrMalformed},
	} {
		f, n, err := httphead.RequestBody(tt.h, tt.minor)
		if !errors.Is(err, tt.err) || err == nil && (f != tt.framed || n != tt.n) {
			t.Errorf("RequestBody(%v) = %v, %d, %v", tt.h, f, n, err)
		}
	}
	for _, tt := range []struct {
		method  string
		code    int
		h       httphead.Header
		framed  httphead.Framing
		codings string
	}{
		{"GET", 200, h("Transfer-Encoding", "gzip, chunked", "Content-Length", "9"), httphead.Chunked, "gzip"},
		{"GET", 200, h("Transfer-Encoding", "gzip"), httphead.UntilClose, "gzip"},
		{"GET", 200, nil, httphead.UntilClose, ""},
		{"HEAD", 200, h("Content-Length", "9"), httphead.NoBody, ""},
		{"GET", 304, h("Content-Length", "9"), httphead.NoBody, ""},
		{"GET", 103, nil, httphead.NoBody, ""},
	} {
		f, _, codings, err := httphead.ResponseBody(tt.method, tt.code, tt.h)
		if err != nil || f != tt.framed || codings != tt.codings {
			t.Errorf("ResponseBody(%s, %d, %v) = %v, %q, %v", tt.method, tt.code, tt.h, f, codings, err)
		}
	}
}

func TestParseTarget(t *testing.T) {
	for _, tt := range []struct {
		method, target string
		want           httphead.Target
		ok             bool
	}{
		{"GET", "http://Example.com:8080/a?b#frag", httphead.Target{Form: httphead.AbsoluteForm, Scheme: "http", Authority: "Example.com:8080", Host: "Example.com", Port: 8080, Path: "/a?b"}, true},
		{"OPTIONS", "http://a", httphead.Target{Form: httphead.AbsoluteForm, Scheme: "http", Authority: "a", Host: "a", Path: "*"}, true},
		{"GET", "http://a?q", httphead.Target{Form: httphead.AbsoluteForm, Scheme: "http", Authority: "a", Host: "a", Path: "/?q"}, true},
		{"connect", "[fe80::1%25eth0]:443", httphead.Target{Form: httphead.AuthorityForm, Authority: "[fe80::1%25eth0]:443", Host: "fe80::1%eth0", Port: 443}, true},
		{"GET", "/x", httphead.Target{Form: httphead.OriginForm, Path: "/x"}, true},
		{"OPTIONS", "*", httphead.Target{Form: httphead.AsteriskForm, Path: "*"}, true},
		{"GET", "http://user@a/", httphead.Target{}, false},
		{"GET", "http:///", httphead.Target{}, false},
		{"CONNECT", "a:0", httphead.Target{}, false},
		{"CONNECT", "[1.2.3.4]:1", httphead.Target{}, false},
		{"GET", "x", httphead.Target{}, false},
	} {
		got, err := httphead.ParseTarget(tt.method, tt.target)
		if (err == nil) != tt.ok || tt.ok && got != tt.want {
			t.Errorf("ParseTarget(%s, %q) = %+v, %v", tt.method, tt.target, got, err)
		}
	}
}

func TestHeaderAppendToRefusesInjection(t *testing.T) {
	h := httphead.Header{{Name: "X", Value: "a\r\nEvil: b"}}
	if b, err := h.AppendTo([]byte("keep")); !errors.Is(err, httphead.ErrMalformed) || string(b) != "keep" {
		t.Fatalf("AppendTo = %q, %v", b, err)
	}
}

// FuzzParse checks that a head that parses is written back by AppendTo as
// one that parses to the same start line and fields, so that a reader that
// sees the written head reads it as this parser did.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"GET http://example.com/ HTTP/1.1\r\nHost: x\r\nA:  b \r\n\r\n",
		"\nHTTP/1.0 200\nX: y\n\n",
		"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		head, err := read(in)
		if err != nil {
			return
		}
		if req, err := httphead.ParseRequest(head, nil); err == nil {
			out, err := req.Header.AppendTo([]byte(req.Method + " " + req.Target + " " + req.Proto + "\r\n"))
			if err != nil {
				t.Fatalf("parsed fields do not append: %v", err)
			}
			again, err := httphead.ParseRequest(string(append(out, "\r\n"...)), nil)
			if err != nil || again.Method != req.Method || again.Target != req.Target || len(again.Header) != len(req.Header) {
				t.Fatalf("%q reads back as %+v, %v", out, again, err)
			}
			for i := range req.Header {
				if again.Header[i] != req.Header[i] {
					t.Fatalf("field %d: %+v, want %+v", i, again.Header[i], req.Header[i])
				}
			}
			_, _, _ = httphead.RequestBody(req.Header, req.Minor)
			_, _ = httphead.ParseTarget(req.Method, req.Target)
		}
		if resp, err := httphead.ParseResponse(head, nil); err == nil {
			_, _, _, _ = httphead.ResponseBody("GET", resp.Code, resp.Header)
		}
	})
}

func Example() {
	br := bufio.NewReader(strings.NewReader("POST http://example.com/form HTTP/1.1\r\n" +
		"Host: example.com\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello"))
	head, err := httphead.Read(br, nil, 64<<10)
	if err != nil {
		fmt.Println(err)
		return
	}
	req, err := httphead.ParseRequest(string(head), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	target, _ := httphead.ParseTarget(req.Method, req.Target)
	framing, n, _ := httphead.RequestBody(req.Header, req.Minor)
	body := make([]byte, n)
	_, _ = io.ReadFull(br, body) // the body stays in br
	fmt.Println(req.Method, target.Host, target.Path, framing, n, string(body), req.Header.HasToken("Connection", "Keep-Alive"))
	// Output: POST example.com /form length 5 hello true
}
