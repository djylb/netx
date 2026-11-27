package httphead

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

// outcome names the result of a parse as the tables compare it.
func outcome(err error) string {
	switch {
	case err == nil:
		return "request"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "incomplete"
	case errors.Is(err, ErrMalformed), errors.Is(err, ErrVersion):
		return "invalid"
	}
	return err.Error()
}

// scanInPieces checks that what parse decides on a prefix of data holds for
// all of it, and that scan, fed data in pieces of step%32+1 bytes, comes to
// the same outcome as parse does at once. It returns both requests and the
// error of parse.
func scanInPieces(t *testing.T, data []byte, step uint8, parse, scan func([]byte) (*RoutedRequest, error)) (want, got *RoutedRequest, wantErr error) {
	t.Helper()
	want, wantErr = parse(data)
	for i := range data {
		if _, err := parse(data[:i]); outcome(err) != "incomplete" && outcome(err) != outcome(wantErr) {
			t.Fatalf("prefix of %d bytes: %v, whole: %v", i, err, wantErr)
		}
	}
	err := io.ErrUnexpectedEOF
	for n := 0; outcome(err) == "incomplete" && n < len(data); {
		n = min(n+int(step%32)+1, len(data))
		got, err = scan(data[:n])
	}
	if outcome(err) != outcome(wantErr) {
		t.Fatalf("pieces of %d: %v, at once: %v", step%32+1, err, wantErr)
	}
	return want, got, wantErr
}

func TestScanRequest(t *testing.T) {
	// Absolute-form fixtures exercise the default port for the cleartext scheme.
	//goland:noinspection HttpUrlsUsage
	tests := []struct {
		name   string
		data   string
		want   string
		method string
		host   string
		path   string
	}{
		{"get", "GET /a/b?x=1 HTTP/1.1\r\nHost: example.com:8080\r\nX: y\r\n\r\n", "request", "GET", "example.com:8080", "/a/b"},
		{"body follows", "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc", "request", "POST", "h", "/p"},
		{"http/1.0 without headers", "GET / HTTP/1.0\r\n\r\n", "request", "GET", "", "/"},
		{"bare LF", "GET / HTTP/1.1\nHost: h\n\n", "request", "GET", "h", "/"},
		{"patch", "PATCH /x HTTP/1.1\r\nHost: h\r\n\r\n", "request", "PATCH", "h", "/x"},
		{"extension method", "PROPFIND /dav HTTP/1.1\r\nHost: h\r\n\r\n", "request", "PROPFIND", "h", "/dav"},
		{"escaped path", "GET /a%20b HTTP/1.1\r\nHost: h\r\n\r\n", "request", "GET", "h", "/a b"},
		{"absolute form", "GET http://abs.example/p HTTP/1.1\r\nHost: ABS.example:80\r\n\r\n", "request", "GET", "abs.example", "/p"},
		{"absolute form and another host", "GET http://abs.example/p HTTP/1.1\r\nHost: other\r\n\r\n", "invalid", "", "", ""},
		{"line breaks first", "\r\n\r\nGET /x HTTP/1.1\r\nHost: h\r\n\r\n", "request", "GET", "h", "/x"},
		{"three leading empty lines", "\r\n\r\n\r\nGET /x HTTP/1.1\r\n\r\n", "request", "GET", "", "/x"},
		{"bare CR before method", "\rGET /x HTTP/1.1\r\n\r\n", "invalid", "", "", ""},
		{"connect path", "CONNECT / HTTP/1.1\r\n\r\n", "invalid", "", "", ""},
		{"get star", "GET * HTTP/1.1\r\n\r\n", "invalid", "", "", ""},
		{"default port with leading zero", "GET http://h:080/a HTTP/1.1\r\nHost: h\r\n\r\n", "request", "GET", "h:080", "/a"},
		{"invalid literal", "GET http://[x:y]/ HTTP/1.1\r\n\r\n", "invalid", "", "", ""},
		{"different ports", "GET http://h:81/a HTTP/1.1\r\nHost: h:80\r\n\r\n", "invalid", "", "", ""},
		{"connect", "CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\n\r\n", "request", "CONNECT", "target.example:443", ""},
		{"options star", "OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n", "request", "OPTIONS", "h", "*"},
		{"options absolute", "OPTIONS http://h HTTP/1.1\r\nHost: h\r\n\r\n", "request", "OPTIONS", "h", "/"},
		{"duplicate host", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "invalid", "", "", ""},
		{"http/2 version", "GET / HTTP/2.0\r\n\r\n", "invalid", "", "", ""},
		{"h2 preface", HTTP2Preface, "invalid", "", "", ""},
		{"lowercase version", "GET / http/1.1\r\n", "invalid", "", "", ""},
		{"missing version", "GET /\r\n\r\n", "invalid", "", "", ""},
		{"double space", "GET  / HTTP/1.1\r\n", "invalid", "", "", ""},
		{"relative target", "GET a/b HTTP/1.1\r\n\r\n", "invalid", "", "", ""},
		{"bad header line", "GET / HTTP/1.1\r\nno colon\r\n\r\n", "invalid", "", "", ""},
		{"tab and obs-text in a value", "GET / HTTP/1.1\r\nHost: h\r\nX: a\tb\xff\r\n\r\n", "request", "GET", "h", "/"},
		{"bare CR in a value", "GET / HTTP/1.1\r\nX: a\rHost: evil\r\nHost: good\r\n\r\n", "invalid", "", "", ""},
		{"NUL in host", "GET / HTTP/1.1\r\nHost: good\x00evil\r\n\r\n", "invalid", "", "", ""},
		{"DEL in a value", "GET / HTTP/1.1\r\nX: a\x7f\r\n\r\n", "invalid", "", "", ""},
		{"tls record", "\x16\x03\x01\x02\x00", "invalid", "", "", ""},
		{"long method", strings.Repeat("A", 33), "incomplete", "", "", ""},
		{"headers incomplete", "GET / HTTP/1.1\r\nHost: h\r\n", "incomplete", "", "", ""},
		{"line incomplete", "GET /index.ht", "incomplete", "", "", ""},
		{"empty", "", "incomplete", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ScanRequest([]byte(tt.data))
			if outcome(err) != tt.want {
				t.Fatalf("parse = %v, want %s", err, tt.want)
			}
			if err != nil {
				return
			}
			if req.Method != tt.method || req.Host != tt.host || req.Path != tt.path {
				t.Fatalf("got method %q host %q path %q", req.Method, req.Host, req.Path)
			}
		})
	}
}

func TestScanRequestPrefixes(t *testing.T) {
	data := "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	for i := range len(data) {
		if _, err := ScanRequest([]byte(data[:i])); outcome(err) != "incomplete" {
			t.Fatalf("prefix %q: %v", data[:i], err)
		}
	}
	req, err := ScanRequest([]byte(data))
	if err != nil || req.Proto != "HTTP/1.1" || req.Target != "/chat" {
		t.Fatalf("parse = %+v, %v", req, err)
	}
	if req.Header.Get("Upgrade") != "websocket" || req.Host != "example.com" || req.Header.Get("Host") != req.Host {
		t.Fatalf("header %v, host %q", req.Header, req.Host)
	}
	var values []string
	for v := range req.Header.All("connection") {
		values = append(values, v)
	}
	if len(values) != 1 || values[0] != "Upgrade" {
		t.Fatalf("Values = %q", values)
	}
}

func TestScannerLimitAndReset(t *testing.T) {
	head := []byte("\r\nGET /chat HTTP/1.1\r\nX-Part: yes\r\n\r\n")
	s := Scanner{MaxBytes: len(head)}
	for i := range head {
		if _, err := s.Scan(head[:i]); !errors.Is(err, io.ErrUnexpectedEOF) || s.Need() != i+1 {
			t.Fatalf("prefix %d: %v, need %d", i, err, s.Need())
		}
	}
	r, err := s.Scan(append(slices.Clone(head), "trailing data"...))
	if err != nil || r.Path != "/chat" || r.Header.Get("X-Part") != "yes" {
		t.Fatalf("exact limit: %v, %v", r, err)
	}
	if again, err := s.Scan(nil); err != nil || again != r {
		t.Fatalf("terminal success was not retained: %v, %v", again, err)
	}
	s.Reset()
	if s.MaxBytes != len(head) || s.Need() != 1 {
		t.Fatalf("reset limit %d, need %d", s.MaxBytes, s.Need())
	}
	s.MaxBytes--
	if _, err := s.Scan(head); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("head over limit: %v", err)
	}
	if _, err := s.Scan(nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("terminal error was not retained: %v", err)
	}
}

func TestPathIsResolved(t *testing.T) {
	tests := map[string]string{
		"/a/./b":             "/a/b",
		"/public/../admin/x": "/admin/x",
		"//admin//x":         "/admin/x",
		"/a%2Fb/c":           "/a/b/c",
		"/x;jsessionid=1":    "/x;jsessionid=1",
		"/../../etc":         "/etc",
		"/x/":                "/x/",
		"/":                  "/",
		"/a%20b?q=1":         "/a b",
	}
	for target, want := range tests {
		req, err := ScanRequest([]byte("GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n"))
		if err != nil {
			t.Errorf("%s: %v", target, err)
		} else if req.Path != want {
			t.Errorf("%s: Path = %q, want %q", target, req.Path, want)
		}
	}
	if req, err := ScanRequest([]byte("GET http://h.example HTTP/1.1\r\n\r\n")); err != nil || req.Path != "/" {
		t.Errorf("absolute form without a path: %+v, %v", req, err)
	}
	if req, err := ScanRequest([]byte("GET /a?x=1&y=%20 HTTP/1.1\r\n\r\n")); err != nil || req.Query().Get("y") != " " {
		t.Errorf("query: %+v, %v", req, err)
	}
	// Paths that servers resolve differently are invalid.
	for _, target := range []string{
		"/admin/..%2Fpublic", "/admin/%2e%2e/public", "/admin/x%2F..%2F..%2Fpublic", "/%2e/x",
		"/public/..;/admin", "/public/.;x/admin", "/;x/admin", "/public\\..\\admin", "/a%5Cb",
		"/public#/../admin", "/p?x=1#&admin=1", "/a/%zz", "http://h/a/%2e%2e/b",
		"/api%00.php", "/a%0Ab", "/a%7F", "http://h/a%0Db",
	} {
		if _, err := ScanRequest([]byte("GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n")); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", target, err)
		}
	}
}

func TestHasPathPrefix(t *testing.T) {
	for _, tc := range []struct {
		path, prefix string
		want         bool
	}{
		{"/api", "/api", true},
		{"/api/", "/api", true},
		{"/api;v=1", "/api", true},
		{"/api/v1", "/api/", true},
		{"/api;v=1", "/api/", false},
		{"/apis", "/api", false},
	} {
		if got := HasPathPrefix(tc.path, tc.prefix); got != tc.want {
			t.Errorf("HasPathPrefix(%q, %q) = %v", tc.path, tc.prefix, got)
		}
	}
}

var benchRequest = []byte("GET /api/v1/items?page=2 HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: bench\r\n" +
	"Accept: */*\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n")

func BenchmarkScanRequest(b *testing.B) {
	b.SetBytes(int64(len(benchRequest)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ScanRequest(benchRequest); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanSlowly feeds an 8 KiB request head in 16-byte pieces, as a
// slow or hostile client would, and scans after every piece.
func BenchmarkScanSlowly(b *testing.B) {
	head := []byte("GET / HTTP/1.1\r\nHost: h\r\nCookie: " + strings.Repeat("c", 8<<10) + "\r\n\r\n")
	b.SetBytes(int64(len(head)))
	b.ReportAllocs()
	for b.Loop() {
		var s Scanner
		for n := 16; ; n += 16 {
			if _, err := s.Scan(head[:min(n, len(head))]); outcome(err) != "incomplete" {
				break
			}
		}
	}
}

// FuzzParse checks that a decision made on a prefix never changes and that a
// Scanner fed in pieces agrees with Parse.
func FuzzScanRequest(f *testing.F) {
	f.Add([]byte("GET /a?b HTTP/1.1\r\nHost: example.com:80\r\nConnection: Upgrade\r\n\r\n"), uint8(0))
	f.Add([]byte("CONNECT h:443 HTTP/1.1\r\n\r\n"), uint8(3))
	f.Add([]byte("GET http://h/p HTTP/1.0\n\n"), uint8(7))
	f.Add([]byte("GET /%41 HTTP/1.1\r\nX: a\r\n folded\r\nHost:  h \r\n\r\n"), uint8(1))
	f.Add([]byte(HTTP2Preface), uint8(5))
	f.Fuzz(func(t *testing.T, data []byte, step uint8) {
		var s Scanner
		want, got, wantErr := scanInPieces(t, data, step, ScanRequest, s.Scan)
		if wantErr == nil && (got.Method != want.Method || got.Host != want.Host || got.Path != want.Path ||
			got.Target != want.Target || !slices.Equal(got.Header, want.Header)) {
			t.Fatalf("pieces: %+v, at once: %+v", got, want)
		}
		if wantErr == nil {
			_ = got.Header.Get("Host")
		}
	})
}

func TestPartialQueryRejected(t *testing.T) {
	if _, err := ScanRequest([]byte("GET /?good=1&bad=% HTTP/1.1\r\n\r\n")); outcome(err) != "invalid" {
		t.Fatal(err)
	}
}
