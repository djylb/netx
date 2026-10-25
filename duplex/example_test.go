package duplex_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/djylb/netx/duplex"
)

// Talk to an HTTP handler over one request: the request body carries what
// the connection writes and the response body what it reads.
func ExampleJoin_httpBody() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		buf := make([]byte, 512)
		for {
			n, err := r.Body.Read(buf)
			_, _ = w.Write(bytes.ToUpper(buf[:n]))
			_ = http.NewResponseController(w).Flush()
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	uplink, body := io.Pipe()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, uplink)
	resp, err := srv.Client().Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	c := duplex.Join(resp.Body, body)
	defer func() { _ = c.Close() }()

	_, _ = c.Write([]byte("hello"))
	_ = c.CloseWrite() // ends the request body
	answer, _ := io.ReadAll(c)
	fmt.Printf("%s over %s\n", answer, c.RemoteAddr())
	// Output: HELLO over duplex
}

// Join two one-way pipes, as from a worker that reads one and writes the
// other, into a connection.
func ExampleJoin_pipes() {
	toWorker, workerIn := io.Pipe()
	workerOut, fromWorker := io.Pipe()
	go func() { // the worker
		_, _ = io.Copy(fromWorker, io.LimitReader(toWorker, 4))
		_ = fromWorker.Close()
	}()

	c := duplex.Join(workerOut, workerIn)
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("ping"))
	echo, _ := io.ReadAll(c)
	fmt.Println(string(echo))
	// Output: ping
}

// Serve a protocol that wants a net.Conn on standard input and output.
func ExampleJoin_stdio() {
	c := duplex.Join(os.Stdin, os.Stdout)
	defer func() { _ = c.Close() }()
	_, _ = io.Copy(c, strings.NewReader("hello\n"))
}

// Move the stream of a sender to a new channel while it writes: Swap
// waits for the write in progress and ends the old channel, and the
// receiver, given each channel as it arrives, reads the old one to its end
// and then the new one.
func ExampleWriter_Swap() {
	arrived := make(chan io.Reader, 2) // the channels, as the receiver learns of them
	open := func() io.Writer {
		r, w := io.Pipe()
		arrived <- r
		return w
	}

	var in duplex.Reader
	go func() {
		for r := range arrived {
			_, _ = in.Append(r)
		}
		_ = in.End()
	}()
	receiver := duplex.Join(&in, nil)
	got := make(chan string)
	go func() {
		b, _ := io.ReadAll(receiver)
		got <- string(b)
	}()

	var up duplex.Writer
	_ = up.Swap(context.Background(), open())
	sender := duplex.Join(nil, &up)
	_, _ = sender.Write([]byte("first "))
	_ = up.Swap(context.Background(), open()) // ends the first channel
	_, _ = sender.Write([]byte("second"))
	close(arrived)
	_ = sender.Close()
	fmt.Println(<-got)
	// Output: first second
}

// Receive a stream that its sender sends as a series of uploads: each
// handler appends its request body and returns once it has been read.
func ExampleReader_Append() {
	var in duplex.Reader
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done, err := in.Append(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusGone)
			return
		}
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	session := duplex.Join(&in, nil)
	defer func() { _ = session.Close() }()
	go func() {
		for _, chunk := range []string{"one ", "two"} {
			resp, err := srv.Client().Post(srv.URL, "application/octet-stream", strings.NewReader(chunk))
			if err == nil {
				_ = resp.Body.Close()
			}
		}
		_ = in.End()
	}()
	b, _ := io.ReadAll(session)
	fmt.Println(string(b))
	// Output: one two
}
