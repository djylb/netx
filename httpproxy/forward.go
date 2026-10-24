package httpproxy

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/httphead"
)

// exchange is one forwarded request and its responses. A netx.Relay runs
// it between two netx.RelayEnds: the client's end reads the request as it
// goes to the target, its head and then its body, and writes to the client;
// the target's end reads the responses as they go to the client and writes
// to the target. Each reads a netx.ChainReader whose parts follow the
// message: a head built here, then the body, which is an *io.LimitedReader
// over the connection when its length is known, so that the relay splices
// it, or a stream that decodes or encodes it otherwise. Both bodies stream
// at once, and RelayOptions apply to the whole exchange.
type exchange struct {
	sc  *serverConn
	req *Request
	up  *upConn

	reqStream, respStream stream
	reqHead               headPart
	respHead              headPart
	// For the new protocol after an upgrade, the bytes the client sent
	// with or after the request.
	rawHead headPart
	// respFields and outFields are reused for each response head.
	respFields httphead.Header
	outFields  httphead.Header
	// respLength delimits the final response's body, with respFraming.
	respLength int64

	// failed is why the target's response could not be read, answered with
	// 502 Bad Gateway or, after ResponseHeaderTimeout, 504.
	failed error
	status int

	// For a request that asks for an upgrade, decided is closed once the
	// final response tells whether the protocol switched, upgraded.
	decided chan struct{}
	aborted chan struct{} // closed when the relay stops early

	// cutMu guards the cut-off of a request that the final response
	// ended before: cutTimer, which cuts it once its grace has passed, and
	// finished, set once the relay has returned, after which nothing is cut.
	cutTimer *time.Timer
	cutMu    sync.Mutex
	// headMu guards the response header timeout, with headSeen: set by the
	// request's direction once the request is sent, cleared by the
	// response's.
	headMu  sync.Mutex
	abortMu sync.Once

	// reqDone and respDone are set when the request, or the final response,
	// has been read to its end, by the goroutine of its direction.
	reqDone, respDone atomic.Bool
	// gotResponse is set once any byte of a response head came.
	gotResponse atomic.Bool
	// interrupted is set when the final response ended before the
	// request, whose rest is then not read.
	interrupted atomic.Bool
	// retry is set when the target's connection failed before any
	// response, on a kept connection, for a request that may be sent again.
	retry    atomic.Bool
	upgraded atomic.Bool

	// pooled tells that the target's connection may be kept.
	pooled    bool
	reqState  uint8
	respState respState
	// respFraming delimits the final response's body, with respLength.
	respFraming httphead.Framing
	// keepAlive tells whether the client connection may serve another
	// request, and upKeep whether the target's may; set with the final
	// response head, read once the relay has returned.
	keepAlive, upKeep bool
	finished          bool // guarded by cutMu
	headSeen          bool // guarded by headMu
}

type respState uint8

const (
	respHead respState = iota // before a response head
	respBody                  // the final response's head was sent
	respEnd                   // the final response's body was sent
	respNone                  // a reply of the server's own was sent
)

// errRetry ends the relay of a request that is sent again on a new
// connection.
var errRetry = errors.New("httpproxy: retry on a new connection")

// idempotent reports whether a request may be sent again after its
// connection failed before any response (RFC 9110, section 9.2.2): an
// idempotent method without a body, which the server has not read beyond.
func idempotent(req *Request) bool {
	switch req.Method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return req.body == httphead.NoBody && !req.upgrade
	}
	return false
}

// reuseKey returns the key under which req's target connection is kept.
func (sc *serverConn) reuseKey(req *Request) (string, bool) {
	s := sc.s
	if s.MaxIdleConnsPerKey < 0 {
		return "", false
	}
	if s.ReuseKey != nil {
		return s.ReuseKey(req)
	}
	return req.Dst.String() + "\x00" + req.User, true
}

// forward serves a request to forward.
func (sc *serverConn) forward(ctx context.Context, req *Request) (bool, error) {
	key, pooled := sc.reuseKey(req)
	for attempt := 0; ; attempt++ {
		var up *upConn
		if pooled && attempt == 0 {
			up = sc.s.targets().get(key)
		}
		if up == nil {
			c, err := sc.dial(ctx, req)
			if err != nil {
				return sc.refuse(req, StatusFor(err), err)
			}
			up = &upConn{c: c, br: getReader(c), key: key}
		}
		keep, err := sc.exchange(ctx, req, up, pooled)
		if errors.Is(err, errRetry) && ctx.Err() == nil {
			continue
		}
		return keep, err
	}
}

// exchange forwards req over up and reports whether the client's
// connection serves another request.
func (sc *serverConn) exchange(ctx context.Context, req *Request, up *upConn, pooled bool) (bool, error) {
	x := &sc.x
	// The buffers of the previous exchange are reused.
	respFields, outFields := x.respFields[:0], x.outFields[:0]
	reqTrailer, respTrailer := x.reqStream.trailer, x.respStream.trailer
	*x = exchange{sc: sc, req: req, up: up, pooled: pooled, respFields: respFields, outFields: outFields}
	x.reqStream.trailer, x.respStream.trailer = reqTrailer, respTrailer
	if req.upgrade {
		x.decided, x.aborted = make(chan struct{}), make(chan struct{})
	}
	defer func() {
		x.req, x.up = nil, nil
		// What is kept for the next exchange holds no strings of this one.
		clear(x.respFields[:cap(x.respFields)])
		clear(x.outFields[:cap(x.outFields)])
	}()
	head, err := x.requestHead()
	if err != nil {
		up.close()
		return sc.refuse(req, 500, err)
	}
	length := int64(0)
	if req.body == httphead.Length {
		length = req.length
	}
	x.reqHead = headPart{head: head, br: sc.br, n: length}
	if req.body == httphead.NoBody {
		x.reqDone.Store(true)
	}
	opts := []netx.RelayOption{netx.WithRelayHalfClose()}
	if sc.s.RelayOptions != nil {
		opts = append(opts, sc.s.RelayOptions(req)...)
	}
	client := &netx.RelayEnd{
		Reader:         &netx.ChainReader{Next: x.nextRequestPart},
		Writer:         sc.c,
		CloseWriteFunc: x.responseSent,
		CloseFunc:      x.closeClient,
	}
	target := &netx.RelayEnd{
		Reader:         &netx.ChainReader{Next: x.nextResponsePart},
		Writer:         up.c,
		CloseWriteFunc: x.requestSent,
		CloseFunc:      x.closeTarget,
	}
	toTarget, toClient, err := netx.Relay(ctx, client, target, opts...)
	x.cutMu.Lock()
	x.finished = true
	if x.cutTimer != nil {
		x.cutTimer.Stop()
	}
	x.cutMu.Unlock()
	if x.interrupted.Load() {
		sc.linger = true // the client may still be sending
	}
	req.result.ToTarget += toTarget
	req.result.ToClient += toClient
	req.result.Reused = up.reused
	if x.status != 0 {
		req.result.Status = x.status
	}
	clean := err == nil && x.reqDone.Load() && x.respDone.Load() && !x.interrupted.Load() && !x.upgraded.Load()
	switch {
	case err != nil && (x.retry.Load() || x.canRetry()) && !x.interrupted.Load():
		up.close()
		return false, errRetry
	case clean && x.upKeep:
		sc.s.targets().put(up)
	default:
		up.close()
	}
	switch {
	case err != nil && x.interrupted.Load() && x.respDone.Load():
		// The rest of the request was cut off on purpose.
	case err != nil:
		return false, err
	case x.failed != nil:
		return false, refusal(x.status, x.failed)
	}
	return clean && x.keepAlive, nil
}

// hopByHop reports whether a field is for one connection only (RFC 9110,
// section 7.6.1), or one that the server sets itself.
func hopByHop(name string) bool {
	switch len(name) {
	case 2:
		return strings.EqualFold(name, "TE")
	case 4:
		return strings.EqualFold(name, "Host")
	case 7:
		return strings.EqualFold(name, "Upgrade") || strings.EqualFold(name, "Trailer")
	case 10:
		return strings.EqualFold(name, "Connection") || strings.EqualFold(name, "Keep-Alive")
	case 14:
		return strings.EqualFold(name, "Content-Length")
	case 16:
		return strings.EqualFold(name, "Proxy-Connection")
	case 17:
		return strings.EqualFold(name, "Transfer-Encoding")
	case 18:
		return strings.EqualFold(name, "Proxy-Authenticate")
	case 19:
		return strings.EqualFold(name, "Proxy-Authorization")
	}
	return false
}

// copyFields appends the fields of h that are passed on to out: not for
// one connection only and not listed in Connection; keepTrailer and
// keepLength keep Trailer and Content-Length.
func copyFields(out, h httphead.Header, keepTrailer, keepLength bool) httphead.Header {
	listed := h.Has("Connection")
	for _, f := range h {
		if hopByHop(f.Name) {
			switch {
			case keepTrailer && strings.EqualFold(f.Name, "Trailer"):
			case keepLength && strings.EqualFold(f.Name, "Content-Length"):
			default:
				continue
			}
		}
		if listed && h.HasToken("Connection", f.Name) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// requestHead returns the head of the request as forwarded: the request line
// with the origin-form target and HTTP/1.1, as this server speaks, Host
// from the URI (RFC 9112, section 3.2.2), the end-to-end fields, Via, those
// of ForwardHeader, the framing of the body and Connection.
func (x *exchange) requestHead() ([]byte, error) {
	req, sc := x.req, x.sc
	// Built in x.outFields itself, which the hook gets a pointer to without
	// a header of its own escaping for each request.
	x.outFields = copyFields(x.outFields[:0], req.Header, req.body == httphead.Chunked, false)
	if sc.s.Via != "" {
		x.outFields = appendVia(x.outFields, req.minor, sc.s.Via)
	}
	if sc.s.ForwardHeader != nil {
		sc.s.ForwardHeader(req, &x.outFields)
	}
	authority := req.tgt.Authority
	if req.intercept {
		if authority = req.Header.Get("Host"); authority == "" {
			authority = req.Dst.String()
		}
	}
	b := sc.outBuf[:0]
	b = append(b, req.Method...)
	b = append(b, ' ')
	b = append(b, req.tgt.Path...)
	b = append(b, " HTTP/1.1\r\nHost: "...)
	b = append(b, authority...)
	b = append(b, "\r\n"...)
	b, err := x.outFields.AppendTo(b)
	if err != nil {
		return nil, err
	}
	switch req.body {
	case httphead.Length:
		b = append(b, "Content-Length: "...)
		b = strconv.AppendInt(b, req.length, 10)
		b = append(b, "\r\n"...)
	case httphead.Chunked:
		b = append(b, "Transfer-Encoding: chunked\r\n"...)
	case httphead.NoBody, httphead.UntilClose:
		// No body; a request body is never read until close.
	}
	switch {
	case req.upgrade:
		for _, v := range req.Header.Values("Upgrade") {
			b = append(b, "Upgrade: "...)
			b = append(b, v...)
			b = append(b, "\r\n"...)
		}
		b = append(b, "Connection: Upgrade\r\n"...)
	case !x.pooled:
		b = append(b, "Connection: close\r\n"...)
	}
	b = append(b, "\r\n"...)
	sc.outBuf = b
	return b, nil
}

// appendVia adds this server to the Via field.
func appendVia(h httphead.Header, minor int, via string) httphead.Header {
	v := "1." + strconv.Itoa(minor) + " " + via
	for i := range h {
		if strings.EqualFold(h[i].Name, "Via") {
			h[i].Value += ", " + v
			return h
		}
	}
	return append(h, httphead.Field{Name: "Via", Value: v})
}

// Parts of the request.
const (
	reqHeadPart = iota
	reqBodyPart
	reqUpgradePart
	reqRawPart
)

// nextRequestPart returns the next part of the request as it goes to the
// target: the head with the buffered start of the body, the body, and,
// after an upgrade, the new protocol.
func (x *exchange) nextRequestPart() (io.Reader, error) {
	sc, req := x.sc, x.req
	for {
		state := x.reqState
		x.reqState++
		switch state {
		case reqHeadPart:
			return &x.reqHead, nil
		case reqBodyPart:
			switch req.body {
			case httphead.Length:
				if left := req.length - x.reqHead.drained; left > 0 {
					// Beneath the buffer, which the head part drained, so
					// that the relay splices it.
					return &io.LimitedReader{R: sc.c, N: left}, nil
				}
			case httphead.Chunked:
				x.reqStream.reset(sc.br, httphead.Chunked, true, positive(sc.s.MaxHeaderBytes, DefaultMaxHeaderBytes))
				return &x.reqStream, nil
			case httphead.NoBody, httphead.UntilClose:
				// No body; a request body is never read until close.
			}
		case reqUpgradePart:
			x.reqDone.Store(true)
			x.requestDone()
			if x.decided == nil {
				return nil, nil
			}
			// The connection carries the new protocol once the target
			// switches to it.
			select {
			case <-x.decided:
			case <-x.aborted:
				return nil, net.ErrClosed
			}
			if !x.upgraded.Load() {
				return nil, nil
			}
			x.rawHead = headPart{br: sc.br, n: math.MaxInt64}
			return &x.rawHead, nil
		case reqRawPart:
			return sc.c, nil
		default: // the request has ended
			return nil, nil
		}
	}
}

// requestDone starts ResponseHeaderTimeout once the request is sent.
func (x *exchange) requestDone() {
	d := x.sc.s.ResponseHeaderTimeout
	if d <= 0 {
		return
	}
	x.headMu.Lock()
	if !x.headSeen {
		_ = x.up.c.SetReadDeadline(time.Now().Add(d))
	}
	x.headMu.Unlock()
}

// nextResponsePart returns the next part of the responses as they go to the
// client: each interim response, the final head with the buffered start of
// the body, and the body.
func (x *exchange) nextResponsePart() (io.Reader, error) {
	for {
		switch x.respState {
		case respHead:
			part, err := x.responseHead()
			if part != nil || err != nil {
				return part, err
			}
		case respBody:
			x.respState = respEnd
			if part := x.responseBody(); part != nil {
				return part, nil
			}
		default:
			x.respDone.Store(true)
			return nil, nil
		}
	}
}

// responseHead reads a response head and returns the part that sends it on,
// or nil for an interim response that is not sent on. A response that
// cannot be read is answered with 502 Bad Gateway, or 504 when it timed
// out, as no final response has started.
func (x *exchange) responseHead() (io.Reader, error) {
	sc, req, up := x.sc, x.req, x.up
	maxHeader := positive(sc.s.MaxHeaderBytes, DefaultMaxHeaderBytes)
	var err error
	sc.respBuf, err = httphead.Read(up.br, sc.respBuf, maxHeader)
	if len(sc.respBuf) > 0 || up.br.Buffered() > 0 {
		x.gotResponse.Store(true)
	}
	var resp httphead.Response
	if err == nil {
		if resp, err = httphead.ParseResponse(string(sc.respBuf), x.respFields[:0]); err == nil {
			x.respFields = resp.Header
		}
	}
	if err == nil && resp.Code == 101 && !req.upgrade {
		err = errors.New("switching protocols without an upgrade request")
	}
	if err != nil {
		switch {
		case x.canRetry() && !netx.IsTimeout(err) && !x.aborted0():
			// Most likely a kept connection that the target closed: the
			// request goes again on a new one.
			x.retry.Store(true)
			return nil, errRetry
		case errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || x.aborted0():
			return nil, err
		}
		return x.badGateway(err), nil
	}
	if resp.Code >= 200 || resp.Code == 101 {
		x.headMu.Lock()
		x.headSeen = true
		if sc.s.ResponseHeaderTimeout > 0 {
			_ = up.c.SetReadDeadline(time.Time{})
		}
		x.headMu.Unlock()
	}
	interim := resp.Code < 200 && resp.Code != 101
	if interim && req.minor == 0 {
		return nil, nil // not sent to HTTP/1.0 clients (RFC 9110, section 15.2)
	}
	framing, length, codings, err := httphead.ResponseBody(req.Method, resp.Code, resp.Header)
	if err == nil && codings != "" && req.minor == 0 {
		// A transfer coding cannot reach an HTTP/1.0 client.
		err = errors.New("transfer coding " + strconv.Quote(codings) + " for an HTTP/1.0 client")
	}
	if err != nil {
		return x.badGateway(err), nil
	}
	if resp.Code == 101 {
		framing = httphead.NoBody
	}
	noBody := framing == httphead.NoBody
	// Re-chunked for HTTP/1.1 clients, so that a body read until close
	// keeps the client connection; HTTP/1.0 clients get it as it is.
	out := (framing == httphead.Chunked || framing == httphead.UntilClose) && req.minor == 1
	keep := !interim && resp.Code != 101 && req.keepAlive &&
		(framing == httphead.NoBody || framing == httphead.Length || out)
	x.outFields = copyFields(x.outFields[:0], resp.Header, out && framing == httphead.Chunked, noBody)
	if sc.s.Via != "" && !interim {
		x.outFields = appendVia(x.outFields, resp.Minor, sc.s.Via)
	}
	if sc.s.ResponseHeader != nil {
		sc.s.ResponseHeader(req, resp.Code, &x.outFields)
	}
	reason := resp.Reason
	if reason == "" {
		reason = StatusText(resp.Code)
	}
	b := appendStatusLine(sc.respOut[:0], resp.Code, reason)
	if b, err = x.outFields.AppendTo(b); err != nil {
		return nil, err
	}
	switch {
	case interim:
	case resp.Code == 101:
		for _, v := range resp.Header.Values("Upgrade") {
			b = append(b, "Upgrade: "...)
			b = append(b, v...)
			b = append(b, "\r\n"...)
		}
		b = append(b, "Connection: Upgrade\r\n"...)
	case !keep:
		b = append(b, "Connection: close\r\n"...)
	case req.minor == 0:
		b = append(b, "Connection: keep-alive\r\n"...)
	}
	switch {
	case out && codings != "":
		b = append(b, "Transfer-Encoding: "...)
		b = append(b, codings...)
		b = append(b, ", chunked\r\n"...)
	case out:
		b = append(b, "Transfer-Encoding: chunked\r\n"...)
	case framing == httphead.Length:
		b = append(b, "Content-Length: "...)
		b = strconv.AppendInt(b, length, 10)
		b = append(b, "\r\n"...)
	}
	b = append(b, "\r\n"...)
	sc.respOut = b
	if interim {
		x.respHead = headPart{head: b}
		return &x.respHead, nil
	}
	x.status, x.keepAlive = resp.Code, keep
	// The target's connection is kept when it says so, HTTP/1.1 without
	// "Connection: close", and the body ends without it closing.
	x.upKeep = x.pooled && resp.Minor == 1 && resp.Code != 101 && framing != httphead.UntilClose &&
		!resp.Header.HasToken("Connection", "close")
	x.respState = respBody
	maxTrailer := positive(sc.s.MaxHeaderBytes, DefaultMaxHeaderBytes)
	drain := int64(0)
	switch framing {
	case httphead.Length:
		drain = length
	case httphead.UntilClose:
		if !out {
			drain = math.MaxInt64
		} else {
			x.respStream.reset(up.br, httphead.UntilClose, true, maxTrailer)
		}
	case httphead.Chunked:
		x.respStream.reset(up.br, httphead.Chunked, out, maxTrailer)
	case httphead.NoBody:
		// Nothing to drain or decode.
	}
	x.respFraming, x.respLength = framing, length
	if resp.Code == 101 {
		// The new protocol: what was buffered goes with the head, then
		// the connection beneath.
		x.upgraded.Store(true)
		drain = math.MaxInt64
	}
	x.decide()
	x.respHead = headPart{head: b, br: up.br, n: drain}
	return &x.respHead, nil
}

// responseBody returns the part that sends the final response's body on,
// beneath the buffer that the head part drained, or nil for none.
func (x *exchange) responseBody() io.Reader {
	if x.upgraded.Load() {
		return x.up.c
	}
	switch x.respFraming {
	case httphead.Length:
		if left := x.respLength - x.respHead.drained; left > 0 {
			return &io.LimitedReader{R: x.up.c, N: left}
		}
		return nil
	case httphead.UntilClose, httphead.Chunked:
		if x.respHead.n == math.MaxInt64 {
			return x.up.c // as it is, until close
		}
		return &x.respStream
	case httphead.NoBody:
		// Nothing follows the head.
	}
	return nil
}

// canRetry reports whether the request may go again on a new connection:
// it went over a kept one, which the target may have closed meanwhile, got
// no byte of a response, and is idempotent.
func (x *exchange) canRetry() bool {
	return x.up.reused && !x.gotResponse.Load() && idempotent(x.req)
}

// aborted0 reports whether the relay stopped early.
func (x *exchange) aborted0() bool {
	if x.aborted == nil {
		return false
	}
	select {
	case <-x.aborted:
		return true
	default:
		return false
	}
}

// decide tells a request waiting for the final response whether the
// protocol switched.
func (x *exchange) decide() {
	if x.decided != nil {
		close(x.decided)
	}
}

// badGatewayReply answers a response that could not be read.
const badGatewayReply = "Content-Length: 0\r\nConnection: close\r\n\r\n"

func (x *exchange) badGateway(err error) io.Reader {
	code := 502
	if netx.IsTimeout(err) {
		code = 504
	}
	x.failed, x.status = err, code
	x.respState, x.keepAlive = respNone, false
	b := appendStatusLine(x.sc.respOut[:0], code, StatusText(code))
	b = append(b, badGatewayReply...)
	x.sc.respOut = b
	x.decide()
	x.respHead = headPart{head: b}
	return &x.respHead
}

// abort ends a wait for the final response.
func (x *exchange) abort() {
	if x.aborted != nil {
		x.abortMu.Do(func() { close(x.aborted) })
	}
}

// responseSent is called when the response has been sent. A request that
// is not done yet, such as one whose target answered before its body
// ended, is cut off if it is still not done after a grace that lets one
// that was about to end, as when the target answered its last bytes at
// once, end as it would: its connection then ends after the response.
// After an upgrade the client's side is shut down for writing.
func (x *exchange) responseSent() error {
	if x.upgraded.Load() {
		return closeWrite(x.sc.c)
	}
	if x.reqDone.Load() {
		return nil
	}
	x.cutMu.Lock()
	defer x.cutMu.Unlock()
	if !x.finished && x.cutTimer == nil {
		x.cutTimer = time.AfterFunc(lingerTimeout, x.cut)
	}
	return nil
}

// cut cuts off a request that the response ended before: its rest is
// neither read from the client nor written to the target, which may have
// stopped reading it.
func (x *exchange) cut() {
	x.cutMu.Lock()
	defer x.cutMu.Unlock()
	if x.finished || x.reqDone.Load() {
		return
	}
	x.interrupted.Store(true)
	_ = x.sc.c.SetReadDeadline(time.Unix(1, 0))
	_ = x.up.c.SetWriteDeadline(time.Unix(1, 0))
}

// requestSent is called when the request has been sent; the target's side
// is shut down for writing after an upgrade only, as some servers take a
// shutdown for the end of the exchange.
func (x *exchange) requestSent() error {
	if x.upgraded.Load() {
		return closeWrite(x.up.c)
	}
	return nil
}

// closeClient leaves the client connection open after an exchange that
// ended well, for the next request, or that is retried, and closes it
// otherwise, which also ends a read or write blocked on it.
func (x *exchange) closeClient() error {
	// A request cut off is ended by the deadlines that cut it; its
	// connection is closed after a lingering read.
	if x.retry.Load() || x.canRetry() || x.respDone.Load() && !x.upgraded.Load() && (x.reqDone.Load() || x.interrupted.Load()) {
		return nil
	}
	x.abort()
	return x.sc.c.Close()
}

// closeTarget leaves the target's connection open after an exchange that
// ended well, for exchange to keep or close, and closes it otherwise.
func (x *exchange) closeTarget() error {
	if x.reqDone.Load() && x.respDone.Load() && !x.upgraded.Load() && !x.interrupted.Load() {
		return nil
	}
	x.abort()
	return x.up.c.Close()
}
