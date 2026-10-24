package wsconn

import (
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/djylb/netx/httphead"
)

// Compression configures permessage-deflate (RFC 7692). It is negotiated
// without context takeover in both directions: each message is compressed
// on its own, so that a connection keeps no compression state between
// messages, which would take about 1 MB per connection. A peer that
// insists on context takeover for its own messages is declined, which
// leaves the connection uncompressed.
type Compression struct {
	// Level is the compress/flate level of sent messages, from
	// flate.HuffmanOnly (-2) to flate.BestCompression (9); zero means
	// flate.BestSpeed.
	Level int
	// Threshold is the size below which messages are sent uncompressed;
	// zero means 128 bytes, and a negative threshold compresses every
	// message.
	Threshold int
}

// deflateConfig is a negotiated Compression.
type deflateConfig struct {
	level     int
	threshold int
}

func (c *Compression) config() *deflateConfig {
	d := &deflateConfig{level: c.Level, threshold: c.Threshold}
	if d.level == 0 || d.level < flate.HuffmanOnly || d.level > flate.BestCompression {
		d.level = flate.BestSpeed
	}
	switch {
	case d.threshold == 0:
		d.threshold = 128
	case d.threshold < 0:
		d.threshold = 0
	}
	return d
}

const deflateExtension = "permessage-deflate"

// deflateOffer is what a client offers and a server accepts.
const deflateOffer = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"

// deflateParams are the parameters of a permessage-deflate offer or
// response.
type deflateParams struct {
	serverNoTakeover bool
	clientNoTakeover bool
	serverMaxBits    int // 0 when absent
	clientMaxBits    int // 0 when absent, -1 without a value
}

// parseDeflateParams parses the parameters after "permessage-deflate",
// failing on unknown, repeated and invalid ones (RFC 7692, section 7.1).
func parseDeflateParams(params []string) (deflateParams, error) {
	var p deflateParams
	seen := map[string]bool{}
	for _, param := range params {
		name, value, hasValue := strings.Cut(param, "=")
		name = strings.ToLower(httphead.TrimOWS(name))
		value = httphead.TrimOWS(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if seen[name] {
			return p, fmt.Errorf("repeated parameter %s", name)
		}
		seen[name] = true
		switch name {
		case "server_no_context_takeover", "client_no_context_takeover":
			if hasValue {
				return p, fmt.Errorf("value for %s", name)
			}
			if name[0] == 's' {
				p.serverNoTakeover = true
			} else {
				p.clientNoTakeover = true
			}
		case "server_max_window_bits", "client_max_window_bits":
			bits := -1
			if hasValue {
				n, err := strconv.Atoi(value)
				if err != nil || n < 8 || n > 15 || value[0] < '1' || value[0] > '9' {
					return p, fmt.Errorf("invalid %s %q", name, value)
				}
				bits = n
			} else if name[0] == 's' {
				return p, fmt.Errorf("no value for %s", name)
			}
			if name[0] == 's' {
				p.serverMaxBits = bits
			} else {
				p.clientMaxBits = bits
			}
		default:
			return p, fmt.Errorf("unknown parameter %s", name)
		}
	}
	return p, nil
}

// extensionOffers yields the extensions of the Sec-WebSocket-Extensions
// fields of h, each as its name and parameters.
func extensionOffers(h *httphead.Header, yield func(name string, params []string) bool) {
	for _, v := range h.Values("Sec-WebSocket-Extensions") {
		for ext := range strings.SplitSeq(v, ",") {
			parts := strings.Split(ext, ";")
			name := httphead.TrimOWS(parts[0])
			if name == "" {
				continue
			}
			if !yield(name, parts[1:]) {
				return
			}
		}
	}
}

// acceptDeflate returns the Sec-WebSocket-Extensions value with which the
// server accepts one of the permessage-deflate offers of h, if any. It
// accepts the first offer that it can serve: one that lets it use the full
// 32 KiB window of compress/flate, which has no smaller one.
func acceptDeflate(h *httphead.Header) (string, bool) {
	resp, ok := "", false
	extensionOffers(h, func(name string, params []string) bool {
		if !strings.EqualFold(name, deflateExtension) {
			return true
		}
		p, err := parseDeflateParams(params)
		if err != nil || p.serverMaxBits > 0 && p.serverMaxBits < 15 {
			return true
		}
		resp, ok = deflateOffer, true
		if p.serverMaxBits == 15 {
			// An accepted limit is answered with one no larger (RFC 7692,
			// section 7.1.2.1).
			resp += "; server_max_window_bits=15"
		}
		return false
	})
	return resp, ok
}

// checkDeflateResponse checks the Sec-WebSocket-Extensions of a response
// to the client's offer, and returns whether it accepted permessage-deflate.
func checkDeflateResponse(h *httphead.Header, offered bool) (bool, error) {
	accepted := false
	var err error
	extensionOffers(h, func(name string, params []string) bool {
		if !offered || !strings.EqualFold(name, deflateExtension) || accepted {
			err = fmt.Errorf("unrequested extension %q", name)
			return false
		}
		var p deflateParams
		if p, err = parseDeflateParams(params); err != nil {
			return false
		}
		switch {
		case !p.serverNoTakeover:
			// It was offered and must be accepted (RFC 7692, section
			// 7.1.1.1); the inflater keeps no window between messages.
			err = errors.New("permessage-deflate without server_no_context_takeover")
		case p.clientMaxBits != 0:
			err = errors.New("unrequested client_max_window_bits")
		}
		accepted = err == nil
		return err == nil
	})
	return accepted, err
}

// syncTail ends a flushed deflate stream, which permessage-deflate leaves
// out of the messages.
const syncTail = "\x00\x00\xff\xff"

// deflateTail is appended to a compressed message to inflate it: the sync
// tail that the sender left out and an empty final block, so that the
// inflater ends without an error.
const deflateTail = syncTail + "\x01\x00\x00\xff\xff"

type flateWriter = *flate.Writer

// deflaters pools compressors by level, from flate.HuffmanOnly.
var deflaters [flate.BestCompression - flate.HuffmanOnly + 1]sync.Pool

func getDeflater(level int, w io.Writer) *flate.Writer {
	if fw, ok := deflaters[level-flate.HuffmanOnly].Get().(*flate.Writer); ok {
		fw.Reset(w)
		return fw
	}
	fw, _ := flate.NewWriter(w, level) // the level is valid
	return fw
}

func putDeflater(level int, fw *flate.Writer) {
	fw.Reset(nil)
	deflaters[level-flate.HuffmanOnly].Put(fw)
}

var inflaters sync.Pool

// noInput is what pooled inflaters read from; they never read it.
var noInput = strings.NewReader("")

func getInflater(r io.Reader) io.ReadCloser {
	if fr, ok := inflaters.Get().(io.ReadCloser); ok {
		_ = fr.(flate.Resetter).Reset(r, nil)
		return fr
	}
	return flate.NewReader(r)
}

func putInflater(fr io.ReadCloser) {
	_ = fr.(flate.Resetter).Reset(noInput, nil)
	inflaters.Put(fr)
}

// rawReader reads the compressed payload of the current message, across
// its frames, followed by deflateTail. It is an io.ByteReader, so that the
// inflater reads it without a buffer of its own.
type rawReader struct{ c *Conn }

func (r *rawReader) Read(p []byte) (int, error) {
	c := r.c
	n, err := c.readRaw(p)
	if err == io.EOF {
		n = copy(p, deflateTail[c.rtail:])
		c.rtail += n
		if n > 0 {
			err = nil
		}
	}
	if err != nil {
		c.rawErr = err
	}
	return n, err
}

func (r *rawReader) ReadByte() (byte, error) {
	c := r.c
	for c.rremain == 0 {
		if c.rfin {
			if c.rtail < len(deflateTail) {
				c.rtail++
				return deflateTail[c.rtail-1], nil
			}
			c.rawErr = io.EOF
			return 0, io.EOF
		}
		if err := c.nextDataFrame(); err != nil {
			c.rawErr = err
			return 0, err
		}
	}
	b, err := c.br.ReadByte()
	if err != nil {
		err = c.readErr(err, true)
		c.rawErr = err
		return 0, err
	}
	c.rremain--
	if c.rmasked {
		b ^= byte(c.rkey >> (8 * c.rpos))
		c.rpos = (c.rpos + 1) & 3
	}
	return b, nil
}

// inflateRead reads the inflated payload of the current message.
func (c *Conn) inflateRead(p []byte) (int, error) {
	if c.inflate == nil {
		c.inflate = getInflater(&c.raw)
	}
	c.rawErr = nil
	n, err := c.inflate.Read(p)
	switch {
	case err == nil:
		return n, nil
	case err == io.EOF:
		// What follows a final block, at least the tail, is not part of
		// the message (RFC 7692, section 7.2.3.3).
		if derr := c.discardRaw(); derr != nil {
			return n, derr
		}
		return n, io.EOF
	case c.rerr != nil:
		// The connection failed, as on the peer's close frame.
		return n, c.rerr
	case c.rawErr != nil && errors.Is(err, c.rawErr):
		// An error of the connection beneath, also a timeout, which the
		// inflater cannot resume from.
		c.rerr = err
		return n, err
	}
	return n, c.fail(StatusInvalidPayload, protocolError("invalid compressed data: "+err.Error()))
}
