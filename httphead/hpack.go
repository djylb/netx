package httphead

import (
	"errors"
	"sync"
)

// hpackField is a header field of HPACK.
type hpackField struct {
	name, value string
}

const (
	// hpackTableSize is the size of the dynamic table that a client may use
	// before it learns the server's settings (RFC 9113, Section 6.5.2).
	hpackTableSize     = 4096
	hpackFieldOverhead = 32 // entries count RFC 7541's per-field overhead
)

var errHPACK = errors.New("httphead: invalid HPACK header block")

// hpackDecoder decodes the header blocks of one connection.
type hpackDecoder struct {
	dynamic       []hpackField // oldest first
	size          int
	maxSize       int
	maxHeaderList int
}

func newHPACKDecoder() *hpackDecoder {
	return &hpackDecoder{maxSize: hpackTableSize, maxHeaderList: defaultMaxHeadBytes}
}

// decode calls emit for each field of a header block.
func (d *hpackDecoder) decode(block []byte, emit func(hpackField)) error {
	listSize := 0
	fields := false // whether a field came yet
	for len(block) > 0 {
		b := block[0]
		var f hpackField
		var err error
		remaining := d.maxHeaderList - listSize - hpackFieldOverhead
		switch {
		case b&0x80 != 0: // indexed field
			var i uint64
			if i, block, err = hpackInt(block, 7); err != nil {
				return err
			}
			if f, err = d.at(i); err != nil {
				return err
			}
		case b&0xc0 == 0x40: // literal with incremental indexing
			if f, block, err = d.literal(block, 6, remaining); err != nil {
				return err
			}
			d.add(f)
		case b&0xe0 == 0x20: // dynamic table size update
			if fields {
				return errHPACK // only at the start of a block (RFC 7541, Section 4.2)
			}
			var n uint64
			if n, block, err = hpackInt(block, 5); err != nil {
				return err
			}
			if n > hpackTableSize {
				return errHPACK
			}
			d.maxSize = int(n)
			d.evict()
			continue
		default: // literal without indexing or never indexed
			if f, block, err = d.literal(block, 4, remaining); err != nil {
				return err
			}
		}
		if len(f.name) > remaining || len(f.value) > remaining-len(f.name) {
			return ErrTooLarge
		}
		listSize += len(f.name) + len(f.value) + hpackFieldOverhead
		fields = true
		emit(f)
	}
	return nil
}

// at returns the field at an index of the static and dynamic tables.
func (d *hpackDecoder) at(i uint64) (hpackField, error) {
	switch {
	case i == 0:
		return hpackField{}, errHPACK
	case i <= uint64(len(hpackStatic)):
		return hpackStatic[i-1], nil
	}
	i -= uint64(len(hpackStatic))
	if i > uint64(len(d.dynamic)) {
		return hpackField{}, errHPACK
	}
	return d.dynamic[uint64(len(d.dynamic))-i], nil
}

// literal reads a literal field whose name index has an n-bit prefix.
func (d *hpackDecoder) literal(p []byte, n uint8, remaining int) (hpackField, []byte, error) {
	i, p, err := hpackInt(p, n)
	if err != nil {
		return hpackField{}, nil, err
	}
	var f hpackField
	if i > 0 {
		var named hpackField
		if named, err = d.at(i); err != nil {
			return hpackField{}, nil, err
		}
		f.name = named.name
	} else if f.name, p, err = hpackString(p, remaining); err != nil {
		return hpackField{}, nil, err
	}
	if len(f.name) > remaining {
		return hpackField{}, nil, ErrTooLarge
	}
	if f.value, p, err = hpackString(p, remaining-len(f.name)); err != nil {
		return hpackField{}, nil, err
	}
	return f, p, nil
}

func (d *hpackDecoder) add(f hpackField) {
	size := len(f.name) + len(f.value) + hpackFieldOverhead
	if size > d.maxSize {
		clear(d.dynamic)
		d.dynamic = d.dynamic[:0]
		d.size = 0
		return
	}
	d.dynamic = append(d.dynamic, f)
	d.size += size
	d.evict()
}

func (d *hpackDecoder) evict() {
	n := 0
	for d.size > d.maxSize && n < len(d.dynamic) {
		d.size -= len(d.dynamic[n].name) + len(d.dynamic[n].value) + hpackFieldOverhead
		n++
	}
	clear(d.dynamic[:n])
	d.dynamic = d.dynamic[n:]
}

// hpackInt reads an integer with an n-bit prefix (RFC 7541, Section 5.1).
func hpackInt(p []byte, n uint8) (uint64, []byte, error) {
	if len(p) == 0 {
		return 0, nil, errHPACK
	}
	mask := uint64(1)<<n - 1
	v := uint64(p[0]) & mask
	p = p[1:]
	if v < mask {
		return v, p, nil
	}
	for shift := uint(0); len(p) > 0 && shift < 63; shift += 7 {
		b := p[0]
		p = p[1:]
		v += uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, p, nil
		}
	}
	return 0, nil, errHPACK
}

// hpackString reads a string literal (RFC 7541, Section 5.2).
func hpackString(p []byte, limit int) (string, []byte, error) {
	if len(p) == 0 {
		return "", nil, errHPACK
	}
	huffman := p[0]&0x80 != 0
	n, p, err := hpackInt(p, 7)
	if err != nil || n > uint64(len(p)) {
		return "", nil, errHPACK
	}
	if limit < 0 || !huffman && n > uint64(limit) {
		return "", nil, ErrTooLarge
	}
	raw, p := p[:n], p[n:]
	if !huffman {
		return string(raw), p, nil
	}
	s, err := huffmanDecode(raw, limit)
	return s, p, err
}

// huffmanNode is a node of the Huffman decoding tree, which consumes eight
// bits per level.
type huffmanNode struct {
	children *[256]*huffmanNode // nil for a leaf
	sym      byte
	codeLen  uint8 // bits of the code that the leaf uses at its level
}

var huffmanRoot = sync.OnceValue(func() *huffmanNode {
	root := &huffmanNode{children: new([256]*huffmanNode)}
	for sym, c := range huffmanCodes {
		code, bits := c.code, c.bits
		n := root
		for bits > 8 {
			bits -= 8
			i := uint8(code >> bits)
			if n.children[i] == nil {
				n.children[i] = &huffmanNode{children: new([256]*huffmanNode)}
			}
			n = n.children[i]
		}
		shift := 8 - bits
		start := int(uint8(code << shift))
		for i := start; i < start+1<<shift; i++ {
			n.children[i] = &huffmanNode{sym: byte(sym), codeLen: bits}
		}
	}
	return root
})

// huffmanDecode decodes a Huffman-coded string, whose padding must be the
// most significant bits of the EOS code, at most seven of them.
func huffmanDecode(p []byte, limit int) (string, error) {
	root := huffmanRoot()
	out := make([]byte, 0, min(len(p), limit))
	n := root
	var cur uint64
	var cbits, sbits uint8 // bits in cur, and bits since the last symbol
	for _, b := range p {
		cur = cur<<8 | uint64(b)
		cbits += 8
		sbits += 8
		for cbits >= 8 {
			n = n.children[cur>>(cbits-8)&0xff]
			if n == nil {
				return "", errHPACK
			}
			if n.children == nil {
				if len(out) == limit {
					return "", ErrTooLarge
				}
				out = append(out, n.sym)
				cbits -= n.codeLen
				n, sbits = root, cbits
			} else {
				cbits -= 8
			}
		}
	}
	for cbits > 0 {
		next := n.children[cur<<(8-cbits)&0xff]
		if next == nil || next.children != nil || next.codeLen > cbits {
			break
		}
		if len(out) == limit {
			return "", ErrTooLarge
		}
		out = append(out, next.sym)
		cbits -= next.codeLen
		n, sbits = root, cbits
	}
	if sbits > 7 || cur&(1<<cbits-1) != 1<<cbits-1 {
		return "", errHPACK
	}
	return string(out), nil
}
