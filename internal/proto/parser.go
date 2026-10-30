package proto

import (
	"bytes"
	"fmt"
	"strings"
)

// ParseResult contains everything produced by one Feed call.
type ParseResult struct {
	Frames []Frame
	Text   []string
	Errors []error
}

// Parser is a streaming decoder for the dongle's frame envelope. It tolerates
// text lines interleaved with binary frames and resynchronises after corrupt
// length or terminator bytes.
//
// The zero value is ready to use. MinPayload and MaxPayload may be overridden
// to tighten or relax validation; zero selects the defaults (8 and 160).
type Parser struct {
	MinPayload int
	MaxPayload int

	buf   []byte
	text  []byte
	lines []string
}

// NewParser returns a parser with the default validation bounds.
func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) limits() (min, max int) {
	min = p.MinPayload
	if min == 0 {
		min = MetadataLen
	}
	max = p.MaxPayload
	if max == 0 {
		max = DefaultMaxPayload
	}
	if max < min {
		max = min
	}
	return min, max
}

// Feed consumes bytes from the serial stream and returns all complete frames,
// text lines, and protocol errors discovered so far.
func (p *Parser) Feed(data []byte) ParseResult {
	p.buf = append(p.buf, data...)
	min, max := p.limits()

	var frames []Frame
	var errs []error

	for len(p.buf) > 0 {
		if p.buf[0] != StartByte {
			i := bytes.IndexByte(p.buf, StartByte)
			if i < 0 {
				p.addText(p.buf)
				p.buf = p.buf[:0]
				break
			}
			p.addText(p.buf[:i])
			p.buf = p.buf[i:]
			continue
		}

		// A text line may have been sent without a trailing newline before
		// the binary frame. Emit it so callers can still see a banner.
		p.flushText()

		if len(p.buf) < 2 {
			break
		}
		n := int(p.buf[1])
		if n < min || n > max {
			errs = append(errs, fmt.Errorf("invalid frame length %d (want %d..%d)", n, min, max))
			// Drop only the start byte and look for the next 0x01. The
			// following bytes may contain the real start of a frame.
			p.buf = p.buf[1:]
			continue
		}
		if len(p.buf) < n+3 {
			break
		}
		if p.buf[n+2] != EndByte {
			errs = append(errs, fmt.Errorf("invalid frame terminator 0x%02x after %d-byte payload", p.buf[n+2], n))
			p.buf = p.buf[1:]
			continue
		}

		payload := make([]byte, n)
		copy(payload, p.buf[2:2+n])
		frames = append(frames, Frame{Payload: payload})
		p.buf = p.buf[n+3:]
	}

	res := ParseResult{Frames: frames, Errors: errs, Text: p.lines}
	p.lines = nil
	return res
}

// FlushText emits any partial text line that has not yet seen a newline. It is
// useful when waiting for a banner that may not be newline terminated.
func (p *Parser) FlushText() []string {
	p.flushText()
	lines := p.lines
	p.lines = nil
	return lines
}

// Reset discards buffered input and text.
func (p *Parser) Reset() {
	p.buf = nil
	p.text = nil
	p.lines = nil
}

func (p *Parser) addText(b []byte) {
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r':
			p.flushText()
		case c == '\t' || (c >= 0x20 && c <= 0x7e):
			// Keep text bounded. The dongle only emits short status lines.
			if len(p.text) < 512 {
				p.text = append(p.text, c)
			}
		default:
			// Ignore binary garbage; it is not useful as a status line.
		}
	}
}

func (p *Parser) flushText() {
	if len(p.text) == 0 {
		return
	}
	line := strings.TrimSpace(string(p.text))
	p.text = p.text[:0]
	if line != "" {
		p.lines = append(p.lines, line)
	}
}
