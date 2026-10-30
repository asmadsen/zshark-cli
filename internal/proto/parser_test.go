package proto_test

import (
	"bytes"
	"strings"
	"testing"

	"zshark/internal/proto"
)

func envelope(payload []byte) []byte {
	b := make([]byte, 0, len(payload)+3)
	b = append(b, proto.StartByte, byte(len(payload)))
	b = append(b, payload...)
	b = append(b, proto.EndByte)
	return b
}

func payload(channel byte, frame ...byte) []byte {
	p := make([]byte, proto.MetadataLen+len(frame))
	p[0] = 0xde
	p[1] = 0xad
	p[2] = 0xbe
	p[3] = 0xef
	p[4] = channel
	copy(p[proto.MetadataLen:], frame)
	return p
}

func TestParseFrameWithText(t *testing.T) {
	p := proto.NewParser()
	stream := append([]byte("Sniffer V1.0 [ConBee II]\r\nChannel 11\n"), envelope(payload(11, 0x61, 0x88, 0x00))...)
	res := p.Feed(stream)

	if len(res.Frames) != 1 {
		t.Fatalf("frames = %d, want 1 (errors: %v)", len(res.Frames), res.Errors)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	if got, want := res.Frames[0].Channel(), byte(11); got != want {
		t.Errorf("channel = %d, want %d", got, want)
	}
	if got, want := res.Frames[0].Data(), []byte{0x61, 0x88, 0x00}; !bytes.Equal(got, want) {
		t.Errorf("data = %x, want %x", got, want)
	}
	wantText := []string{"Sniffer V1.0 [ConBee II]", "Channel 11"}
	if len(res.Text) != len(wantText) {
		t.Fatalf("text = %q, want %q", res.Text, wantText)
	}
	for i := range wantText {
		if res.Text[i] != wantText[i] {
			t.Errorf("text[%d] = %q, want %q", i, res.Text[i], wantText[i])
		}
	}
}

func TestParseFramesSplitAcrossReads(t *testing.T) {
	p := proto.NewParser()
	stream := append([]byte("IDLE\r\n"), envelope(payload(15, 0x01, 0x02, 0x03))...)
	stream = append(stream, envelope(payload(20, 0xaa))...)

	var frames []proto.Frame
	var text []string
	for i := 0; i < len(stream); i++ {
		res := p.Feed(stream[i : i+1])
		frames = append(frames, res.Frames...)
		text = append(text, res.Text...)
		if len(res.Errors) != 0 {
			t.Fatalf("unexpected errors at byte %d: %v", i, res.Errors)
		}
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	if frames[0].Channel() != 15 || !bytes.Equal(frames[0].Data(), []byte{1, 2, 3}) {
		t.Errorf("frame 0 = channel %d data %x", frames[0].Channel(), frames[0].Data())
	}
	if frames[1].Channel() != 20 || !bytes.Equal(frames[1].Data(), []byte{0xaa}) {
		t.Errorf("frame 1 = channel %d data %x", frames[1].Channel(), frames[1].Data())
	}
	if len(text) != 1 || text[0] != "IDLE" {
		t.Errorf("text = %q, want [IDLE]", text)
	}
}

func TestParseResyncAfterBadLength(t *testing.T) {
	tests := []struct {
		name  string
		bad   []byte
		error string
	}{
		{name: "zero", bad: []byte{proto.StartByte, 0x00}, error: "invalid frame length"},
		{name: "short", bad: []byte{proto.StartByte, 0x03, 1, 2, 3, proto.EndByte}, error: "invalid frame length"},
		{name: "absurd", bad: []byte{proto.StartByte, 0xff, 1, 2, 3}, error: "invalid frame length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := proto.NewParser()
			good := envelope(payload(11, 0x11, 0x22))
			res := p.Feed(append(append([]byte{}, tt.bad...), good...))

			if len(res.Errors) == 0 {
				t.Fatal("expected a framing error")
			}
			if !strings.Contains(res.Errors[0].Error(), tt.error) {
				t.Errorf("error = %q, want substring %q", res.Errors[0], tt.error)
			}
			if len(res.Frames) != 1 {
				t.Fatalf("frames = %d, want 1 after resync", len(res.Frames))
			}
			if got, want := res.Frames[0].Data(), []byte{0x11, 0x22}; !bytes.Equal(got, want) {
				t.Errorf("data = %x, want %x", got, want)
			}
		})
	}
}

func TestParseResyncAfterBadTerminator(t *testing.T) {
	p := proto.NewParser()
	bad := []byte{proto.StartByte, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xff}
	good := envelope(payload(26, 0x42))
	res := p.Feed(append(bad, good...))

	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Error(), "terminator") {
		t.Fatalf("errors = %v, want terminator error", res.Errors)
	}
	if len(res.Frames) != 1 {
		t.Fatalf("frames = %d, want 1 after resync", len(res.Frames))
	}
	if res.Frames[0].Channel() != 26 || !bytes.Equal(res.Frames[0].Data(), []byte{0x42}) {
		t.Errorf("frame = channel %d data %x", res.Frames[0].Channel(), res.Frames[0].Data())
	}
}

func TestParseIgnoresTextOnlyStream(t *testing.T) {
	p := proto.NewParser()
	res := p.Feed([]byte("Channel 15\r\nIDLE\r\n"))
	if len(res.Frames) != 0 || len(res.Errors) != 0 {
		t.Fatalf("frames=%d errors=%v, want none", len(res.Frames), res.Errors)
	}
	if len(res.Text) != 2 || res.Text[0] != "Channel 15" || res.Text[1] != "IDLE" {
		t.Fatalf("text = %q", res.Text)
	}
}

func TestParsePartialBannerFlush(t *testing.T) {
	p := proto.NewParser()
	if res := p.Feed([]byte("Sniffer V1.0")); len(res.Text) != 0 {
		t.Fatalf("unexpected text before newline: %q", res.Text)
	}
	lines := p.FlushText()
	if len(lines) != 1 || lines[0] != "Sniffer V1.0" {
		t.Fatalf("flushed text = %q", lines)
	}
}

func TestParseMaxPayloadOverride(t *testing.T) {
	p := proto.NewParser()
	p.MaxPayload = 10
	tooBig := payload(11, bytes.Repeat([]byte{0xaa}, 5)...)
	res := p.Feed(envelope(tooBig))
	if len(res.Errors) == 0 {
		t.Fatal("expected length error for payload larger than override")
	}
	if len(res.Frames) != 0 {
		t.Fatalf("frames = %d, want 0", len(res.Frames))
	}
}

func TestFrameShortPayload(t *testing.T) {
	f := proto.Frame{Payload: []byte{1, 2, 3}}
	if f.Valid() {
		t.Error("short payload reported valid")
	}
	if f.Data() != nil {
		t.Error("short payload returned data")
	}
	if f.Channel() != 0 {
		t.Errorf("short payload channel = %d", f.Channel())
	}
}
