package zep_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"zshark/internal/zep"
)

func TestBuildHeaderBytes(t *testing.T) {
	// First data datagram from /tmp/opencode/zshark/zep-sample.pcap.
	frame, _ := hex.DecodeString("6188007fa300009f2d091a000050de1e92490323fefff55e156a57d0deb938c1a4281e6dd7056a42acfeff958edc00ea0b75df48f99c579e80")
	wantHeader, _ := hex.DecodeString("455802010b00000000ee8f2e046758c08b000000ab0000000000000000000039")

	got := zep.BuildNTP(frame, 11, 0xee8f2e046758c08b, 0xab)
	if len(got) != zep.HeaderLen+len(frame) {
		t.Fatalf("length = %d, want %d", len(got), zep.HeaderLen+len(frame))
	}
	if !bytes.Equal(got[:zep.HeaderLen], wantHeader) {
		t.Fatalf("header = %x\nwant   = %x", got[:zep.HeaderLen], wantHeader)
	}
	if !bytes.Equal(got[zep.HeaderLen:], frame) {
		t.Fatalf("frame = %x\nwant  = %x", got[zep.HeaderLen:], frame)
	}
}

func TestBuildFields(t *testing.T) {
	frame := []byte{0x01, 0x02, 0x03, 0x04}
	ts := time.Unix(1700000000, 123456789)
	got := zep.Build(frame, 26, ts, 0x01020304)

	if string(got[0:2]) != "EX" {
		t.Errorf("magic = %q", got[0:2])
	}
	if got[2] != zep.Version || got[3] != zep.TypeData {
		t.Errorf("version/type = %d/%d", got[2], got[3])
	}
	if got[4] != 26 {
		t.Errorf("channel = %d", got[4])
	}
	if !bytes.Equal(got[5:9], []byte{0, 0, 0, 0}) {
		t.Errorf("device/mode/lqi = %x", got[5:9])
	}
	if want := []byte{0xe8, 0xfe, 0x6f, 0x80, 0x1f, 0x9a, 0xdd, 0x37}; !bytes.Equal(got[9:17], want) {
		t.Errorf("NTP timestamp = %x, want %x", got[9:17], want)
	}
	if !bytes.Equal(got[17:21], []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("sequence = %x", got[17:21])
	}
	if !bytes.Equal(got[21:31], make([]byte, 10)) {
		t.Errorf("reserved = %x", got[21:31])
	}
	if got[31] != 4 {
		t.Errorf("frame length = %d", got[31])
	}
}

func TestNTPTime(t *testing.T) {
	ts := time.Unix(1700000000, 123456789).UTC()
	if got, want := zep.NTPTime(ts), uint64(0xe8fe6f801f9add37); got != want {
		t.Errorf("NTPTime = %016x, want %016x", got, want)
	}
}

func TestTimeFromNTP(t *testing.T) {
	// The first data frame in the sample: 2026-10-30T14:53:56.403697999Z.
	want := time.Unix(1793372036, 403697999).UTC()
	if got := zep.TimeFromNTP(0xee8f2e046758c08b); !got.Equal(want) {
		t.Errorf("TimeFromNTP = %v, want %v", got, want)
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	// 0.5s is exactly representable in NTP's 32-bit fraction.
	ts := time.Unix(1793372036, 500000000).UTC()
	packet := zep.Build([]byte{0xaa}, 11, ts, 1)
	got, ok := zep.Timestamp(packet)
	if !ok {
		t.Fatal("Timestamp returned false")
	}
	if !got.Equal(ts) {
		t.Errorf("timestamp = %v, want %v", got, ts)
	}
}

func TestTimestampShort(t *testing.T) {
	if _, ok := zep.Timestamp(make([]byte, zep.HeaderLen-1)); ok {
		t.Error("short packet accepted")
	}
}

func TestBuildEmptyFrame(t *testing.T) {
	got := zep.Build(nil, 11, time.Unix(0, 0), 0)
	if len(got) != zep.HeaderLen {
		t.Fatalf("length = %d", len(got))
	}
	if got[31] != 0 {
		t.Errorf("length field = %x", got[31])
	}
}

func TestSequenceIsBigEndian(t *testing.T) {
	got := zep.Build(nil, 11, time.Unix(0, 0), 0x01020304)
	if !bytes.Equal(got[17:21], []byte{1, 2, 3, 4}) {
		t.Errorf("sequence = %x", got[17:21])
	}
	if binary.BigEndian.Uint32(got[17:21]) != 0x01020304 {
		t.Error("sequence not big endian")
	}
}
