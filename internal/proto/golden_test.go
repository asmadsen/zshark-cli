package proto_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"

	"zshark/internal/proto"
	"zshark/internal/zep"
)

const defaultSample = "/tmp/opencode/zshark/zep-sample.pcap"

type goldenFrame struct {
	zep     []byte
	ntp     uint64
	seq     uint32
	channel byte
	frame   []byte
}

// TestGoldenReplaySample reconstructs the serial envelope for every data frame
// in the real ConBee II capture, decodes it with the streaming parser, rebuilds
// the ZEP datagram, and compares it byte-for-byte with the captured datagram.
func TestGoldenReplaySample(t *testing.T) {
	path := os.Getenv("ZSHARK_SAMPLE")
	if path == "" {
		path = defaultSample
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("sample capture not present: %s", path)
	}
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	packets, err := parsePCAP(data)
	if err != nil {
		t.Fatalf("parse sample pcap: %v", err)
	}

	var samples []goldenFrame
	var stream []byte
	for _, packet := range packets {
		z, ok := zepFromEthernet(packet)
		if !ok || len(z) < zep.HeaderLen || z[2] != zep.Version || z[3] != zep.TypeData {
			continue
		}
		n := int(z[31] & 0x7f)
		if len(z) < zep.HeaderLen+n {
			t.Fatalf("truncated ZEP frame: have %d bytes, need %d", len(z), zep.HeaderLen+n)
		}
		frame := z[zep.HeaderLen : zep.HeaderLen+n]

		// Build the 8-byte metadata prefix the dongle would send. Only byte 4
		// (channel) is meaningful in v0; the rest is deliberately non-zero so
		// the test catches a wrong frame offset.
		payload := make([]byte, proto.MetadataLen+len(frame))
		for i := 0; i < proto.MetadataLen; i++ {
			payload[i] = byte(0xa0 + i)
		}
		payload[4] = z[4]
		copy(payload[proto.MetadataLen:], frame)

		stream = append(stream, proto.StartByte, byte(len(payload)))
		stream = append(stream, payload...)
		stream = append(stream, proto.EndByte)
		// Text lines are interleaved in the real stream too.
		stream = append(stream, []byte("Channel 11\r\n")...)

		samples = append(samples, goldenFrame{
			zep:     z,
			ntp:     binary.BigEndian.Uint64(z[9:17]),
			seq:     binary.BigEndian.Uint32(z[17:21]),
			channel: z[4],
			frame:   frame,
		})
	}
	if len(samples) < 10 {
		t.Fatalf("sample contains only %d data frames", len(samples))
	}

	parser := proto.NewParser()
	var frames []proto.Frame
	for i := 0; i < len(stream); i += 5 {
		end := i + 5
		if end > len(stream) {
			end = len(stream)
		}
		res := parser.Feed(stream[i:end])
		frames = append(frames, res.Frames...)
		if len(res.Errors) != 0 {
			t.Fatalf("parse error at stream byte %d: %v", i, res.Errors)
		}
	}
	if len(frames) != len(samples) {
		t.Fatalf("decoded %d frames, want %d", len(frames), len(samples))
	}

	for i, want := range samples {
		gotFrame := frames[i]
		if gotFrame.Channel() != want.channel {
			t.Errorf("frame %d channel = %d, want %d", i, gotFrame.Channel(), want.channel)
		}
		if !bytes.Equal(gotFrame.Data(), want.frame) {
			t.Errorf("frame %d data mismatch\n got %x\nwant %x", i, gotFrame.Data(), want.frame)
			continue
		}
		got := zep.BuildNTP(gotFrame.Data(), gotFrame.Channel(), want.ntp, want.seq)
		if !bytes.Equal(got, want.zep) {
			t.Errorf("frame %d ZEP mismatch\n got %x\nwant %x", i, got, want.zep)
		}
	}
}

func parsePCAP(data []byte) ([][]byte, error) {
	if len(data) < 24 {
		return nil, errors.New("short pcap header")
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(data[:4]) == 0xa1b2c3d4:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(data[:4]) == 0xa1b2c3d4:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("unsupported pcap magic %x", data[:4])
	}
	if linkType := order.Uint32(data[20:24]); linkType != 1 {
		return nil, fmt.Errorf("unsupported pcap link type %d", linkType)
	}

	var packets [][]byte
	for off := 24; off < len(data); {
		if off+16 > len(data) {
			return nil, errors.New("truncated pcap record header")
		}
		incl := int(order.Uint32(data[off+8 : off+12]))
		off += 16
		if incl < 0 || off+incl > len(data) {
			return nil, fmt.Errorf("truncated pcap record: %d bytes at offset %d", incl, off)
		}
		packets = append(packets, data[off:off+incl])
		off += incl
	}
	return packets, nil
}

func zepFromEthernet(packet []byte) ([]byte, bool) {
	if len(packet) < 14 {
		return nil, false
	}
	if binary.BigEndian.Uint16(packet[12:14]) != 0x0800 {
		return nil, false
	}
	ip := packet[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 17 {
		return nil, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return nil, false
	}
	udp := ip[ihl:]
	if len(udp) < 8 {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || len(udp) < udpLen {
		return nil, false
	}
	return udp[8:udpLen], true
}
