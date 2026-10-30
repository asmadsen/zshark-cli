package sink_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"zshark/internal/sink"
	"zshark/internal/zep"
)

func TestPcapngBlocks(t *testing.T) {
	var out bytes.Buffer
	w, err := sink.NewPcapng(&out)
	if err != nil {
		t.Fatal(err)
	}

	p1 := zep.Build([]byte{0x61, 0x88, 0x00, 0x7f}, 11, time.Unix(1700000000, 123456000), 1)
	p2 := zep.Build([]byte{0x41, 0x88}, 26, time.Unix(1700000001, 654321000), 2)
	if err := w.Write(p1); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(p2); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	blocks := splitBlocks(t, out.Bytes())
	if len(blocks) != 4 {
		t.Fatalf("blocks = %d, want 4", len(blocks))
	}

	le := binary.LittleEndian
	shb := blocks[0]
	if got := le.Uint32(shb[0:4]); got != 0x0a0d0d0a {
		t.Errorf("SHB type = %#x", got)
	}
	if got := le.Uint32(shb[4:8]); got != 28 {
		t.Errorf("SHB length = %d", got)
	}
	if got := le.Uint32(shb[8:12]); got != 0x1a2b3c4d {
		t.Errorf("SHB byte-order magic = %#x", got)
	}
	if got := le.Uint16(shb[12:14]); got != 1 {
		t.Errorf("SHB major = %d", got)
	}
	if got := le.Uint16(shb[14:16]); got != 0 {
		t.Errorf("SHB minor = %d", got)
	}
	if got := le.Uint64(shb[16:24]); got != ^uint64(0) {
		t.Errorf("SHB section length = %d", got)
	}
	if got := le.Uint32(shb[24:28]); got != 28 {
		t.Errorf("SHB trailer = %d", got)
	}

	idb := blocks[1]
	if got := le.Uint32(idb[0:4]); got != 1 {
		t.Errorf("IDB type = %d", got)
	}
	if got := le.Uint32(idb[4:8]); got != 20 {
		t.Errorf("IDB length = %d", got)
	}
	if got := le.Uint16(idb[8:10]); got != 1 {
		t.Errorf("IDB link type = %d, want Ethernet (1)", got)
	}
	if got := le.Uint32(idb[12:16]); got != 65535 {
		t.Errorf("IDB snaplen = %d", got)
	}
	if got := le.Uint32(idb[16:20]); got != 20 {
		t.Errorf("IDB trailer = %d", got)
	}

	wantTS := []uint64{
		uint64(1700000000)*1e6 + 123456,
		uint64(1700000001)*1e6 + 654321,
	}
	for i, packet := range [][]byte{p1, p2} {
		block := blocks[2+i]
		if got := le.Uint32(block[0:4]); got != 6 {
			t.Errorf("EPB %d type = %d", i, got)
		}
		if got := le.Uint32(block[8:12]); got != 0 {
			t.Errorf("EPB %d interface = %d", i, got)
		}
		ts := uint64(le.Uint32(block[12:16]))<<32 | uint64(le.Uint32(block[16:20]))
		if ts != wantTS[i] {
			t.Errorf("EPB %d timestamp = %d, want %d", i, ts, wantTS[i])
		}
		want := sink.EthernetFrame(packet)
		if got := int(le.Uint32(block[20:24])); got != len(want) {
			t.Errorf("EPB %d captured length = %d, want %d", i, got, len(want))
		}
		if got := int(le.Uint32(block[24:28])); got != len(want) {
			t.Errorf("EPB %d original length = %d, want %d", i, got, len(want))
		}
		if got := int(le.Uint32(block[4:8])); got != len(block) {
			t.Errorf("EPB %d block length = %d, want %d", i, got, len(block))
		}
		if got := int(le.Uint32(block[len(block)-4:])); got != len(block) {
			t.Errorf("EPB %d trailer = %d, want %d", i, got, len(block))
		}
		if !bytes.Equal(block[28:28+len(want)], want) {
			t.Errorf("EPB %d packet bytes differ", i)
		}
		for _, b := range block[28+len(want) : len(block)-4] {
			if b != 0 {
				t.Errorf("EPB %d padding is not zero", i)
				break
			}
		}
	}
}

func TestEthernetFrame(t *testing.T) {
	packet := zep.Build([]byte{0x61, 0x88, 0x01}, 11, time.Unix(1700000000, 0), 7)
	frame := sink.EthernetFrame(packet)

	wantLen := 14 + 20 + 8 + len(packet)
	if len(frame) != wantLen {
		t.Fatalf("frame length = %d, want %d", len(frame), wantLen)
	}
	if !bytes.Equal(frame[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("destination MAC = %x", frame[0:6])
	}
	if !bytes.Equal(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("source MAC = %x", frame[6:12])
	}
	if got := binary.BigEndian.Uint16(frame[12:14]); got != 0x0800 {
		t.Errorf("ethertype = %#x", got)
	}

	ip := frame[14:34]
	if ip[0] != 0x45 {
		t.Errorf("IP version/IHL = %#x", ip[0])
	}
	if got := binary.BigEndian.Uint16(ip[2:4]); got != uint16(20+8+len(packet)) {
		t.Errorf("IP total length = %d", got)
	}
	if ip[8] != 64 || ip[9] != 17 {
		t.Errorf("IP TTL/proto = %d/%d", ip[8], ip[9])
	}
	if !bytes.Equal(ip[12:16], []byte{192, 168, 20, 234}) {
		t.Errorf("IP src = %v", ip[12:16])
	}
	if !bytes.Equal(ip[16:20], []byte{192, 168, 20, 1}) {
		t.Errorf("IP dst = %v", ip[16:20])
	}
	if ipChecksum(ip) != 0 {
		t.Errorf("IPv4 header checksum invalid: %#x", binary.BigEndian.Uint16(ip[10:12]))
	}

	udp := frame[34:]
	if got := binary.BigEndian.Uint16(udp[0:2]); got != 48311 {
		t.Errorf("UDP source port = %d", got)
	}
	if got := binary.BigEndian.Uint16(udp[2:4]); got != 17754 {
		t.Errorf("UDP destination port = %d", got)
	}
	if got := binary.BigEndian.Uint16(udp[4:6]); got != uint16(8+len(packet)) {
		t.Errorf("UDP length = %d", got)
	}
	if got := binary.BigEndian.Uint16(udp[6:8]); got != 0 {
		t.Errorf("UDP checksum = %#x, want 0 (not computed for IPv4)", got)
	}
	if !bytes.Equal(udp[8:], packet) {
		t.Error("UDP payload differs from ZEP packet")
	}
}

func TestPcapngRejectsShortPacket(t *testing.T) {
	var out bytes.Buffer
	w, err := sink.NewPcapng(&out)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Write([]byte{1, 2, 3}); err == nil {
		t.Fatal("short ZEP packet accepted")
	}
}

func TestPcapngFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	w, err := sink.NewPcapngFile(path)
	if err != nil {
		t.Fatal(err)
	}
	packet := zep.Build([]byte{0x61, 0x88, 0x00}, 15, time.Unix(1700000000, 250000000), 9)
	if err := w.Write(packet); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blocks := splitBlocks(t, data)
	if len(blocks) != 3 {
		t.Fatalf("blocks = %d, want SHB, IDB, EPB", len(blocks))
	}
	frame := sink.EthernetFrame(packet)
	epb := blocks[2]
	if got := int(binary.LittleEndian.Uint32(epb[20:24])); got != len(frame) {
		t.Errorf("captured length = %d, want %d", got, len(frame))
	}
	if !bytes.Equal(epb[28:28+len(frame)], frame) {
		t.Error("EPB payload differs from EthernetFrame")
	}
}

func TestPcapngTimestampRoundsToNextSecond(t *testing.T) {
	var out bytes.Buffer
	w, err := sink.NewPcapng(&out)
	if err != nil {
		t.Fatal(err)
	}
	packet := zep.Build(nil, 11, time.Unix(1700000000, 999999999), 1)
	if err := w.Write(packet); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	blocks := splitBlocks(t, out.Bytes())
	epb := blocks[2]
	got := uint64(binary.LittleEndian.Uint32(epb[12:16]))<<32 | uint64(binary.LittleEndian.Uint32(epb[16:20]))
	if want := uint64(1700000001) * 1_000_000; got != want {
		t.Errorf("timestamp = %d, want %d", got, want)
	}
}

func splitBlocks(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var blocks [][]byte
	le := binary.LittleEndian
	for off := 0; off < len(data); {
		if off+8 > len(data) {
			t.Fatalf("truncated block header at %d", off)
		}
		total := int(le.Uint32(data[off+4 : off+8]))
		if total < 12 || off+total > len(data) {
			t.Fatalf("bad block length %d at offset %d", total, off)
		}
		blocks = append(blocks, data[off:off+total])
		off += total
	}
	return blocks
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
