package proto_test

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"zshark/internal/sink"
	"zshark/internal/zep"
)

// TestPcapngDissectsWithTshark ties the replay sample to the pcapng sink: it
// writes the sample's ZEP data datagrams through internal/sink and asks
// tshark to dissect the result. It is skipped when the sample or tshark is
// unavailable, so the normal test suite stays self-contained.
func TestPcapngDissectsWithTshark(t *testing.T) {
	if testing.Short() {
		t.Skip("tshark integration test skipped in short mode")
	}
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Skipf("tshark not available: %v", err)
	}
	path := sampleCapturePath()
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

	type expected struct {
		channel byte
		seq     uint32
		length  int
		ntp     uint64
	}
	var want []expected

	outPath := filepath.Join(t.TempDir(), "zep-sample.pcapng")
	w, err := sink.NewPcapngFile(outPath)
	if err != nil {
		t.Fatalf("create pcapng: %v", err)
	}
	for _, packet := range packets {
		z, ok := zepFromEthernet(packet)
		if !ok || len(z) < zep.HeaderLen || z[2] != zep.Version || z[3] != zep.TypeData {
			continue
		}
		n := int(z[31] & 0x7f)
		if len(z) < zep.HeaderLen+n {
			t.Fatalf("truncated ZEP frame: have %d bytes, need %d", len(z), zep.HeaderLen+n)
		}
		if err := w.Write(z); err != nil {
			t.Fatalf("write pcapng: %v", err)
		}
		want = append(want, expected{
			channel: z[4],
			seq:     binary.BigEndian.Uint32(z[17:21]),
			length:  n,
			ntp:     binary.BigEndian.Uint64(z[9:17]),
		})
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close pcapng: %v", err)
	}
	if len(want) < 10 {
		t.Fatalf("sample contains only %d data frames", len(want))
	}

	cmd := exec.Command(tshark, "-r", outPath, "-Y", "zep.type==1", "-T", "fields",
		"-e", "frame.protocols", "-e", "zep.channel_id", "-e", "zep.seqno",
		"-e", "zep.length", "-e", "frame.time_epoch")
	out, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			t.Fatalf("tshark failed: %v: %s", err, exit.Stderr)
		}
		t.Fatalf("tshark failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != len(want) {
		t.Fatalf("tshark decoded %d packets, want %d", len(lines), len(want))
	}

	sawNetworkLayer := false
	for i, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			t.Fatalf("packet %d: fields = %q", i, fields)
		}
		if !strings.HasPrefix(fields[0], "eth:ethertype:ip:udp:zep:wpan") {
			t.Errorf("packet %d: protocols = %q, want eth/ip/udp/zep/wpan prefix", i, fields[0])
		}
		if strings.Contains(fields[0], "zbee_nwk") {
			sawNetworkLayer = true
		}

		channel, err := strconv.Atoi(fields[1])
		if err != nil || channel != int(want[i].channel) {
			t.Errorf("packet %d: channel = %q, want %d", i, fields[1], want[i].channel)
		}
		seq, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || uint32(seq) != want[i].seq {
			t.Errorf("packet %d: sequence = %q, want %d", i, fields[2], want[i].seq)
		}
		length, err := strconv.Atoi(fields[3])
		if err != nil || length != want[i].length {
			t.Errorf("packet %d: length = %q, want %d", i, fields[3], want[i].length)
		}
		gotTime, err := strconv.ParseFloat(fields[4], 64)
		if err != nil {
			t.Errorf("packet %d: frame.time_epoch = %q: %v", i, fields[4], err)
			continue
		}
		wantTime := float64(zep.TimeFromNTP(want[i].ntp).UnixNano()) / 1e9
		// pcapng stores microseconds, so the dissected capture timestamp is
		// the ZEP timestamp rounded to the nearest microsecond.
		if math.Abs(gotTime-wantTime) > 1e-6 {
			t.Errorf("packet %d: capture time = %.9f, want %.9f", i, gotTime, wantTime)
		}
	}
	if !sawNetworkLayer {
		t.Error("tshark did not dissect any packet as ZigBee network layer")
	}
}
