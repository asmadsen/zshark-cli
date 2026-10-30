package sink_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"zshark/internal/sink"
	"zshark/internal/zep"
	"zshark/internal/zigbee"
)

const jsonlFrame = "6188012b1a000034120802000034121e2a2804030201dc8e95fffeac426a00aeb3b0a5f4788d9c9225d771bbdc"

var jsonlKey = [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

type jsonlLine struct {
	Time       string             `json:"ts"`
	Channel    uint8              `json:"channel"`
	Seq        uint32             `json:"seq"`
	Length     int                `json:"len"`
	Radio      *jsonlRadio        `json:"radio"`
	Data       string             `json:"data"`
	MAC        *zigbee.MAC        `json:"mac"`
	NWK        *zigbee.NWK        `json:"nwk"`
	Decryption *zigbee.Decryption `json:"decryption"`
}

type jsonlRadio struct {
	RSSI     int   `json:"rssi"`
	LQI      uint8 `json:"lqi"`
	FCSValid bool  `json:"fcsValid"`
}

func jsonlPacket(t *testing.T, frame []byte, channel byte, seq uint32) []byte {
	t.Helper()
	// ZEP LQI mode carries two trailing CC24xx metadata bytes: RSSI -98 and
	// an FCS-valid/LQI byte.
	payload := append(append([]byte(nil), frame...), 0x9e, 0x80)
	return zep.Build(payload, channel, time.Unix(1700000000, 123456000), seq)
}

func TestJSONLDecryptsAndStripsMetadata(t *testing.T) {
	frame := mustHex(t, jsonlFrame)
	var out bytes.Buffer
	j := sink.NewJSONL(&out, [][16]byte{jsonlKey}, zigbee.SecEncMIC32)
	if err := j.Write(jsonlPacket(t, frame, 11, 42)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines = %d, want 1\n%s", len(lines), out.String())
	}
	var rec jsonlLine
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, lines[0])
	}
	if rec.Time != "2023-11-14T22:13:20.123455999Z" {
		t.Errorf("ts = %q", rec.Time)
	}
	if rec.Channel != 11 || rec.Seq != 42 {
		t.Errorf("channel/seq = %d/%d", rec.Channel, rec.Seq)
	}
	if rec.Length != len(frame) || rec.Data != hex.EncodeToString(frame) {
		t.Errorf("len/data = %d/%q", rec.Length, rec.Data)
	}
	if rec.Radio == nil || rec.Radio.RSSI != -98 || rec.Radio.LQI != 0 || !rec.Radio.FCSValid {
		t.Errorf("radio = %+v", rec.Radio)
	}
	if rec.MAC == nil || rec.MAC.Src != "0x1234" || rec.NWK == nil || rec.NWK.Security == nil {
		t.Errorf("decoded headers = %+v / %+v", rec.MAC, rec.NWK)
	}
	if rec.Decryption == nil || rec.Decryption.Status != zigbee.DecryptOK ||
		rec.Decryption.Payload != "00112233445566778899" {
		t.Errorf("decryption = %+v", rec.Decryption)
	}
	if strings.Contains(lines[0], `"zep"`) || strings.Contains(lines[0], `"ether"`) {
		t.Errorf("line contains capture plumbing: %s", lines[0])
	}
}

func TestJSONLWithoutKeys(t *testing.T) {
	frame := mustHex(t, jsonlFrame)
	var out bytes.Buffer
	j := sink.NewJSONL(&out, nil, zigbee.SecEncMIC32)
	if err := j.Write(jsonlPacket(t, frame, 11, 1)); err != nil {
		t.Fatal(err)
	}
	var rec jsonlLine
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Decryption == nil || rec.Decryption.Status != zigbee.DecryptNoKey {
		t.Errorf("decryption = %+v", rec.Decryption)
	}
	if rec.NWK == nil || rec.NWK.Security == nil || rec.NWK.Security.MIC != "d771bbdc" {
		t.Errorf("security = %+v", rec.NWK)
	}
}

func TestJSONLWritesOneLinePerFrame(t *testing.T) {
	frame := mustHex(t, jsonlFrame)
	var out bytes.Buffer
	j := sink.NewJSONL(&out, nil, zigbee.SecEncMIC32)
	for i := 0; i < 3; i++ {
		if err := j.Write(jsonlPacket(t, frame, 11, uint32(i))); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	for i, line := range lines {
		var rec jsonlLine
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if rec.Seq != uint32(i) {
			t.Errorf("line %d sequence = %d", i, rec.Seq)
		}
	}
}

func TestJSONLRejectsShortPacket(t *testing.T) {
	j := sink.NewJSONL(&bytes.Buffer{}, nil, 5)
	if err := j.Write([]byte{1, 2, 3}); err == nil {
		t.Fatal("short ZEP packet accepted")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}
