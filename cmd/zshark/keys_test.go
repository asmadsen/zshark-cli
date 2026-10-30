package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"strings"
	"testing"
	"time"

	"zshark/internal/zigbee"
)

func testNetworkKey() zigbee.NetworkKey {
	key := zigbee.NetworkKey{
		KeyType:      zigbee.KeyTypeStandardNetwork,
		Sequence:     7,
		PAN:          0x1a2b,
		HasDestShort: true,
		HasSrcShort:  true,
	}
	copy(key.Key[:], "ZigBeeAlliance09")
	copy(key.Destination[:], []byte{0x00, 0x12, 0x4b, 0x00, 0x1a, 0x2b, 0x3c, 0x4d})
	copy(key.Source[:], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11})
	key.HasSource = true
	key.DestinationShort = 0x1234
	key.SourceShort = 0x0000
	return key
}

func TestParseKeysDefaults(t *testing.T) {
	cfg, err := parseKeysArgs(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Channel != 11 || cfg.Port != "" || cfg.JSON || cfg.All || cfg.Verbose {
		t.Errorf("unexpected default: %+v", cfg)
	}
}

func TestParseKeysAllFlags(t *testing.T) {
	cfg, err := parseKeysArgs([]string{
		"--port", "/dev/ttyACM0",
		"--channel", "26",
		"--json",
		"--all",
		"--verbose",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "/dev/ttyACM0" || cfg.Channel != 26 || !cfg.JSON || !cfg.All || !cfg.Verbose {
		t.Errorf("config = %+v", cfg)
	}
}

func TestParseKeysChannelValidation(t *testing.T) {
	for _, ch := range []string{"10", "27", "0", "-1"} {
		if _, err := parseKeysArgs([]string{"--channel", ch}, &bytes.Buffer{}); err == nil {
			t.Errorf("channel %s accepted", ch)
		}
	}
	if _, err := parseKeysArgs([]string{"extra"}, &bytes.Buffer{}); err == nil {
		t.Fatal("extra positional argument accepted")
	}
}

func TestParseKeysHelp(t *testing.T) {
	if _, err := parseKeysArgs([]string{"--help"}, &bytes.Buffer{}); err != flag.ErrHelp {
		t.Fatalf("error = %v, want flag.ErrHelp", err)
	}
}

func TestKeyOutputPlain(t *testing.T) {
	var out bytes.Buffer
	stats := &keysStats{}
	o := &keyOutput{w: &out, seen: map[string]struct{}{}}
	ts := time.Date(2026, 10, 30, 16, 20, 0, 0, time.UTC)
	if err := o.write(ts, 15, testNetworkKey(), stats); err != nil {
		t.Fatal(err)
	}

	line := out.String()
	for _, want := range []string{
		"2026-10-30T16:20:00Z",
		"channel=15",
		"pan=0x1a2b",
		"dst=0x1234",
		"src=0x0000",
		"dst_ext=4d:3c:2b:1a:00:4b:12:00",
		"src_ext=11:00:ff:ee:dd:cc:bb:aa",
		"type=standard-network",
		"key_seq=7",
		"key=5a6967426565416c6c69616e63653039",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("output %q missing %q", line, want)
		}
	}
	if stats.Keys != 1 || stats.Unique != 1 || stats.Duplicates != 0 {
		t.Errorf("stats = %+v", stats)
	}
}

func TestKeyOutputSuppressesRepeats(t *testing.T) {
	var out bytes.Buffer
	stats := &keysStats{}
	o := &keyOutput{w: &out, seen: map[string]struct{}{}}
	ts := time.Date(2026, 10, 30, 16, 20, 0, 0, time.UTC)
	key := testNetworkKey()

	if err := o.write(ts, 15, key, stats); err != nil {
		t.Fatal(err)
	}
	first := out.Len()
	if err := o.write(ts.Add(time.Second), 15, key, stats); err != nil {
		t.Fatal(err)
	}
	if out.Len() != first {
		t.Errorf("repeat printed %d extra bytes", out.Len()-first)
	}
	if stats.Keys != 2 || stats.Unique != 1 || stats.Duplicates != 1 {
		t.Errorf("stats = %+v", stats)
	}
}

func TestKeyOutputAllPrintsRepeats(t *testing.T) {
	var out bytes.Buffer
	stats := &keysStats{}
	o := &keyOutput{w: &out, all: true, seen: map[string]struct{}{}}
	ts := time.Date(2026, 10, 30, 16, 20, 0, 0, time.UTC)
	key := testNetworkKey()

	if err := o.write(ts, 15, key, stats); err != nil {
		t.Fatal(err)
	}
	if err := o.write(ts.Add(time.Second), 15, key, stats); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), "\n"); got != 2 {
		t.Errorf("lines = %d, want 2\n%s", got, out.String())
	}
	if stats.Duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", stats.Duplicates)
	}
}

func TestKeyOutputJSON(t *testing.T) {
	var out bytes.Buffer
	stats := &keysStats{}
	o := &keyOutput{w: &out, json: true, seen: map[string]struct{}{}}
	ts := time.Date(2026, 10, 30, 16, 20, 0, 0, time.UTC)
	if err := o.write(ts, 15, testNetworkKey(), stats); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), "\n"); got != 1 {
		t.Fatalf("lines = %d, want 1\n%s", got, out.String())
	}

	var rec keyRecord
	if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if rec.Channel != 15 || rec.Key != "5a6967426565416c6c69616e63653039" ||
		rec.KeyType != "standard-network" || rec.PAN != "0x1a2b" ||
		rec.Destination != "4d:3c:2b:1a:00:4b:12:00" || rec.KeySequence != 7 {
		t.Errorf("record = %+v", rec)
	}
	if rec.Time.UTC() != ts {
		t.Errorf("time = %v, want %v", rec.Time, ts)
	}
}

func TestKeyOutputDistinguishesDestinations(t *testing.T) {
	var out bytes.Buffer
	stats := &keysStats{}
	o := &keyOutput{w: &out, seen: map[string]struct{}{}}
	ts := time.Date(2026, 10, 30, 16, 20, 0, 0, time.UTC)
	key := testNetworkKey()
	other := testNetworkKey()
	other.Destination[0] = 0xff

	if err := o.write(ts, 15, key, stats); err != nil {
		t.Fatal(err)
	}
	if err := o.write(ts, 15, other, stats); err != nil {
		t.Fatal(err)
	}
	if stats.Unique != 2 || stats.Duplicates != 0 {
		t.Errorf("stats = %+v", stats)
	}
	if got := strings.Count(out.String(), "\n"); got != 2 {
		t.Errorf("lines = %d, want 2", got)
	}
}

func TestRunKeysUsageError(t *testing.T) {
	if code := run([]string{"keys", "--channel", "10"}, &bytes.Buffer{}, &bytes.Buffer{}); code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
}

func TestRunHelpMentionsKeys(t *testing.T) {
	var stdout bytes.Buffer
	if code := run([]string{"help"}, &stdout, &bytes.Buffer{}); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "keys [--port") {
		t.Errorf("help does not mention keys:\n%s", stdout.String())
	}
}
