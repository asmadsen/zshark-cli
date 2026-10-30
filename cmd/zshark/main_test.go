package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"go.bug.st/serial"

	"zshark/internal/proto"
	"zshark/internal/serialport"
)

func TestRunNoArguments(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(nil, &bytes.Buffer{}, &stderr); code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "usage: zshark") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunListJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"list", "--json"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	var devices []serialport.Device
	if err := json.Unmarshal(stdout.Bytes(), &devices); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout.String())
	}
	if devices == nil {
		t.Error("JSON output is null, want an array")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"nope"}, &bytes.Buffer{}, &stderr); code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stdout bytes.Buffer
	if code := run([]string{"help"}, &stdout, &bytes.Buffer{}); code != exitOK {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "usage: zshark") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRunCaptureUsageError(t *testing.T) {
	for _, args := range [][]string{
		{"capture", "--channel", "10"},
		{"capture", "--dest", "bad"},
		{"capture", "--no-zep"},
	} {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}); code != exitUsage {
			t.Errorf("%v: exit = %d, want %d", args, code, exitUsage)
		}
	}
}

func TestRunCaptureHelp(t *testing.T) {
	if code := run([]string{"capture", "--help"}, &bytes.Buffer{}, &bytes.Buffer{}); code != exitOK {
		t.Errorf("exit = %d, want 0", code)
	}
}

// scriptedPort serves a fixed byte stream through Read. waitBanner only uses
// Read, so the embedded interface's other methods are never called.
type scriptedPort struct {
	serial.Port
	data []byte
}

func (p *scriptedPort) Read(b []byte) (int, error) {
	if len(p.data) == 0 {
		return 0, nil
	}
	n := copy(b, p.data)
	p.data = p.data[n:]
	return n, nil
}

func TestWaitBannerConBeeII(t *testing.T) {
	// Exact parms response from a stock ConBee II (DE2490137, firmware 2.0).
	port := &scriptedPort{data: []byte("> parms\r\n\r\nPLATFORM: ConBee2 V2.0\r\nCURR_CMSK: 0x07fff800\r\nCURR_CHAN: 11\r\n\r\nOK")}
	var logs bytes.Buffer
	log := &captureLogger{w: &logs, verbose: true}
	if err := waitBanner(context.Background(), port, proto.NewParser(), log, &captureStats{}); err != nil {
		t.Fatalf("waitBanner = %v, want nil\nlogs: %s", err, logs.String())
	}
	if !strings.Contains(logs.String(), "PLATFORM: ConBee2 V2.0") {
		t.Errorf("verbose log missing banner line:\n%s", logs.String())
	}
}

func TestWaitBannerFirmwareFailure(t *testing.T) {
	port := &scriptedPort{data: []byte("> parms\r\nfail\r\n")}
	log := &captureLogger{w: &bytes.Buffer{}, verbose: true}
	err := waitBanner(context.Background(), port, proto.NewParser(), log, &captureStats{})
	if !errors.Is(err, errFirmware) {
		t.Errorf("waitBanner = %v, want %v", err, errFirmware)
	}
}

func TestIsSnifferBanner(t *testing.T) {
	for _, line := range []string{
		"Sniffer V1.0 [ConBee II]",
		"PLATFORM: ConBee2 V2.0",
	} {
		if !isSnifferBanner(line) {
			t.Errorf("isSnifferBanner(%q) = false, want true", line)
		}
	}
	for _, line := range []string{
		"> parms",
		"OK",
		"CURR_CHAN: 11",
		"Receiving...OK",
	} {
		if isSnifferBanner(line) {
			t.Errorf("isSnifferBanner(%q) = true, want false", line)
		}
	}
}
