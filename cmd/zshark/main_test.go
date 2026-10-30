package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

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
