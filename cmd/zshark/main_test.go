package main

import (
	"bytes"
	"strings"
	"testing"
)

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
