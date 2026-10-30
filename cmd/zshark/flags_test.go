package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestCaptureDefaults(t *testing.T) {
	cfg, err := parseCaptureArgs(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Channel != 11 {
		t.Errorf("channel = %d, want 11", cfg.Channel)
	}
	if cfg.Dest != "127.0.0.1:17754" {
		t.Errorf("dest = %q", cfg.Dest)
	}
	if cfg.Port != "" || cfg.Pcap != "" || cfg.NoZEP || cfg.Verbose {
		t.Errorf("unexpected default: %+v", cfg)
	}
}

func TestCaptureAllFlags(t *testing.T) {
	cfg, err := parseCaptureArgs([]string{
		"--port", "/dev/ttyACM0",
		"--channel", "26",
		"--dest", "192.0.2.10:17754",
		"--pcap", "out.pcapng",
		"--no-zep",
		"--verbose",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "/dev/ttyACM0" || cfg.Channel != 26 || cfg.Dest != "192.0.2.10:17754" ||
		cfg.Pcap != "out.pcapng" || !cfg.NoZEP || !cfg.Verbose {
		t.Errorf("config = %+v", cfg)
	}
}

func TestCaptureChannelValidation(t *testing.T) {
	for _, ch := range []string{"10", "27", "0", "-1"} {
		if _, err := parseCaptureArgs([]string{"--channel", ch}, &bytes.Buffer{}); err == nil {
			t.Errorf("channel %s accepted", ch)
		}
	}
}

func TestCaptureDestValidation(t *testing.T) {
	for _, dest := range []string{"127.0.0.1", ":17754", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:abc"} {
		if _, err := parseCaptureArgs([]string{"--dest", dest}, &bytes.Buffer{}); err == nil {
			t.Errorf("dest %q accepted", dest)
		}
	}
}

func TestCaptureNoZEPRequiresPcap(t *testing.T) {
	_, err := parseCaptureArgs([]string{"--no-zep"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--pcap") {
		t.Fatalf("error = %v, want --pcap requirement", err)
	}
	if _, err := parseCaptureArgs([]string{"--no-zep", "--pcap", "x.pcapng"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("valid combination rejected: %v", err)
	}
}

func TestCaptureRejectsExtraArguments(t *testing.T) {
	if _, err := parseCaptureArgs([]string{"extra"}, &bytes.Buffer{}); err == nil {
		t.Fatal("extra positional argument accepted")
	}
}

func TestListFlags(t *testing.T) {
	jsonOut, err := parseListArgs([]string{"--json"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonOut {
		t.Error("--json not parsed")
	}
	if _, err := parseListArgs([]string{"extra"}, &bytes.Buffer{}); err == nil {
		t.Fatal("extra positional argument accepted")
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	_, err := parseCaptureArgs([]string{"--help"}, &bytes.Buffer{})
	if !errorsIsHelp(err) {
		t.Fatalf("error = %v, want flag.ErrHelp", err)
	}
}

func errorsIsHelp(err error) bool {
	return err == flag.ErrHelp
}
