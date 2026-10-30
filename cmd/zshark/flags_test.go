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
	if cfg.Port != "" || cfg.Pcap != "" || cfg.JSONL != "" || len(cfg.NetworkKeys) != 0 ||
		cfg.SecurityLevel != 5 || cfg.NoZEP || cfg.Verbose {
		t.Errorf("unexpected default: %+v", cfg)
	}
}

func TestCaptureAllFlags(t *testing.T) {
	cfg, err := parseCaptureArgs([]string{
		"--port", "/dev/ttyACM0",
		"--channel", "26",
		"--dest", "192.0.2.10:17754",
		"--pcap", "out.pcapng",
		"--jsonl", "out.jsonl",
		"--network-key", "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
		"--security-level", "6",
		"--no-zep",
		"--verbose",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "/dev/ttyACM0" || cfg.Channel != 26 || cfg.Dest != "192.0.2.10:17754" ||
		cfg.Pcap != "out.pcapng" || cfg.JSONL != "out.jsonl" || !cfg.NoZEP || !cfg.Verbose {
		t.Errorf("config = %+v", cfg)
	}
	if len(cfg.NetworkKeys) != 1 || cfg.NetworkKeys[0][0] != 0x00 || cfg.NetworkKeys[0][15] != 0xff {
		t.Errorf("network keys = %x", cfg.NetworkKeys)
	}
	if cfg.SecurityLevel != 6 {
		t.Errorf("security level = %d, want 6", cfg.SecurityLevel)
	}
}

func TestCaptureChannelValidation(t *testing.T) {
	for _, ch := range []string{"10", "27", "0", "-1"} {
		if _, err := parseCaptureArgs([]string{"--channel", ch}, &bytes.Buffer{}); err == nil {
			t.Errorf("channel %s accepted", ch)
		}
	}
}

func TestCaptureChannelBoundsAccepted(t *testing.T) {
	for channel, want := range map[string]int{"11": 11, "26": 26} {
		cfg, err := parseCaptureArgs([]string{"--channel", channel}, &bytes.Buffer{})
		if err != nil {
			t.Errorf("channel %s rejected: %v", channel, err)
			continue
		}
		if cfg.Channel != want {
			t.Errorf("channel = %d, want %d", cfg.Channel, want)
		}
	}
}

func TestCaptureIPv6Destination(t *testing.T) {
	cfg, err := parseCaptureArgs([]string{"--dest", "[::1]:17754"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("IPv6 destination rejected: %v", err)
	}
	if cfg.Dest != "[::1]:17754" {
		t.Errorf("dest = %q", cfg.Dest)
	}
}

func TestCaptureDestValidation(t *testing.T) {
	for _, dest := range []string{"127.0.0.1", ":17754", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:abc"} {
		if _, err := parseCaptureArgs([]string{"--dest", dest}, &bytes.Buffer{}); err == nil {
			t.Errorf("dest %q accepted", dest)
		}
	}
}

func TestCaptureNoZEPRequiresOutput(t *testing.T) {
	_, err := parseCaptureArgs([]string{"--no-zep"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--pcap or --jsonl") {
		t.Fatalf("error = %v, want --pcap/--jsonl requirement", err)
	}
	for _, args := range [][]string{
		{"--no-zep", "--pcap", "x.pcapng"},
		{"--no-zep", "--jsonl", "x.jsonl"},
	} {
		if _, err := parseCaptureArgs(args, &bytes.Buffer{}); err != nil {
			t.Fatalf("valid combination rejected: %v", err)
		}
	}
}

func TestCaptureNetworkKeyValidation(t *testing.T) {
	valid := []string{
		"00112233445566778899aabbccddeeff",
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
		"0011-2233-4455-6677-8899-aabb-ccdd-eeff",
		"0x00112233445566778899aabbccddeeff",
	}
	for _, key := range valid {
		if _, err := parseCaptureArgs([]string{"--jsonl", "-", "--network-key", key}, &bytes.Buffer{}); err != nil {
			t.Errorf("key %q rejected: %v", key, err)
		}
	}
	for _, key := range []string{"", "0011", "00112233445566778899aabbccddee", "00112233445566778899aabbccddeefg"} {
		if _, err := parseCaptureArgs([]string{"--jsonl", "-", "--network-key", key}, &bytes.Buffer{}); err == nil {
			t.Errorf("key %q accepted", key)
		}
	}
	if _, err := parseCaptureArgs([]string{"--network-key", valid[0]}, &bytes.Buffer{}); err == nil {
		t.Error("network key accepted without --jsonl")
	}
}

func TestCaptureSecurityLevelValidation(t *testing.T) {
	for _, level := range []string{"0", "7"} {
		if _, err := parseCaptureArgs([]string{"--security-level", level}, &bytes.Buffer{}); err != nil {
			t.Errorf("level %s rejected: %v", level, err)
		}
	}
	for _, level := range []string{"-1", "8"} {
		if _, err := parseCaptureArgs([]string{"--security-level", level}, &bytes.Buffer{}); err == nil {
			t.Errorf("level %s accepted", level)
		}
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
	if _, err := parseListArgs([]string{"--help"}, &bytes.Buffer{}); !errorsIsHelp(err) {
		t.Fatalf("list error = %v, want flag.ErrHelp", err)
	}
}

func errorsIsHelp(err error) bool {
	return err == flag.ErrHelp
}
