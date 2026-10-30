package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"zshark/internal/zigbee"
)

const (
	defaultChannel       = 11
	defaultDest          = "127.0.0.1:17754"
	defaultSecurityLevel = 5 // AES-128 encryption with a 32-bit MIC
)

type captureConfig struct {
	Port          string
	Channel       int
	Dest          string
	Pcap          string
	JSONL         string
	NetworkKeys   [][16]byte
	SecurityLevel int
	NoZEP         bool
	Verbose       bool
}

func defaultCaptureConfig() captureConfig {
	return captureConfig{
		Channel:       defaultChannel,
		Dest:          defaultDest,
		SecurityLevel: defaultSecurityLevel,
	}
}

// networkKeys collects repeatable --network-key flags.
type networkKeys [][16]byte

func (k *networkKeys) String() string {
	return fmt.Sprintf("%d key(s)", len(*k))
}

func (k *networkKeys) Set(value string) error {
	key, err := zigbee.ParseKey(value)
	if err != nil {
		return err
	}
	*k = append(*k, key)
	return nil
}

func parseCaptureArgs(args []string, stderr io.Writer) (captureConfig, error) {
	cfg := defaultCaptureConfig()
	var keys networkKeys
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Port, "port", "", "serial port path (auto-detected when omitted)")
	fs.IntVar(&cfg.Channel, "channel", defaultChannel, "ZigBee channel (11-26)")
	fs.StringVar(&cfg.Dest, "dest", defaultDest, "ZEP UDP destination IP:PORT")
	fs.StringVar(&cfg.Pcap, "pcap", "", "write a pcapng capture to FILE")
	fs.StringVar(&cfg.JSONL, "jsonl", "", "write one JSON object per ZigBee frame to FILE (- for stdout)")
	fs.Var(&keys, "network-key", "ZigBee network key (16 bytes hex; repeatable)")
	fs.IntVar(&cfg.SecurityLevel, "security-level", defaultSecurityLevel, "ZigBee security level used for decryption (0-7)")
	fs.BoolVar(&cfg.NoZEP, "no-zep", false, "disable ZEP UDP output (requires --pcap or --jsonl)")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "verbose logging to stderr")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: zshark capture [--port PATH] [--channel N] [--dest IP:PORT] [--pcap FILE] [--jsonl FILE] [--network-key HEX] [--security-level N] [--no-zep] [--verbose]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	cfg.NetworkKeys = keys
	if fs.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected argument(s): %s", strings.Join(fs.Args(), " "))
	}
	if cfg.Channel < 11 || cfg.Channel > 26 {
		return cfg, fmt.Errorf("--channel must be between 11 and 26 (got %d)", cfg.Channel)
	}
	if cfg.SecurityLevel < 0 || cfg.SecurityLevel > 7 {
		return cfg, fmt.Errorf("--security-level must be between 0 and 7 (got %d)", cfg.SecurityLevel)
	}
	if err := validateDest(cfg.Dest); err != nil {
		return cfg, err
	}
	if cfg.NoZEP && cfg.Pcap == "" && cfg.JSONL == "" {
		return cfg, fmt.Errorf("--no-zep requires --pcap or --jsonl")
	}
	if len(cfg.NetworkKeys) > 0 && cfg.JSONL == "" {
		return cfg, fmt.Errorf("--network-key requires --jsonl")
	}
	return cfg, nil
}

func parseListArgs(args []string, stderr io.Writer) (bool, error) {
	var jsonOut bool
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&jsonOut, "json", false, "print machine-readable JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: zshark list [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	if fs.NArg() != 0 {
		return false, fmt.Errorf("unexpected argument(s): %s", strings.Join(fs.Args(), " "))
	}
	return jsonOut, nil
}

func validateDest(dest string) error {
	host, portText, err := net.SplitHostPort(dest)
	if err != nil {
		return fmt.Errorf("--dest %q must be IP:PORT", dest)
	}
	if host == "" {
		return fmt.Errorf("--dest %q has an empty host", dest)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("--dest %q has an invalid port", dest)
	}
	return nil
}
