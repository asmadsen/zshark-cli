package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	defaultChannel = 11
	defaultDest    = "127.0.0.1:17754"
)

type captureConfig struct {
	Port    string
	Channel int
	Dest    string
	Pcap    string
	NoZEP   bool
	Verbose bool
}

type keysConfig struct {
	Port    string
	Channel int
	JSON    bool
	All     bool
	Verbose bool
}

func defaultCaptureConfig() captureConfig {
	return captureConfig{
		Channel: defaultChannel,
		Dest:    defaultDest,
	}
}

func defaultKeysConfig() keysConfig {
	return keysConfig{Channel: defaultChannel}
}

func parseCaptureArgs(args []string, stderr io.Writer) (captureConfig, error) {
	cfg := defaultCaptureConfig()
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Port, "port", "", "serial port path (auto-detected when omitted)")
	fs.IntVar(&cfg.Channel, "channel", defaultChannel, "ZigBee channel (11-26)")
	fs.StringVar(&cfg.Dest, "dest", defaultDest, "ZEP UDP destination IP:PORT")
	fs.StringVar(&cfg.Pcap, "pcap", "", "write a pcapng capture to FILE")
	fs.BoolVar(&cfg.NoZEP, "no-zep", false, "disable ZEP UDP output (requires --pcap)")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "verbose logging to stderr")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: zshark capture [--port PATH] [--channel N] [--dest IP:PORT] [--pcap FILE] [--no-zep] [--verbose]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected argument(s): %s", strings.Join(fs.Args(), " "))
	}
	if cfg.Channel < 11 || cfg.Channel > 26 {
		return cfg, fmt.Errorf("--channel must be between 11 and 26 (got %d)", cfg.Channel)
	}
	if err := validateDest(cfg.Dest); err != nil {
		return cfg, err
	}
	if cfg.NoZEP && cfg.Pcap == "" {
		return cfg, fmt.Errorf("--no-zep requires --pcap")
	}
	return cfg, nil
}

func parseKeysArgs(args []string, stderr io.Writer) (keysConfig, error) {
	cfg := defaultKeysConfig()
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Port, "port", "", "serial port path (auto-detected when omitted)")
	fs.IntVar(&cfg.Channel, "channel", defaultChannel, "ZigBee channel (11-26)")
	fs.BoolVar(&cfg.JSON, "json", false, "print one JSON object per key")
	fs.BoolVar(&cfg.All, "all", false, "print repeated transports of the same key")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "verbose logging to stderr")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: zshark keys [--port PATH] [--channel N] [--json] [--all] [--verbose]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected argument(s): %s", strings.Join(fs.Args(), " "))
	}
	if cfg.Channel < 11 || cfg.Channel > 26 {
		return cfg, fmt.Errorf("--channel must be between 11 and 26 (got %d)", cfg.Channel)
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
