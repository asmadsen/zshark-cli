package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"zshark/internal/serialport"
)

const (
	exitOK       = 0
	exitRuntime  = 1
	exitUsage    = 2
	exitDevice   = 3
	exitFirmware = 4
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "list":
		jsonOut, err := parseListArgs(args[1:], stderr)
		if err != nil {
			return flagError(stderr, err)
		}
		return runList(jsonOut, stdout, stderr)
	case "capture":
		cfg, err := parseCaptureArgs(args[1:], stderr)
		if err != nil {
			return flagError(stderr, err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runCapture(ctx, cfg, stdout, stderr)
	case "keys":
		cfg, err := parseKeysArgs(args[1:], stderr)
		if err != nil {
			return flagError(stderr, err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runKeys(ctx, cfg, stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "zshark: unknown command %q\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func flagError(stderr io.Writer, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	fmt.Fprintf(stderr, "zshark: %v\n", err)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: zshark <command> [options]

commands:
  list [--json]
      List candidate serial ports. ConBee II (1cf1:0030) is preferred.

  capture [--port PATH] [--channel N] [--dest IP:PORT]
          [--pcap FILE] [--jsonl FILE] [--network-key HEX]
          [--security-level N] [--no-zep] [--verbose]
      Capture 802.15.4 frames and emit ZEP v2. Defaults:
        --channel 11
        --dest    127.0.0.1:17754
      --pcap additionally writes a pcapng file.
      --jsonl additionally writes one JSON object per ZigBee frame
              (use - for stdout); --network-key decrypts secured
              payloads.
      --no-zep disables UDP output and requires --pcap or --jsonl.

  keys [--port PATH] [--channel N] [--json] [--all] [--verbose]
      Listen for ZigBee APS Transport-Key commands that carry a network key
      in clear and print each discovered key. Set --channel to the network's
      channel. --json prints one JSON object per line. Repeats of the same key
      are suppressed unless --all is given.

exit codes:
  0 success
  1 runtime, file, or socket error
  2 usage error
  3 serial device unavailable
  4 dongle firmware/banner failure`)
}

func runList(jsonOut bool, stdout, stderr io.Writer) int {
	devices, err := serialport.Enumerate()
	if err != nil {
		fmt.Fprintf(stderr, "zshark: list serial ports: %v\n", err)
		return exitRuntime
	}
	if jsonOut {
		if devices == nil {
			devices = []serialport.Device{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(devices); err != nil {
			fmt.Fprintf(stderr, "zshark: write JSON: %v\n", err)
			return exitRuntime
		}
		return exitOK
	}
	if len(devices) == 0 {
		fmt.Fprintln(stderr, "zshark: no serial ports found")
		return exitOK
	}
	for _, d := range devices {
		fmt.Fprintln(stdout, d.String())
	}
	return exitOK
}
