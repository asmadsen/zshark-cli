package main

// This file holds the serial device runtime shared by the capture and keys
// commands: logging and counters, port discovery, the sniff handshake, the
// reconnect loop, and the frame read loop. Capture-specific sink setup and
// fanout lives in capture.go.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"go.bug.st/serial"

	"zshark/internal/proto"
	"zshark/internal/serialport"
	"zshark/internal/zep"
)

const (
	bannerTimeout = 2 * time.Second
	statsInterval = 30 * time.Second
)

var (
	errNoBanner   = errors.New("no sniffer banner; wrong or missing firmware")
	errFirmware   = errors.New("dongle reported a failure; wrong or missing firmware")
	errSerialRead = errors.New("serial read failed")
)

type captureLogger struct {
	w       io.Writer
	verbose bool
}

func (l *captureLogger) printf(format string, args ...any) {
	fmt.Fprintf(l.w, "zshark: "+format+"\n", args...)
}

func (l *captureLogger) errorf(format string, args ...any) {
	l.printf("error: "+format, args...)
}

func (l *captureLogger) verbosef(format string, args ...any) {
	if l.verbose {
		l.printf(format, args...)
	}
}

type captureStats struct {
	Frames     uint64
	ZEP        uint64
	Pcap       uint64
	JSONL      uint64
	Dropped    uint64
	Errors     uint64
	Reconnects uint64
	Text       uint64
}

func (s *captureStats) line() string {
	return fmt.Sprintf("frames=%d zep=%d pcap=%d jsonl=%d dropped=%d errors=%d reconnects=%d text_lines=%d",
		s.Frames, s.ZEP, s.Pcap, s.JSONL, s.Dropped, s.Errors, s.Reconnects, s.Text)
}

type deviceConfig struct {
	Port    string
	Channel int
}

// frameHandler consumes one raw 802.15.4 frame (without the dongle envelope).
type frameHandler func([]byte) error

// runDevice finds and opens the sniffer, starts sniffing on the configured
// channel, and feeds every frame to handle. Serial failures reconnect with
// exponential backoff; a handler failure stops the session. The returned value
// is the process exit code.
func runDevice(ctx context.Context, cfg deviceConfig, log *captureLogger, stats *captureStats, handle frameHandler) int {
	device, err := serialport.Find(cfg.Port)
	if err != nil {
		log.errorf("%v", err)
		return exitDevice
	}
	path := device.Path
	log.verbosef("using serial port %s", path)

	backoff := time.Second
	everOpened := false

	for {
		if ctx.Err() != nil {
			break
		}

		// Re-enumerate on reconnect when the port was auto-detected: a
		// replugged CDC-ACM device can come back under a different node.
		if cfg.Port == "" {
			device, err := serialport.Find("")
			if err != nil {
				if !everOpened {
					log.errorf("%v", err)
					return exitDevice
				}
				stats.Errors++
				stats.Reconnects++
				log.errorf("%v; retrying in %s", err, backoff)
				if !sleepContext(ctx, backoff) {
					break
				}
				backoff = nextBackoff(backoff)
				continue
			}
			path = device.Path
		}

		port, err := serialport.Open(path)
		if err != nil {
			if !everOpened {
				log.errorf("%v", err)
				return exitDevice
			}
			stats.Errors++
			stats.Reconnects++
			log.errorf("%v; reconnecting in %s", err, backoff)
			if !sleepContext(ctx, backoff) {
				break
			}
			backoff = nextBackoff(backoff)
			continue
		}

		started := time.Now()
		parser := proto.NewParser()
		if err := startSniff(ctx, port, parser, cfg.Channel, log, stats); err != nil {
			log.verbosef("-> idle (startup failure)")
			_ = serialport.WriteCommand(port, proto.CmdIdle)
			_ = port.Close()
			if ctx.Err() != nil {
				break
			}
			if !everOpened {
				log.errorf("%v", err)
				if errors.Is(err, errNoBanner) || errors.Is(err, errFirmware) {
					return exitFirmware
				}
				return exitDevice
			}
			stats.Errors++
			stats.Reconnects++
			log.errorf("%v; reconnecting in %s", err, backoff)
			if !sleepContext(ctx, backoff) {
				break
			}
			backoff = nextBackoff(backoff)
			continue
		}
		everOpened = true
		log.verbosef("starting sniff on channel %d", cfg.Channel)

		readErr := readLoop(ctx, port, parser, stats, log, handle)
		log.verbosef("-> idle (shutdown)")
		_ = serialport.WriteCommand(port, proto.CmdIdle)
		_ = port.Close()

		if ctx.Err() != nil {
			break
		}
		if readErr == nil {
			break
		}
		if !errors.Is(readErr, errSerialRead) {
			log.errorf("%v", readErr)
			return exitRuntime
		}
		if errors.Is(readErr, errJSONL) {
			log.errorf("%v", readErr)
			log.printf("stats: %s", stats.line())
			return exitRuntime
		}
		stats.Errors++
		stats.Reconnects++
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		log.errorf("serial read: %v; reconnecting in %s", readErr, backoff)
		if !sleepContext(ctx, backoff) {
			break
		}
		backoff = nextBackoff(backoff)
	}

	return exitOK
}

func startSniff(ctx context.Context, port serial.Port, parser *proto.Parser, channel int, log *captureLogger, stats *captureStats) error {
	log.verbosef("-> idle")
	if err := serialport.WriteCommand(port, proto.CmdIdle); err != nil {
		return fmt.Errorf("send idle: %w", err)
	}
	log.verbosef("-> parms")
	if err := serialport.WriteCommand(port, proto.CmdParms); err != nil {
		return fmt.Errorf("send parms: %w", err)
	}
	if err := waitBanner(ctx, port, parser, log, stats); err != nil {
		return err
	}
	log.verbosef("-> chan %d", channel)
	if err := serialport.WriteCommand(port, proto.CmdChannel(channel)); err != nil {
		return fmt.Errorf("send channel: %w", err)
	}
	log.verbosef("-> sniff")
	if err := serialport.WriteCommand(port, proto.CmdSniff); err != nil {
		return fmt.Errorf("send sniff: %w", err)
	}
	return nil
}

func waitBanner(ctx context.Context, port serial.Port, parser *proto.Parser, log *captureLogger, stats *captureStats) error {
	deadline := time.Now().Add(bannerTimeout)
	buf := make([]byte, 1024)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !time.Now().Before(deadline) {
			for _, line := range parser.FlushText() {
				stats.Text++
				log.verbosef("dongle: %s", line)
				if isSnifferBanner(line) {
					return nil
				}
				if strings.Contains(strings.ToLower(line), "fail") {
					return errFirmware
				}
			}
			return errNoBanner
		}

		n, err := port.Read(buf)
		if err != nil {
			return fmt.Errorf("read banner: %w", err)
		}
		if n == 0 {
			continue
		}
		result := parser.Feed(buf[:n])
		for _, line := range result.Text {
			stats.Text++
			log.verbosef("dongle: %s", line)
			if isSnifferBanner(line) {
				return nil
			}
			if strings.Contains(strings.ToLower(line), "fail") {
				return errFirmware
			}
		}
		for _, parseErr := range result.Errors {
			stats.Errors++
			log.verbosef("framing: %v", parseErr)
		}
		// Frames received during the banner exchange are pre-sniff traffic and
		// are intentionally ignored.
	}
}

// isSnifferBanner reports whether a dongle status line confirms a usable
// sniffer. The dedicated sniffer firmware sends a "Sniffer V..." banner; the
// stock ConBee II (deCONZ) firmware answers `parms` with a block starting
// "PLATFORM: ConBee2 ..." instead.
func isSnifferBanner(line string) bool {
	return strings.Contains(line, "Sniffer") || strings.Contains(line, "PLATFORM:")
}

func readLoop(ctx context.Context, port serial.Port, parser *proto.Parser, stats *captureStats, log *captureLogger, handle frameHandler) error {
	buf := make([]byte, 4096)
	lastStats := time.Now()
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := port.Read(buf)
		if err != nil {
			return fmt.Errorf("%w: %w", errSerialRead, err)
		}
		if n == 0 {
			if log.verbose && time.Since(lastStats) >= statsInterval {
				log.printf("stats: %s", stats.line())
				lastStats = time.Now()
			}
			continue
		}

		result := parser.Feed(buf[:n])
		for _, line := range result.Text {
			stats.Text++
			log.verbosef("dongle: %s", line)
			if strings.Contains(strings.ToLower(line), "fail") {
				stats.Errors++
				log.printf("dongle reported: %s", line)
			}
		}
		for _, parseErr := range result.Errors {
			stats.Errors++
			log.verbosef("framing: %v", parseErr)
		}

		for _, frame := range result.Frames {
			stats.Frames++
			data := frame.Data()
			if len(data) == 0 || len(data) > zep.MaxFrameLen {
				stats.Errors++
				log.verbosef("skipping frame with %d data bytes", len(data))
				continue
			}
			if err := handle(data); err != nil {
				return err
			}
		}

		if log.verbose && time.Since(lastStats) >= statsInterval {
			log.printf("stats: %s", stats.line())
			lastStats = time.Now()
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}
