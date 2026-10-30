package main

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
	"zshark/internal/sink"
	"zshark/internal/zep"
)

const (
	bannerTimeout = 2 * time.Second
	statsInterval = 30 * time.Second
)

var (
	errNoBanner = errors.New("no sniffer banner; wrong or missing firmware")
	errFirmware = errors.New("dongle reported a failure; wrong or missing firmware")
	errPcap     = errors.New("pcap write failed")
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
	Errors     uint64
	Reconnects uint64
	Text       uint64
}

func (s *captureStats) line() string {
	return fmt.Sprintf("frames=%d zep=%d pcap=%d errors=%d reconnects=%d text_lines=%d",
		s.Frames, s.ZEP, s.Pcap, s.Errors, s.Reconnects, s.Text)
}

func runCapture(ctx context.Context, cfg captureConfig, stderr io.Writer) (code int) {
	log := &captureLogger{w: stderr, verbose: cfg.Verbose}
	stats := &captureStats{}

	var pcapSink *sink.Pcapng
	if cfg.Pcap != "" {
		p, err := sink.NewPcapngFile(cfg.Pcap)
		if err != nil {
			log.errorf("create %s: %v", cfg.Pcap, err)
			return exitRuntime
		}
		pcapSink = p
		defer func() {
			if err := pcapSink.Close(); err != nil {
				log.errorf("close %s: %v", cfg.Pcap, err)
				if code == exitOK {
					code = exitRuntime
				}
			}
		}()
		log.verbosef("writing pcapng to %s", cfg.Pcap)
	}

	var udpSink *sink.UDP
	if !cfg.NoZEP {
		u, err := sink.NewUDP(cfg.Dest)
		if err != nil {
			log.errorf("ZEP destination: %v", err)
			return exitRuntime
		}
		udpSink = u
		defer func() { _ = udpSink.Close() }()
		log.verbosef("sending ZEP to %s", cfg.Dest)
	}

	device, err := serialport.Find(cfg.Port)
	if err != nil {
		log.errorf("%v", err)
		return exitDevice
	}
	path := device.Path
	log.verbosef("using serial port %s", path)

	seq := uint32(0)
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

		readErr := readLoop(ctx, port, parser, &seq, pcapSink, udpSink, stats, log)
		_ = serialport.WriteCommand(port, proto.CmdIdle)
		_ = port.Close()

		if ctx.Err() != nil {
			break
		}
		if readErr == nil {
			break
		}
		if errors.Is(readErr, errPcap) {
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

	log.printf("stats: %s", stats.line())
	return exitOK
}

func startSniff(ctx context.Context, port serial.Port, parser *proto.Parser, channel int, log *captureLogger, stats *captureStats) error {
	if err := serialport.WriteCommand(port, proto.CmdIdle); err != nil {
		return fmt.Errorf("send idle: %w", err)
	}
	if err := serialport.WriteCommand(port, proto.CmdParms); err != nil {
		return fmt.Errorf("send parms: %w", err)
	}
	if err := waitBanner(ctx, port, parser, log, stats); err != nil {
		return err
	}
	if err := serialport.WriteCommand(port, proto.CmdChannel(channel)); err != nil {
		return fmt.Errorf("send channel: %w", err)
	}
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
				if strings.Contains(line, "Sniffer") {
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
			if strings.Contains(line, "Sniffer") {
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

func readLoop(ctx context.Context, port serial.Port, parser *proto.Parser, seq *uint32, pcapSink *sink.Pcapng, udpSink *sink.UDP, stats *captureStats, log *captureLogger) error {
	buf := make([]byte, 4096)
	lastStats := time.Now()
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := port.Read(buf)
		if err != nil {
			return err
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
			channel := frame.Channel()
			packet := zep.BuildNTP(data, channel, zep.NTPTime(time.Now()), *seq)
			thisSeq := *seq
			(*seq)++
			log.verbosef("frame channel=%d len=%d seq=%d", channel, len(data), thisSeq)

			if pcapSink != nil {
				if err := pcapSink.Write(packet); err != nil {
					return fmt.Errorf("%w: %v", errPcap, err)
				}
				stats.Pcap++
			}
			if udpSink != nil {
				if err := udpSink.Write(packet); err != nil {
					stats.Errors++
					log.verbosef("ZEP send: %v", err)
				} else {
					stats.ZEP++
				}
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
