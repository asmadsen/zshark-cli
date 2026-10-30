package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"zshark/internal/sink"
	"zshark/internal/zep"
)

var (
	errPcap  = errors.New("pcap write failed")
	errJSONL = errors.New("JSONL write failed")
)

func runCapture(ctx context.Context, cfg captureConfig, stdout, stderr io.Writer) (code int) {
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

	var jsonSink *sink.JSONL
	if cfg.JSONL != "" {
		var err error
		if cfg.JSONL == "-" {
			jsonSink = sink.NewJSONL(stdout, cfg.NetworkKeys, uint8(cfg.SecurityLevel))
		} else {
			jsonSink, err = sink.NewJSONLFile(cfg.JSONL, cfg.NetworkKeys, uint8(cfg.SecurityLevel))
			if err != nil {
				log.errorf("create %s: %v", cfg.JSONL, err)
				return exitRuntime
			}
		}
		defer func() {
			if err := jsonSink.Close(); err != nil {
				log.errorf("close %s: %v", cfg.JSONL, err)
				if code == exitOK {
					code = exitRuntime
				}
			}
		}()
		log.verbosef("writing JSONL to %s", cfg.JSONL)
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

	out := &captureOutput{
		channel: cfg.Channel,
		pcap:    pcapSink,
		jsonl:   jsonSink,
		udp:     udpSink,
		stats:   stats,
		log:     log,
	}
	code = runDevice(ctx, deviceConfig{Port: cfg.Port, Channel: cfg.Channel}, log, stats, out.frame)
	log.printf("stats: %s", stats.line())
	return code
}

// captureOutput turns one raw 802.15.4 frame into a ZEP datagram and writes it
// to the configured sinks. It is the frame handler for the capture command.
type captureOutput struct {
	channel int
	pcap    *sink.Pcapng
	jsonl   *sink.JSONL
	udp     *sink.UDP
	stats   *captureStats
	log     *captureLogger
	seq     uint32
}

func (c *captureOutput) frame(data []byte) error {
	packet := zep.BuildNTP(data, byte(c.channel), zep.NTPTime(time.Now()), c.seq)
	thisSeq := c.seq
	c.seq++
	c.log.verbosef("frame channel=%d len=%d seq=%d", c.channel, len(data), thisSeq)

	if c.pcap != nil {
		if err := c.pcap.Write(packet); err != nil {
			return fmt.Errorf("%w: %v", errPcap, err)
		}
		c.stats.Pcap++
	}
	if c.jsonl != nil {
		if err := c.jsonl.Write(packet); err != nil {
			return fmt.Errorf("%w: %v", errJSONL, err)
		}
		c.stats.JSONL++
	}
	if c.udp != nil {
		if err := c.udp.Write(packet); err != nil {
			c.stats.Dropped++
			c.stats.Errors++
			c.log.verbosef("ZEP send: %v", err)
		} else {
			c.stats.ZEP++
		}
	}
	return nil
}
