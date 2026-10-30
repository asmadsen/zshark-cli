package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"zshark/internal/zigbee"
)

// keysStats extends the shared capture counters with key discovery counts.
type keysStats struct {
	captureStats
	Keys       uint64
	Unique     uint64
	Duplicates uint64
}

func (s *keysStats) line() string {
	return fmt.Sprintf("frames=%d keys=%d unique=%d duplicates=%d errors=%d reconnects=%d text_lines=%d",
		s.Frames, s.Keys, s.Unique, s.Duplicates, s.Errors, s.Reconnects, s.Text)
}

// keyRecord is one discovered network key as printed by the keys command.
type keyRecord struct {
	Time             time.Time `json:"time"`
	Channel          int       `json:"channel"`
	PAN              string    `json:"pan"`
	DestinationShort string    `json:"destination_short,omitempty"`
	SourceShort      string    `json:"source_short,omitempty"`
	Destination      string    `json:"destination"`
	Source           string    `json:"source,omitempty"`
	KeyType          string    `json:"key_type"`
	Key              string    `json:"key"`
	KeySequence      uint8     `json:"key_sequence"`
}

func (r keyRecord) line() string {
	parts := []string{
		r.Time.UTC().Format(time.RFC3339Nano),
		fmt.Sprintf("channel=%d", r.Channel),
		"pan=" + r.PAN,
	}
	if r.DestinationShort != "" {
		parts = append(parts, "dst="+r.DestinationShort)
	}
	if r.SourceShort != "" {
		parts = append(parts, "src="+r.SourceShort)
	}
	parts = append(parts, "dst_ext="+r.Destination)
	if r.Source != "" {
		parts = append(parts, "src_ext="+r.Source)
	}
	parts = append(parts,
		"type="+r.KeyType,
		fmt.Sprintf("key_seq=%d", r.KeySequence),
		"key="+r.Key,
	)
	return strings.Join(parts, " ")
}

func newKeyRecord(ts time.Time, channel int, key zigbee.NetworkKey) keyRecord {
	rec := keyRecord{
		Time:        ts.UTC(),
		Channel:     channel,
		PAN:         fmt.Sprintf("0x%04x", key.PAN),
		Destination: formatEUI64(key.Destination),
		KeyType:     key.KeyType.String(),
		Key:         hex.EncodeToString(key.Key[:]),
		KeySequence: key.Sequence,
	}
	if key.HasDestShort {
		rec.DestinationShort = fmt.Sprintf("0x%04x", key.DestinationShort)
	}
	if key.HasSrcShort {
		rec.SourceShort = fmt.Sprintf("0x%04x", key.SourceShort)
	}
	if key.HasSource {
		rec.Source = formatEUI64(key.Source)
	}
	return rec
}

// formatEUI64 renders an extended address the way Wireshark does: most
// significant byte first, separated by colons.
func formatEUI64(addr [8]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		addr[7], addr[6], addr[5], addr[4], addr[3], addr[2], addr[1], addr[0])
}

// keyOutput prints discovered keys and suppresses repeated transports of the
// same key unless all is set.
type keyOutput struct {
	w    io.Writer
	json bool
	all  bool
	seen map[string]struct{}
}

func (o *keyOutput) write(ts time.Time, channel int, key zigbee.NetworkKey, stats *keysStats) error {
	if o.seen == nil {
		o.seen = make(map[string]struct{})
	}
	stats.Keys++
	id := keyIdentity(key)
	if _, ok := o.seen[id]; ok {
		stats.Duplicates++
		if !o.all {
			return nil
		}
	} else {
		o.seen[id] = struct{}{}
		stats.Unique++
	}

	rec := newKeyRecord(ts, channel, key)
	if o.json {
		line, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("encode key: %w", err)
		}
		_, err = fmt.Fprintf(o.w, "%s\n", line)
		return err
	}
	_, err := fmt.Fprintln(o.w, rec.line())
	return err
}

// keyIdentity identifies one key transported to one device. Repeats of the
// transport (devices commonly receive it more than once) share an identity.
func keyIdentity(key zigbee.NetworkKey) string {
	return fmt.Sprintf("%x/%04x/%x/%d", key.Key, key.PAN, key.Destination, key.Sequence)
}

func runKeys(ctx context.Context, cfg keysConfig, stdout, stderr io.Writer) int {
	log := &captureLogger{w: stderr, verbose: cfg.Verbose}
	stats := &keysStats{}
	out := &keyOutput{
		w:    stdout,
		json: cfg.JSON,
		all:  cfg.All,
		seen: make(map[string]struct{}),
	}

	code := runDevice(ctx, deviceConfig{Port: cfg.Port, Channel: cfg.Channel}, log, &stats.captureStats, func(frame []byte) error {
		key, ok := zigbee.ExtractNetworkKey(frame)
		if !ok {
			return nil
		}
		return out.write(time.Now(), cfg.Channel, key, stats)
	})
	log.printf("stats: %s", stats.line())
	return code
}
