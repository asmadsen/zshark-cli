package sink

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"zshark/internal/zep"
	"zshark/internal/zigbee"
)

// JSONL writes one JSON object per IEEE 802.15.4 frame. Unlike the pcapng sink
// it stores only ZigBee data: no Ethernet, IP, UDP or ZEP headers. Network keys
// may be supplied to decrypt NWK-secured payloads.
type JSONL struct {
	buf    *bufio.Writer
	enc    *json.Encoder
	closer io.Closer
	keys   [][16]byte
	level  uint8
	closed bool
}

type jsonlRecord struct {
	Time       string             `json:"ts"`
	Channel    uint8              `json:"channel"`
	Seq        uint32             `json:"seq"`
	Length     int                `json:"len"`
	Radio      *jsonlRadio        `json:"radio,omitempty"`
	Data       string             `json:"data"`
	MAC        *zigbee.MAC        `json:"mac,omitempty"`
	NWK        *zigbee.NWK        `json:"nwk,omitempty"`
	Decryption *zigbee.Decryption `json:"decryption,omitempty"`
}

type jsonlRadio struct {
	RSSI     int   `json:"rssi"`
	LQI      uint8 `json:"lqi"`
	FCSValid bool  `json:"fcsValid"`
}

// NewJSONL returns a JSONL writer. The caller keeps ownership of w.
func NewJSONL(w io.Writer, keys [][16]byte, level uint8) *JSONL {
	buf := bufio.NewWriter(w)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	return &JSONL{buf: buf, enc: enc, keys: keys, level: level}
}

// NewJSONLFile creates or truncates path and returns a JSONL writer.
func NewJSONLFile(path string, keys [][16]byte, level uint8) (*JSONL, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	j := NewJSONL(f, keys, level)
	j.closer = f
	return j, nil
}

// Write appends one frame as a JSON line. packet is a complete ZEP v2 data
// datagram; the ZEP header supplies the timestamp, channel and sequence.
func (j *JSONL) Write(packet []byte) error {
	if len(packet) < zep.HeaderLen {
		return fmt.Errorf("jsonl: ZEP datagram too short (%d bytes)", len(packet))
	}
	ts, ok := zep.Timestamp(packet)
	if !ok {
		return fmt.Errorf("jsonl: ZEP datagram too short (%d bytes)", len(packet))
	}

	frameLen := int(packet[31] & 0x7f)
	if frameLen == 0 || frameLen > len(packet)-zep.HeaderLen {
		frameLen = len(packet) - zep.HeaderLen
	}
	payload := packet[zep.HeaderLen : zep.HeaderLen+frameLen]

	rec := jsonlRecord{
		Time:    ts.UTC().Format(time.RFC3339Nano),
		Channel: packet[4],
		Seq:     binary.BigEndian.Uint32(packet[17:21]),
	}

	// ZEP mode 0 carries ChipCon/TI CC24xx metadata (RSSI, FCS/LQI) in the
	// last two bytes. Mode 1 carries a two-byte CRC. Neither belongs to the
	// 802.15.4 frame itself.
	if len(payload) >= zigbee.CC24xxMetadataLen {
		meta := payload[len(payload)-zigbee.CC24xxMetadataLen:]
		if packet[7] == 0 {
			rec.Radio = &jsonlRadio{
				RSSI:     int(int8(meta[0])),
				LQI:      meta[1] & 0x7f,
				FCSValid: meta[1]&0x80 != 0,
			}
		}
		payload = payload[:len(payload)-zigbee.CC24xxMetadataLen]
	}
	rec.Length = len(payload)
	rec.Data = hex.EncodeToString(payload)

	if frame, err := zigbee.Parse(payload); err == nil {
		rec.MAC = &frame.MAC
		rec.NWK = frame.NWK
		if frame.NWK != nil && frame.NWK.Security != nil {
			rec.Decryption = frame.Decrypt(j.keys, j.level)
		}
	}

	if err := j.enc.Encode(&rec); err != nil {
		return err
	}
	// Flush every line so consumers can tail a live capture.
	return j.buf.Flush()
}

// Close flushes buffered data and closes the file, if this sink owns one.
func (j *JSONL) Close() error {
	if j.closed {
		return nil
	}
	j.closed = true
	err := j.buf.Flush()
	if j.closer != nil {
		if cerr := j.closer.Close(); err == nil {
			err = cerr
		}
	}
	return err
}
