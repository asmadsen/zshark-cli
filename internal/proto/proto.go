// Package proto implements the host side of the ConBee sniffer wire protocol:
// the newline-terminated text commands and the 0x01/LEN/PAYLOAD/0x04 frame
// envelope.
package proto

import "fmt"

// Envelope bytes used by the dongle's binary frame protocol.
const (
	StartByte = 0x01
	EndByte   = 0x04
)

// MetadataLen is the number of bytes between the envelope length and the raw
// 802.15.4 frame. The dongle emits the constant marker 01 02 03 04 05 06 07 08
// here; it does not carry the selected channel.
const MetadataLen = 8

// DefaultMaxPayload is a conservative upper bound for the envelope length.
// The largest legal 802.15.4 PSDU is 127 bytes, plus the 8-byte metadata
// prefix, so 160 leaves headroom while still rejecting corrupt length bytes.
const DefaultMaxPayload = 160

// Text commands sent to the dongle. They are newline framed on both sides.
var (
	CmdIdle  = []byte("\nidle\n")
	CmdParms = []byte("\nparms\n")
	CmdSniff = []byte("\nsniff\n")
)

// CmdChannel returns the command that selects a ZigBee channel.
func CmdChannel(channel int) []byte {
	return []byte(fmt.Sprintf("\nchan %d\n", channel))
}

// Frame is one decoded envelope payload. The payload consists of an 8-byte
// metadata prefix followed by an 802.15.4 frame.
type Frame struct {
	Payload []byte
}

// Valid reports whether the payload is long enough to contain the metadata
// prefix.
func (f Frame) Valid() bool {
	return len(f.Payload) >= MetadataLen
}

// Data returns the raw 802.15.4 frame that starts at payload offset 8.
func (f Frame) Data() []byte {
	if !f.Valid() {
		return nil
	}
	return f.Payload[MetadataLen:]
}
