// Package zep builds ZEP v2 datagrams as expected by Wireshark's ZEP
// dissector.
package zep

import (
	"encoding/binary"
	"time"
)

// HeaderLen is the fixed ZEP v2 header size in bytes.
const HeaderLen = 32

const (
	// Version is the only ZEP version emitted by this package.
	Version = 2
	// TypeData identifies a frame-bearing ZEP datagram.
	TypeData = 1
	// TypeAck identifies an acknowledgement datagram.
	TypeAck = 2
	// MaxFrameLen is the largest frame representable by ZEP's 7-bit length
	// field.
	MaxFrameLen = 127
)

// NTPEpochOffset is the number of seconds between the Unix and NTP epochs
// (1900-01-01).
const NTPEpochOffset = 2208988800

// Build returns one ZEP v2 data datagram containing frame. The header layout
// matches Wireshark's ZEP dissector:
//
//	0..1   "EX"
//	2      version (2)
//	3      type (1 = data)
//	4      channel
//	5..6   device code (big endian)
//	7      LQI/CRC mode (0 = LQI)
//	8      LQI
//	9..16  NTP timestamp (big endian)
//	17..20 sequence number (big endian)
//	21..30 reserved, zero
//	31     frame length (7 bits)
func Build(frame []byte, channel byte, ts time.Time, seq uint32) []byte {
	return BuildNTP(frame, channel, NTPTime(ts), seq)
}

// BuildNTP is Build with a raw 64-bit NTP timestamp. It is useful for replaying
// captured datagrams exactly.
func BuildNTP(frame []byte, channel byte, ntp uint64, seq uint32) []byte {
	p := make([]byte, HeaderLen+len(frame))
	p[0] = 'E'
	p[1] = 'X'
	p[2] = Version
	p[3] = TypeData
	p[4] = channel
	// Bytes 5-6 are the device code; byte 7 selects LQI mode and byte 8 is LQI.
	binary.BigEndian.PutUint64(p[9:17], ntp)
	binary.BigEndian.PutUint32(p[17:21], seq)
	// Bytes 21-30 are reserved.
	p[31] = byte(len(frame)) & 0x7f
	copy(p[HeaderLen:], frame)
	return p
}

// NTPTime converts a Unix time to the 64-bit NTP timestamp used by ZEP.
func NTPTime(ts time.Time) uint64 {
	sec := uint64(ts.Unix() + NTPEpochOffset)
	frac := (uint64(ts.Nanosecond()) << 32) / 1e9
	return sec<<32 | frac
}

// TimeFromNTP converts a ZEP NTP timestamp to a Unix time.
func TimeFromNTP(ntp uint64) time.Time {
	sec := int64(ntp>>32) - NTPEpochOffset
	frac := ntp & 0xffffffff
	nsec := int64((frac * 1e9) >> 32)
	return time.Unix(sec, nsec).UTC()
}

// Timestamp extracts the NTP timestamp from a ZEP datagram. It returns false if
// the datagram is too short to contain a header.
func Timestamp(packet []byte) (time.Time, bool) {
	if len(packet) < HeaderLen {
		return time.Time{}, false
	}
	return TimeFromNTP(binary.BigEndian.Uint64(packet[9:17])), true
}
