// Package zigbee decodes IEEE 802.15.4 MAC, ZigBee NWK and APS headers.
//
// It provides frame decoding and NWK payload decryption with network keys for
// the JSONL sink, and recognises cleartext APS Transport-Key commands that
// carry a network key so the keys command can report it.
//
// Only frames that are not secured at the MAC, NWK or APS layer can be read
// for key discovery. A network key protected by the well-known Trust Center
// Link Key is therefore intentionally not reported.
package zigbee

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Decryption status values used in JSON output.
const (
	DecryptOK          = "ok"
	DecryptNoKey       = "no-key"
	DecryptFailed      = "failed"
	DecryptUnsupported = "unsupported-key"
	DecryptNoSecurity  = "no-security"
)

// CC24xxMetadataLen is the number of trailing bytes a ChipCon/TI CC24xx radio
// appends to a frame: RSSI followed by an FCS/LQI byte. ZEP mode 0 datagrams
// and raw dongle payloads both carry this metadata, which is not part of the
// 802.15.4 frame. Parse expects it to be removed; ExtractNetworkKey removes it
// from raw dongle payloads before parsing.
const CC24xxMetadataLen = 2

// MAC describes the IEEE 802.15.4 MAC header of a captured frame.
type MAC struct {
	Type       string `json:"type,omitempty"`
	Seq        *uint8 `json:"seq,omitempty"`
	DstPAN     string `json:"dstPan,omitempty"`
	Dst        string `json:"dst,omitempty"`
	SrcPAN     string `json:"srcPan,omitempty"`
	Src        string `json:"src,omitempty"`
	AckRequest bool   `json:"ackRequest,omitempty"`
	Security   bool   `json:"security,omitempty"`
}

// NWK describes the ZigBee network layer header. It is only present for
// 802.15.4 data frames that carry a NWK frame.
type NWK struct {
	Type     string    `json:"type,omitempty"`
	Dst      string    `json:"dst,omitempty"`
	Src      string    `json:"src,omitempty"`
	ExtDst   string    `json:"extDst,omitempty"`
	ExtSrc   string    `json:"extSrc,omitempty"`
	Security *Security `json:"security,omitempty"`
}

// Security describes the ZigBee auxiliary security header.
type Security struct {
	Level        uint8  `json:"level"`
	KeyID        uint8  `json:"keyId"`
	KeyType      string `json:"keyType,omitempty"`
	FrameCounter uint32 `json:"frameCounter"`
	ExtSrc       string `json:"extSrc,omitempty"`
	KeySeq       uint8  `json:"keySeq"`
	MIC          string `json:"mic,omitempty"`
}

// Decryption is the result of applying network keys to a secured NWK frame.
type Decryption struct {
	Status   string `json:"status"`
	Level    uint8  `json:"level"`
	KeyIndex *int   `json:"keyIndex,omitempty"`
	Payload  string `json:"payload,omitempty"`
}

// Frame is a parsed IEEE 802.15.4 frame. MAC is always populated when Parse
// succeeds; NWK is populated for data frames with a readable NWK header.
type Frame struct {
	MAC MAC
	NWK *NWK

	raw          []byte
	auxStart     int
	payloadStart int
	control      byte
	frameCounter uint32
	keyID        uint8
	extSrcWire   []byte
	nwkSrc64Wire []byte

	// Numeric header context. The exported MAC and NWK values are formatted
	// for display; key extraction needs the raw numbers and presence flags.
	// These fields are unexported so the JSON encoding is unchanged.
	macVersion  uint16
	macDstPAN   uint16
	macSrcPAN   uint16
	macDstShort uint16
	macSrcShort uint16
	hasDstShort bool
	hasSrcShort bool
}

// Parse decodes the MAC header, and for data frames the NWK header and
// auxiliary security header. The frame must not include the trailing
// CC24xxMetadataLen bytes of CC24xx metadata (RSSI/LQI) that ZEP and raw dongle
// payloads carry.
func Parse(raw []byte) (*Frame, error) {
	if len(raw) < 3 {
		return nil, fmt.Errorf("802.15.4 frame too short (%d bytes)", len(raw))
	}
	f := &Frame{raw: raw}
	fcf := binary.LittleEndian.Uint16(raw[0:2])
	f.MAC.Type = macTypeName(fcf & 0x07)
	f.MAC.AckRequest = fcf&0x20 != 0
	f.MAC.Security = fcf&0x08 != 0

	off := 2
	version := (fcf >> 12) & 0x03
	f.macVersion = version
	seqSuppressed := version == 2 && fcf&0x0080 != 0
	if !seqSuppressed {
		if len(raw) < off+1 {
			return nil, fmt.Errorf("truncated MAC sequence number")
		}
		seq := raw[off]
		f.MAC.Seq = &seq
		off++
	}

	dstMode := (fcf >> 10) & 0x03
	srcMode := (fcf >> 14) & 0x03
	panCompression := fcf&0x40 != 0

	if dstMode != 0 {
		if len(raw) < off+2 {
			return nil, fmt.Errorf("truncated destination PAN")
		}
		f.macDstPAN = binary.LittleEndian.Uint16(raw[off:])
		f.MAC.DstPAN = shortAddr(raw[off:])
		off += 2
		addr, n, err := parseAddr(raw[off:], dstMode)
		if err != nil {
			return nil, err
		}
		if dstMode == 2 {
			f.macDstShort = binary.LittleEndian.Uint16(raw[off:])
			f.hasDstShort = true
		}
		f.MAC.Dst = addr
		off += n
	}
	if srcMode != 0 {
		if srcMode == 0x01 || dstMode == 0x01 {
			return nil, fmt.Errorf("reserved MAC addressing mode")
		}
		if !panCompression || dstMode == 0 {
			if len(raw) < off+2 {
				return nil, fmt.Errorf("truncated source PAN")
			}
			f.macSrcPAN = binary.LittleEndian.Uint16(raw[off:])
			f.MAC.SrcPAN = shortAddr(raw[off:])
			off += 2
		} else {
			f.macSrcPAN = f.macDstPAN
			f.MAC.SrcPAN = f.MAC.DstPAN
		}
		addr, n, err := parseAddr(raw[off:], srcMode)
		if err != nil {
			return nil, err
		}
		if srcMode == 2 {
			f.macSrcShort = binary.LittleEndian.Uint16(raw[off:])
			f.hasSrcShort = true
		}
		f.MAC.Src = addr
		off += n
	}

	// ZigBee uses NWK-layer security. If the MAC layer also carries a
	// security header we cannot locate the NWK header reliably, so stop here.
	if f.MAC.Security {
		return f, nil
	}
	if fcf&0x07 != 1 { // not a data frame
		return f, nil
	}
	if err := f.parseNWK(off); err != nil {
		return f, err
	}
	return f, nil
}

// frameVersion returns the 802.15.4 frame version from the MAC frame control
// field.
func (f *Frame) frameVersion() uint16 {
	return f.macVersion
}

// panID returns the PAN identifier that applies to the frame: the destination
// PAN when the frame has one, otherwise the source PAN. It is zero when the
// frame has neither.
func (f *Frame) panID() uint16 {
	if f.MAC.DstPAN != "" {
		return f.macDstPAN
	}
	return f.macSrcPAN
}

// shortAddresses returns the destination and source MAC short addresses and
// whether each was present as a 16-bit address.
func (f *Frame) shortAddresses() (dst, src uint16, hasDst, hasSrc bool) {
	return f.macDstShort, f.macSrcShort, f.hasDstShort, f.hasSrcShort
}

// nwkPayload returns the bytes following the decoded NWK header and, when
// present, the auxiliary security header. It is nil when the frame has no
// decoded NWK header.
func (f *Frame) nwkPayload() []byte {
	if f.NWK == nil || f.payloadStart > len(f.raw) {
		return nil
	}
	return f.raw[f.payloadStart:]
}

func (f *Frame) parseNWK(off int) error {
	raw := f.raw
	if len(raw) < off+2 {
		return fmt.Errorf("truncated NWK frame control")
	}
	fcf := binary.LittleEndian.Uint16(raw[off : off+2])
	off += 2

	nwk := &NWK{Type: nwkTypeName(fcf & 0x03)}
	version := (fcf >> 2) & 0x0f
	security := fcf&0x0200 != 0
	multicast := fcf&0x0100 != 0
	route := fcf&0x0400 != 0
	extDst := fcf&0x0800 != 0
	extSrc := fcf&0x1000 != 0

	// Interpan frames have no addressing fields.
	if fcf&0x03 != 3 {
		if len(raw) < off+6 {
			return fmt.Errorf("truncated NWK header")
		}
		nwk.Dst = shortAddr(raw[off:])
		nwk.Src = shortAddr(raw[off+2:])
		off += 6 // destination, source, radius, sequence number

		if version >= 2 && extDst {
			if len(raw) < off+8 {
				return fmt.Errorf("truncated NWK extended destination")
			}
			nwk.ExtDst = extAddr(raw[off:], true)
			off += 8
		}
		if version >= 2 && extSrc {
			if len(raw) < off+8 {
				return fmt.Errorf("truncated NWK extended source")
			}
			f.nwkSrc64Wire = raw[off : off+8]
			nwk.ExtSrc = extAddr(raw[off:], true)
			off += 8
		}
		if version >= 2 && multicast {
			if len(raw) < off+1 {
				return fmt.Errorf("truncated NWK multicast control")
			}
			off++
		}
		if version >= 2 && route {
			if len(raw) < off+2 {
				return fmt.Errorf("truncated NWK source route")
			}
			relayCount := int(raw[off])
			if len(raw) < off+2+2*relayCount {
				return fmt.Errorf("truncated NWK relay list")
			}
			off += 2 + 2*relayCount
		}
	}

	if security {
		sec, next, err := parseSecurity(raw, off)
		if err != nil {
			return err
		}
		f.auxStart = off
		f.payloadStart = next
		f.control = sec.control
		f.frameCounter = sec.frameCounter
		f.keyID = sec.keyID
		f.extSrcWire = sec.extSrc
		nwk.Security = sec.info
	} else {
		f.payloadStart = off
	}

	f.NWK = nwk
	return nil
}

type securityHeader struct {
	info         *Security
	control      byte
	frameCounter uint32
	keyID        uint8
	extSrc       []byte
}

func parseSecurity(raw []byte, off int) (*securityHeader, int, error) {
	if len(raw) < off+1 {
		return nil, 0, fmt.Errorf("truncated auxiliary security header")
	}
	control := raw[off]
	off++
	keyID := (control >> 3) & 0x03
	info := &Security{
		Level:   control & 0x07,
		KeyID:   keyID,
		KeyType: KeyTypeName(keyID),
	}
	if len(raw) < off+4 {
		return nil, 0, fmt.Errorf("truncated security frame counter")
	}
	info.FrameCounter = binary.LittleEndian.Uint32(raw[off:])
	off += 4

	var extSrc []byte
	if control&0x20 != 0 {
		if len(raw) < off+8 {
			return nil, 0, fmt.Errorf("truncated security extended source")
		}
		extSrc = raw[off : off+8]
		info.ExtSrc = extAddr(extSrc, false)
		off += 8
	}
	if keyID == 1 { // network keys carry a key sequence number
		if len(raw) < off+1 {
			return nil, 0, fmt.Errorf("truncated security key sequence number")
		}
		info.KeySeq = raw[off]
		off++
	}
	return &securityHeader{
		info:         info,
		control:      control,
		frameCounter: info.FrameCounter,
		keyID:        keyID,
		extSrc:       extSrc,
	}, off, nil
}

// Decrypt applies network keys to a secured NWK frame. level is the ZigBee
// security level to use for decryption; ZigBee devices commonly transmit level
// 0 in the auxiliary header, so the level is configured out of band like
// Wireshark does. The frame's Security.MIC is updated to match level.
func (f *Frame) Decrypt(keys [][16]byte, level uint8) *Decryption {
	if f.NWK == nil || f.NWK.Security == nil {
		return nil
	}
	sec := f.NWK.Security
	level &= 0x07
	micLen := MICLen(level)
	payloadEnd := len(f.raw) - micLen
	if payloadEnd < f.payloadStart {
		sec.MIC = ""
		return &Decryption{Status: DecryptFailed, Level: level}
	}
	mic := f.raw[payloadEnd:]
	sec.MIC = hex.EncodeToString(mic)

	if f.keyID != 1 {
		return &Decryption{Status: DecryptUnsupported, Level: level}
	}
	if level == SecNone {
		return &Decryption{Status: DecryptNoSecurity, Level: level}
	}

	control := f.control&^0x07 | level
	aad := make([]byte, f.payloadStart)
	copy(aad, f.raw[:f.payloadStart])
	aad[f.auxStart] = control

	src := f.extSrcWire
	if len(src) != 8 {
		// Without an extended nonce the nonce uses the sender's NWK extended
		// source address, whose wire bytes are already little-endian.
		src = f.nwkSrc64Wire
	}
	if len(src) != 8 {
		return &Decryption{Status: DecryptFailed, Level: level}
	}
	var nonce [13]byte
	copy(nonce[0:8], src)
	binary.LittleEndian.PutUint32(nonce[8:12], f.frameCounter)
	nonce[12] = control

	ciphertext := f.raw[f.payloadStart:payloadEnd]
	if len(keys) == 0 {
		return &Decryption{Status: DecryptNoKey, Level: level}
	}
	for i := range keys {
		plain, ok := ccmStarDecrypt(keys[i][:], nonce[:], aad, ciphertext, mic, level)
		if ok {
			index := i
			return &Decryption{
				Status:   DecryptOK,
				Level:    level,
				KeyIndex: &index,
				Payload:  hex.EncodeToString(plain),
			}
		}
	}
	return &Decryption{Status: DecryptFailed, Level: level}
}

// KeyTypeName names a ZigBee key identifier.
func KeyTypeName(id uint8) string {
	switch id {
	case 0:
		return "link"
	case 1:
		return "network"
	case 2:
		return "transport"
	case 3:
		return "load"
	}
	return ""
}

func macTypeName(t uint16) string {
	switch t {
	case 0:
		return "beacon"
	case 1:
		return "data"
	case 2:
		return "ack"
	case 3:
		return "command"
	case 4:
		return "reserved"
	case 5:
		return "multipurpose"
	case 6:
		return "fragment"
	case 7:
		return "extended"
	}
	return ""
}

func nwkTypeName(t uint16) string {
	switch t {
	case 0:
		return "data"
	case 1:
		return "command"
	case 2:
		return "reserved"
	case 3:
		return "interpan"
	}
	return ""
}

func parseAddr(b []byte, mode uint16) (string, int, error) {
	switch mode {
	case 2:
		if len(b) < 2 {
			return "", 0, fmt.Errorf("truncated short MAC address")
		}
		return shortAddr(b), 2, nil
	case 3:
		if len(b) < 8 {
			return "", 0, fmt.Errorf("truncated extended MAC address")
		}
		return extAddr(b, true), 8, nil
	}
	return "", 0, fmt.Errorf("unsupported MAC addressing mode %d", mode)
}

func shortAddr(b []byte) string {
	return fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(b))
}

// extAddr formats an IEEE address. ZigBee carries extended addresses
// little-endian on the wire, but the auxiliary security header carries them
// most-significant byte first, matching Wireshark's display.
func extAddr(b []byte, wireLittleEndian bool) string {
	if len(b) < 8 {
		return ""
	}
	var v [8]byte
	copy(v[:], b[:8])
	if wireLittleEndian {
		for i, j := 0, 7; i < j; i, j = i+1, j-1 {
			v[i], v[j] = v[j], v[i]
		}
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])
}
