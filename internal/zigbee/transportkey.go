package zigbee

import "encoding/binary"

// KeyType identifies the key descriptor carried by an APS Transport-Key
// command. Values match the ZigBee specification and Wireshark's
// zbee_aps.cmd.key_type field.
type KeyType byte

const (
	KeyTypeTrustCenterMaster   KeyType = 0x00
	KeyTypeStandardNetwork     KeyType = 0x01
	KeyTypeApplicationMaster   KeyType = 0x02
	KeyTypeApplicationLink     KeyType = 0x03
	KeyTypeTrustCenterLink     KeyType = 0x04
	KeyTypeHighSecurityNetwork KeyType = 0x05
	KeyTypeBasicAuthorization  KeyType = 0xB2
	KeyTypeAdminAuthorization  KeyType = 0xB3
)

// String returns a human-readable key type name.
func (t KeyType) String() string {
	switch t {
	case KeyTypeTrustCenterMaster:
		return "trust-center-master"
	case KeyTypeStandardNetwork:
		return "standard-network"
	case KeyTypeApplicationMaster:
		return "application-master"
	case KeyTypeApplicationLink:
		return "application-link"
	case KeyTypeTrustCenterLink:
		return "trust-center-link"
	case KeyTypeHighSecurityNetwork:
		return "high-security-network"
	case KeyTypeBasicAuthorization:
		return "basic-authorization"
	case KeyTypeAdminAuthorization:
		return "admin-authorization"
	default:
		return "unknown"
	}
}

// IsNetworkKey reports whether the key type is a network key.
func (t KeyType) IsNetworkKey() bool {
	return t == KeyTypeStandardNetwork || t == KeyTypeHighSecurityNetwork
}

// NetworkKey is an APS Transport-Key command that carries a network key
// without APS security.
type NetworkKey struct {
	KeyType  KeyType
	Key      [16]byte
	Sequence uint8

	// Destination and Source are extended (64-bit) addresses in wire order,
	// least significant byte first. Source is zero unless HasSource is set.
	Destination [8]byte
	Source      [8]byte
	HasSource   bool

	// PAN and the short addresses come from the MAC and NWK headers. The
	// short address flags are false when the corresponding address was an
	// extended address or absent.
	PAN              uint16
	DestinationShort uint16
	SourceShort      uint16
	HasDestShort     bool
	HasSrcShort      bool
}

const (
	apsFrameTypeCommand    = 0x01
	apsCommandTransportKey = 0x05
	keyLength              = 16
)

// ExtractNetworkKey returns the network key carried by frame when frame is a
// cleartext 802.15.4 data frame with an APS Transport-Key command for a
// standard or high-security network key. It returns false for every other
// frame, including secured frames and unrelated key descriptors.
func ExtractNetworkKey(frame []byte) (NetworkKey, bool) {
	mac, ok := parseMAC(frame)
	if !ok {
		return NetworkKey{}, false
	}
	payload, ok := parseNWK(mac.payload)
	if !ok {
		return NetworkKey{}, false
	}
	key, ok := parseAPS(payload)
	if !ok {
		return NetworkKey{}, false
	}
	key.PAN = mac.pan
	key.DestinationShort = mac.dstShort
	key.SourceShort = mac.srcShort
	key.HasDestShort = mac.hasDstShort
	key.HasSrcShort = mac.hasSrcShort
	return key, true
}

type macInfo struct {
	pan         uint16
	dstShort    uint16
	srcShort    uint16
	hasDstShort bool
	hasSrcShort bool
	payload     []byte
}

// parseMAC strips the IEEE 802.15.4 MAC header and returns addressing
// context plus the MAC payload. Secured frames and frames with reserved
// addressing modes are rejected.
func parseMAC(frame []byte) (macInfo, bool) {
	if len(frame) < 3 {
		return macInfo{}, false
	}
	fcf := binary.LittleEndian.Uint16(frame[0:2])
	if fcf&0x0007 != 0x0001 { // only data frames carry NWK
		return macInfo{}, false
	}
	if fcf&(1<<3) != 0 { // MAC security: payload is encrypted
		return macInfo{}, false
	}

	version := (fcf >> 12) & 0x0003
	if version > 1 {
		// ZigBee uses the 2003 and 2006 MAC header layouts. Version 2
		// (2015) adds sequence suppression and header IEs that are not
		// needed here.
		return macInfo{}, false
	}
	dstMode := (fcf >> 10) & 0x0003
	srcMode := (fcf >> 14) & 0x0003
	if dstMode == 1 || srcMode == 1 { // reserved addressing modes
		return macInfo{}, false
	}
	panCompression := fcf&(1<<6) != 0

	var info macInfo
	off := 2 + 1 // frame control + sequence number
	if dstMode != 0 {
		if off+2 > len(frame) {
			return macInfo{}, false
		}
		info.pan = binary.LittleEndian.Uint16(frame[off : off+2])
		off += 2
		var ok bool
		off, info.dstShort, info.hasDstShort, ok = readAddress(frame, off, dstMode)
		if !ok {
			return macInfo{}, false
		}
	}
	if srcMode != 0 {
		// The source PAN is omitted when PAN ID compression is set and a
		// destination PAN is present.
		if dstMode == 0 || !panCompression {
			if off+2 > len(frame) {
				return macInfo{}, false
			}
			if dstMode == 0 {
				info.pan = binary.LittleEndian.Uint16(frame[off : off+2])
			}
			off += 2
		}
		var ok bool
		off, info.srcShort, info.hasSrcShort, ok = readAddress(frame, off, srcMode)
		if !ok {
			return macInfo{}, false
		}
	}
	if off > len(frame) {
		return macInfo{}, false
	}
	info.payload = frame[off:]
	return info, true
}

// readAddress consumes one address and returns its short value when it is a
// 16-bit address.
func readAddress(frame []byte, off int, mode uint16) (next int, short uint16, hasShort bool, ok bool) {
	switch mode {
	case 2:
		if off+2 > len(frame) {
			return off, 0, false, false
		}
		return off + 2, binary.LittleEndian.Uint16(frame[off : off+2]), true, true
	case 3:
		if off+8 > len(frame) {
			return off, 0, false, false
		}
		return off + 8, 0, false, true
	default:
		return off, 0, false, true
	}
}

// parseNWK strips the ZigBee NWK header and returns the APS payload.
func parseNWK(payload []byte) ([]byte, bool) {
	if len(payload) < 8 {
		return nil, false
	}
	fcf := binary.LittleEndian.Uint16(payload[0:2])
	if fcf&0x0003 != 0x0000 { // only NWK data frames carry APS
		return nil, false
	}
	if fcf&(1<<6) != 0 { // NWK security: payload is encrypted
		return nil, false
	}

	version := (fcf >> 2) & 0x0003
	multicast := fcf&(1<<5) != 0
	sourceRoute := fcf&(1<<7) != 0
	extDst := fcf&(1<<8) != 0
	extSrc := fcf&(1<<9) != 0

	off := 8 // FCF + destination + source + radius + sequence
	if version >= 2 {
		if extDst {
			off += 8
		}
		if extSrc {
			off += 8
		}
		if multicast {
			off++
		}
	}
	if version >= 2 && sourceRoute {
		if off >= len(payload) {
			return nil, false
		}
		// Relay count, relay index, then two bytes per relay.
		off += 2 + 2*int(payload[off])
	}
	if off > len(payload) {
		return nil, false
	}
	return payload[off:], true
}

// parseAPS returns the network key from an unsecured APS Transport-Key
// command.
func parseAPS(payload []byte) (NetworkKey, bool) {
	if len(payload) < 3 {
		return NetworkKey{}, false
	}
	fcf := payload[0]
	if fcf&0x03 != apsFrameTypeCommand {
		return NetworkKey{}, false
	}
	if fcf&(1<<5) != 0 { // APS security: command is encrypted
		return NetworkKey{}, false
	}
	if fcf&(1<<7) != 0 { // extended header; not used by commands
		return NetworkKey{}, false
	}

	off := 2 // frame control + APS counter
	if payload[off] != apsCommandTransportKey {
		return NetworkKey{}, false
	}
	off++

	if off >= len(payload) {
		return NetworkKey{}, false
	}
	keyType := KeyType(payload[off])
	off++
	if !keyType.IsNetworkKey() {
		return NetworkKey{}, false
	}
	if off+keyLength > len(payload) {
		return NetworkKey{}, false
	}

	var key NetworkKey
	key.KeyType = keyType
	copy(key.Key[:], payload[off:off+keyLength])
	off += keyLength

	// Network key descriptor: key sequence number, destination address and,
	// in current captures, the source address.
	if off+1+8 > len(payload) {
		return NetworkKey{}, false
	}
	key.Sequence = payload[off]
	off++
	copy(key.Destination[:], payload[off:off+8])
	off += 8
	if off+8 <= len(payload) {
		copy(key.Source[:], payload[off:off+8])
		key.HasSource = true
	}
	return key, true
}
