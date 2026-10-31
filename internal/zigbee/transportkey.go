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

// NetworkKey is an APS Transport-Key command that carries a network key.
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

// ExtractNetworkKey returns the network key carried by frame when frame is an
// 802.15.4 data frame with an APS Transport-Key command for a standard or
// high-security network key. linkKeys are Trust Center link keys used to
// decrypt APS-secured transports; pass none to accept only cleartext ones. It
// returns false for every other frame and key descriptor.
//
// frame is a raw dongle payload. Like a ZEP mode 0 datagram it ends with the
// CC24xxMetadataLen bytes of RSSI/LQI metadata, which are removed before the
// frame is decoded with Parse.
func ExtractNetworkKey(frame []byte, linkKeys ...[16]byte) (NetworkKey, bool) {
	if len(frame) >= CC24xxMetadataLen {
		frame = frame[:len(frame)-CC24xxMetadataLen]
	}
	parsed, err := Parse(frame)
	if err != nil {
		return NetworkKey{}, false
	}

	// ZigBee uses the 2003 and 2006 MAC header layouts. Version 2 (2015) adds
	// header IEs that Parse does not decode.
	if parsed.frameVersion() > 1 {
		return NetworkKey{}, false
	}
	// Parse stops after the MAC header for secured and non-data frames, so a
	// missing NWK header rejects both. Network key discovery also needs an
	// unsecured NWK data frame; APS security is handled by parseAPS.
	if parsed.NWK == nil || parsed.NWK.Type != "data" || parsed.NWK.Security != nil {
		return NetworkKey{}, false
	}

	key, ok := parseAPS(parsed.nwkPayload(), parsed, linkKeys)
	if !ok {
		return NetworkKey{}, false
	}
	key.PAN = parsed.panID()
	key.DestinationShort, key.SourceShort, key.HasDestShort, key.HasSrcShort = parsed.shortAddresses()
	return key, true
}

// parseAPS returns the network key from an APS Transport-Key command. Clear
// commands are parsed directly; APS-secured commands are decrypted with the
// supplied Trust Center link keys.
func parseAPS(payload []byte, frame *Frame, linkKeys [][16]byte) (NetworkKey, bool) {
	if len(payload) < 3 {
		return NetworkKey{}, false
	}
	fcf := payload[0]
	if fcf&0x03 != apsFrameTypeCommand {
		return NetworkKey{}, false
	}
	if fcf&(1<<7) != 0 { // extended header; not used by commands
		return NetworkKey{}, false
	}

	if fcf&(1<<5) == 0 {
		return parseTransportKeyCommand(payload[2:])
	}
	plain, ok := decryptAPSTransportKey(payload, frame, linkKeys)
	if !ok {
		return NetworkKey{}, false
	}
	return parseTransportKeyCommand(plain)
}

// parseTransportKeyCommand decodes an unencrypted APS command payload that
// starts with the Transport-Key command identifier.
func parseTransportKeyCommand(payload []byte) (NetworkKey, bool) {
	if len(payload) < 1 || payload[0] != apsCommandTransportKey {
		return NetworkKey{}, false
	}
	off := 1

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

// decryptAPSTransportKey decrypts the APS payload of a command secured with a
// Trust Center link key (key identifier 0). The authenticated data is the APS
// header followed by the auxiliary security header; the MIC covers both and
// the plaintext. Devices commonly transmit security level 0 and use level 5
// on air, so level 0 tries the encrypted levels in turn.
func decryptAPSTransportKey(payload []byte, frame *Frame, keys [][16]byte) ([]byte, bool) {
	if len(keys) == 0 || len(payload) < 3 {
		return nil, false
	}
	control := payload[2]
	if keyID := (control >> 3) & 0x03; keyID != 0 {
		// Network, transport and load keys are either unknown here or need a
		// derived key; only the Trust Center link key is supported.
		return nil, false
	}
	off := 3
	if len(payload) < off+4 {
		return nil, false
	}
	frameCounter := binary.LittleEndian.Uint32(payload[off:])
	off += 4

	var src []byte
	if control&0x20 != 0 {
		if len(payload) < off+8 {
			return nil, false
		}
		src = payload[off : off+8]
		off += 8
	} else {
		// Without an extended nonce the source comes from the NWK header.
		src = frame.nwkSrc64Wire
	}
	if len(src) != 8 {
		return nil, false
	}

	levels := []uint8{control & 0x07}
	if levels[0] == 0 {
		levels = []uint8{SecEncMIC32, SecEncMIC64, SecEncMIC128}
	}
	for _, level := range levels {
		micLen := MICLen(level)
		payloadEnd := len(payload) - micLen
		if micLen == 0 || payloadEnd < off {
			continue
		}
		controlEff := control&^0x07 | level
		aad := make([]byte, off)
		copy(aad, payload[:off])
		aad[2] = controlEff

		var nonce [13]byte
		copy(nonce[0:8], src)
		binary.LittleEndian.PutUint32(nonce[8:12], frameCounter)
		nonce[12] = controlEff

		for i := range keys {
			plain, ok := ccmStarDecrypt(keys[i][:], nonce[:], aad, payload[off:payloadEnd], payload[payloadEnd:], level)
			if ok {
				return plain, true
			}
		}
	}
	return nil, false
}
