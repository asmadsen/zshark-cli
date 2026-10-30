package zigbee

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
//
// frame is a raw dongle payload. Like a ZEP mode 0 datagram it ends with the
// CC24xxMetadataLen bytes of RSSI/LQI metadata, which are removed before the
// frame is decoded with Parse.
func ExtractNetworkKey(frame []byte) (NetworkKey, bool) {
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
	// unsecured NWK data frame; APS security is checked by parseAPS.
	if parsed.NWK == nil || parsed.NWK.Type != "data" || parsed.NWK.Security != nil {
		return NetworkKey{}, false
	}

	key, ok := parseAPS(parsed.nwkPayload())
	if !ok {
		return NetworkKey{}, false
	}
	key.PAN = parsed.panID()
	key.DestinationShort, key.SourceShort, key.HasDestShort, key.HasSrcShort = parsed.shortAddresses()
	return key, true
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
