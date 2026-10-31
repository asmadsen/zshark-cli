package zigbee

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"testing"
)

// Builders for the frame shapes the dongle produces. Every frame ends with the
// two-byte TI CC24xx RSSI/LQI metadata the ZEP dissector expects; the parser
// must ignore those trailing bytes.

type macOptions struct {
	fcf      uint16
	dstPAN   uint16
	dstShort uint16
	srcShort uint16
	dstExt   [8]byte
	srcExt   [8]byte
}

func shortMAC(dstPAN, dst, src uint16) []byte {
	return macFrame(macOptions{
		fcf:      0x8841, // data, PAN compression, short destination and source
		dstPAN:   dstPAN,
		dstShort: dst,
		srcShort: src,
	})
}

func longMAC(dstPAN uint16, dst, src [8]byte) []byte {
	return macFrame(macOptions{
		fcf:    0xCC41, // data, PAN compression, extended destination and source
		dstPAN: dstPAN,
		dstExt: dst,
		srcExt: src,
	})
}

func macFrame(o macOptions) []byte {
	b := make([]byte, 0, 32)
	b = binary.LittleEndian.AppendUint16(b, o.fcf)
	b = append(b, 0x01) // sequence number
	if (o.fcf>>10)&0x3 != 0 {
		b = binary.LittleEndian.AppendUint16(b, o.dstPAN)
		b = appendAddr(b, (o.fcf>>10)&0x3, o.dstShort, o.dstExt)
	}
	if (o.fcf>>14)&0x3 != 0 {
		if (o.fcf>>10)&0x3 == 0 || o.fcf&(1<<6) == 0 {
			b = binary.LittleEndian.AppendUint16(b, o.dstPAN)
		}
		b = appendAddr(b, (o.fcf>>14)&0x3, o.srcShort, o.srcExt)
	}
	return b
}

func appendAddr(b []byte, mode uint16, short uint16, ext [8]byte) []byte {
	switch mode {
	case 2:
		return binary.LittleEndian.AppendUint16(b, short)
	case 3:
		return append(b, ext[:]...)
	default:
		return b
	}
}

func nwkHeader(fcf uint16, tail []byte) []byte {
	b := make([]byte, 0, 16+len(tail))
	b = binary.LittleEndian.AppendUint16(b, fcf)
	b = binary.LittleEndian.AppendUint16(b, 0x1234) // destination
	b = binary.LittleEndian.AppendUint16(b, 0x0000) // source
	b = append(b, 7, 1)                             // radius, sequence
	return append(b, tail...)
}

func apsTransportKey(keyType byte, key [16]byte, seq byte, dest, src [8]byte, secured bool) []byte {
	fcf := byte(0x01) // command
	if secured {
		fcf |= 1 << 5
	}
	b := []byte{fcf, 0x01, 0x05, keyType}
	b = append(b, key[:]...)
	b = append(b, seq)
	b = append(b, dest[:]...)
	b = append(b, src[:]...)
	return b
}

func networkKeyFrame(keyType byte) []byte {
	key := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	dst := [8]byte{0x00, 0x12, 0x4b, 0x00, 0x1a, 0x2b, 0x3c, 0x4d}
	src := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	frame := shortMAC(0x1a2b, 0x1234, 0x0000)
	frame = append(frame, nwkHeader(0x0008, nil)...)
	frame = append(frame, apsTransportKey(keyType, key, 3, dst, src, false)...)
	frame = append(frame, 0x9e, 0x80) // RSSI, LQI with CRC OK
	return frame
}

func TestExtractStandardNetworkKey(t *testing.T) {
	key, ok := ExtractNetworkKey(networkKeyFrame(byte(KeyTypeStandardNetwork)))
	if !ok {
		t.Fatal("ExtractNetworkKey = false, want true")
	}
	if key.KeyType != KeyTypeStandardNetwork {
		t.Errorf("key type = %v, want standard-network", key.KeyType)
	}
	if got, want := string(key.Key[:]), "ZigBeeAlliance09"; got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
	if key.Sequence != 3 {
		t.Errorf("sequence = %d, want 3", key.Sequence)
	}
	if key.PAN != 0x1a2b || !key.HasDestShort || key.DestinationShort != 0x1234 {
		t.Errorf("destination context = %+v", key)
	}
	if !key.HasSrcShort || key.SourceShort != 0x0000 {
		t.Errorf("source context = %+v", key)
	}
	if got, want := formatHex(key.Destination), "00124b001a2b3c4d"; got != want {
		t.Errorf("destination = %s, want %s", got, want)
	}
	if !key.HasSource {
		t.Fatal("source address not reported")
	}
	if got, want := formatHex(key.Source), "aabbccddeeff0011"; got != want {
		t.Errorf("source = %s, want %s", got, want)
	}
}

func TestExtractHighSecurityNetworkKey(t *testing.T) {
	key, ok := ExtractNetworkKey(networkKeyFrame(byte(KeyTypeHighSecurityNetwork)))
	if !ok {
		t.Fatal("ExtractNetworkKey = false, want true")
	}
	if key.KeyType != KeyTypeHighSecurityNetwork {
		t.Errorf("key type = %v, want high-security-network", key.KeyType)
	}
}

func TestExtractRejectsSecuredFrames(t *testing.T) {
	base := networkKeyFrame(byte(KeyTypeStandardNetwork))

	macSecured := append([]byte(nil), base...)
	macFCF := binary.LittleEndian.Uint16(macSecured[0:2]) | 1<<3
	binary.LittleEndian.PutUint16(macSecured[0:2], macFCF)

	nwkSecured := append([]byte(nil), base...)
	// NWK header starts after the 9-byte short MAC header. Bit 9 is the NWK
	// security bit in the ZigBee frame control field.
	nwkOff := 9
	nwkFCF := binary.LittleEndian.Uint16(nwkSecured[nwkOff:nwkOff+2]) | 0x0200
	binary.LittleEndian.PutUint16(nwkSecured[nwkOff:nwkOff+2], nwkFCF)

	apsSecured := append([]byte(nil), base...)
	apsOff := nwkOff + 8
	apsSecured[apsOff] |= 1 << 5

	for name, frame := range map[string][]byte{
		"mac": macSecured,
		"nwk": nwkSecured,
		"aps": apsSecured,
	} {
		if _, ok := ExtractNetworkKey(frame); ok {
			t.Errorf("%s secured frame accepted", name)
		}
	}
}

func TestExtractRejectsOtherKeyTypes(t *testing.T) {
	for _, keyType := range []KeyType{
		KeyTypeTrustCenterMaster,
		KeyTypeApplicationMaster,
		KeyTypeApplicationLink,
		KeyTypeTrustCenterLink,
		KeyTypeBasicAuthorization,
		KeyTypeAdminAuthorization,
	} {
		if _, ok := ExtractNetworkKey(networkKeyFrame(byte(keyType))); ok {
			t.Errorf("key type %v accepted as a network key", keyType)
		}
	}
}

func TestExtractRejectsOtherFrames(t *testing.T) {
	key := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	dst := [8]byte{0x00, 0x12, 0x4b, 0x00, 0x1a, 0x2b, 0x3c, 0x4d}

	// APS data frame rather than a command.
	dataAPS := apsTransportKey(byte(KeyTypeStandardNetwork), key, 0, dst, [8]byte{}, false)
	dataAPS[0] = 0x00

	// A different APS command.
	otherCommand := append([]byte(nil), dataAPS...)
	otherCommand[0] = 0x01
	otherCommand[2] = 0x06

	// A beacon frame rather than MAC data.
	beacon := networkKeyFrame(byte(KeyTypeStandardNetwork))
	beacon[0] = 0x00

	for name, frame := range map[string][]byte{
		"aps data":      dataAPS,
		"other command": otherCommand,
		"beacon":        beacon,
		"empty":         nil,
		"short":         {0x41, 0x88},
	} {
		if _, ok := ExtractNetworkKey(frame); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestExtractIgnoresMissingSource(t *testing.T) {
	key := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	dst := [8]byte{0x00, 0x12, 0x4b, 0x00, 0x1a, 0x2b, 0x3c, 0x4d}
	aps := apsTransportKey(byte(KeyTypeStandardNetwork), key, 0, dst, [8]byte{}, false)
	aps = aps[:len(aps)-8] // omit the source address
	frame := shortMAC(0x1a2b, 0x1234, 0x0000)
	frame = append(frame, nwkHeader(0x0008, nil)...)
	frame = append(frame, aps...)
	frame = append(frame, 0x9e, 0x80) // RSSI, LQI with CRC OK

	got, ok := ExtractNetworkKey(frame)
	if !ok {
		t.Fatal("ExtractNetworkKey = false, want true")
	}
	if got.HasSource {
		t.Error("HasSource = true with no source address in the frame")
	}
}

func TestExtractHandlesExtendedNWKHeaderFields(t *testing.T) {
	key := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	dst := [8]byte{0x00, 0x12, 0x4b, 0x00, 0x1a, 0x2b, 0x3c, 0x4d}
	aps := apsTransportKey(byte(KeyTypeStandardNetwork), key, 1, dst, [8]byte{}, false)

	tests := map[string][]byte{
		"extended addresses": nwkHeader(0x1808, bytes.Repeat([]byte{0xaa}, 16)),
		"multicast":          nwkHeader(0x0108, []byte{0x01}),
		"source route":       nwkHeader(0x0408, []byte{0x01, 0x00, 0x34, 0x12}),
	}
	for name, header := range tests {
		frame := shortMAC(0x1a2b, 0x1234, 0x0000)
		frame = append(frame, header...)
		frame = append(frame, aps...)
		frame = append(frame, 0x9e, 0x80) // RSSI, LQI with CRC OK
		if _, ok := ExtractNetworkKey(frame); !ok {
			t.Errorf("%s: ExtractNetworkKey = false", name)
		}
	}
}

func TestExtractExtendedMACAddresses(t *testing.T) {
	key := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	dst := [8]byte{0x00, 0x12, 0x4b, 0x00, 0x1a, 0x2b, 0x3c, 0x4d}
	aps := apsTransportKey(byte(KeyTypeStandardNetwork), key, 0, dst, [8]byte{}, false)
	macDst := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	macSrc := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
	frame := longMAC(0x1a2b, macDst, macSrc)
	frame = append(frame, nwkHeader(0x0008, nil)...)
	frame = append(frame, aps...)
	frame = append(frame, 0x9e, 0x80) // RSSI, LQI with CRC OK

	got, ok := ExtractNetworkKey(frame)
	if !ok {
		t.Fatal("ExtractNetworkKey = false, want true")
	}
	if got.PAN != 0x1a2b {
		t.Errorf("PAN = %#04x, want 0x1a2b", got.PAN)
	}
	if got.HasDestShort || got.HasSrcShort {
		t.Errorf("short addresses reported for extended MAC addresses: %+v", got)
	}
}

func FuzzExtractNetworkKey(f *testing.F) {
	f.Add(networkKeyFrame(byte(KeyTypeStandardNetwork)))
	f.Add(networkKeyFrame(byte(KeyTypeStandardNetwork))[:20])
	f.Add([]byte{0x41, 0x88, 0x01})
	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _ = ExtractNetworkKey(frame)
	})
}

func formatHex(addr [8]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 16)
	for _, b := range addr {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out)
}

// encryptCCM mirrors the CCM* transformation for test frames.
func encryptCCM(key [16]byte, nonce, aad, plain []byte, level uint8) (ct, mic []byte) {
	block, _ := aes.NewCipher(key[:])
	ct = append([]byte(nil), plain...)
	if Encrypted(level) {
		var counter [16]byte
		counter[0] = 1
		copy(counter[1:14], nonce)
		var stream [16]byte
		for i := 0; i < len(ct); i += aes.BlockSize {
			putUint16(counter[14:16], uint16(i/aes.BlockSize+1))
			block.Encrypt(stream[:], counter[:])
			for j := 0; j < aes.BlockSize && i+j < len(ct); j++ {
				ct[i+j] ^= stream[j]
			}
		}
	}
	micLen := MICLen(level)
	if micLen == 0 {
		return ct, nil
	}
	mac := ccmMAC(block, nonce, aad, plain, micLen)
	var a0 [16]byte
	a0[0] = 1
	copy(a0[1:14], nonce)
	var s0 [16]byte
	block.Encrypt(s0[:], a0[:])
	mic = make([]byte, micLen)
	for i := range mic {
		mic[i] = mac[i] ^ s0[i]
	}
	return ct, mic
}

// securedAPSFrame builds a Transport-Key command protected at the APS layer
// with a Trust Center link key. wireLevel is written to the frame (devices
// commonly send 0); effectiveLevel is used for the CCM* transformation.
func securedAPSFrame(tcKey [16]byte, wireLevel, effectiveLevel, keyID uint8, frameCounter uint32, extSrc [8]byte, keyType byte, networkKey [16]byte, seq byte, dst, src [8]byte) []byte {
	plain := []byte{apsCommandTransportKey, keyType}
	plain = append(plain, networkKey[:]...)
	plain = append(plain, seq)
	plain = append(plain, dst[:]...)
	plain = append(plain, src[:]...)

	control := wireLevel&0x07 | keyID<<3 | 0x20 // extended nonce
	apsHeader := []byte{0x21, 0x01, control}    // command, security, APS counter
	apsHeader = binary.LittleEndian.AppendUint32(apsHeader, frameCounter)
	apsHeader = append(apsHeader, extSrc[:]...)

	controlEff := control&^0x07 | effectiveLevel
	aad := append([]byte(nil), apsHeader...)
	aad[2] = controlEff

	var nonce [13]byte
	copy(nonce[0:8], extSrc[:])
	binary.LittleEndian.PutUint32(nonce[8:12], frameCounter)
	nonce[12] = controlEff

	encKey := tcKey
	switch keyID {
	case 2:
		encKey = keyedHash(tcKey, 0x00)
	case 3:
		encKey = keyedHash(tcKey, 0x02)
	}
	ct, mic := encryptCCM(encKey, nonce[:], aad, plain, effectiveLevel)

	frame := shortMAC(0x1a2b, 0x1234, 0x0000)
	frame = append(frame, nwkHeader(0x0008, nil)...)
	frame = append(frame, apsHeader...)
	frame = append(frame, ct...)
	frame = append(frame, mic...)
	frame = append(frame, 0x9e, 0x80) // RSSI, LQI with CRC OK
	return frame
}

func TestExtractAPSLinkKeyTransport(t *testing.T) {
	tcKey := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	netKey := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dst := [8]byte{0x00, 0x12, 0x4b, 0x00, 0x1a, 0x2b, 0x3c, 0x4d}
	src := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	extSrc := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	for _, wireLevel := range []uint8{SecEncMIC32, SecNone} {
		frame := securedAPSFrame(tcKey, wireLevel, SecEncMIC32, 0, 0x01020304, extSrc,
			byte(KeyTypeStandardNetwork), netKey, 7, dst, src)

		key, ok := ExtractNetworkKey(frame, tcKey)
		if !ok {
			t.Fatalf("wire level %d: ExtractNetworkKey = false, want true", wireLevel)
		}
		if key.Key != netKey || key.KeyType != KeyTypeStandardNetwork || key.Sequence != 7 {
			t.Errorf("wire level %d: key = %+v", wireLevel, key)
		}
		if key.PAN != 0x1a2b || !key.HasDestShort || key.DestinationShort != 0x1234 || !key.HasSrcShort || key.SourceShort != 0x0000 {
			t.Errorf("wire level %d: context = %+v", wireLevel, key)
		}
		if !key.HasSource || key.Source != src {
			t.Errorf("wire level %d: source = %x, want %x", wireLevel, key.Source, src)
		}

		if _, ok := ExtractNetworkKey(frame); ok {
			t.Errorf("wire level %d: secured frame accepted without a link key", wireLevel)
		}
		wrong := tcKey
		wrong[0] ^= 0xff
		if _, ok := ExtractNetworkKey(frame, wrong); ok {
			t.Errorf("wire level %d: secured frame accepted with the wrong link key", wireLevel)
		}
	}
}

func TestExtractAPSHighSecurityNetworkKey(t *testing.T) {
	tcKey := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	netKey := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	frame := securedAPSFrame(tcKey, 0, SecEncMIC64, 0, 99, [8]byte{9, 9, 9, 9, 9, 9, 9, 9},
		byte(KeyTypeHighSecurityNetwork), netKey, 2, [8]byte{}, [8]byte{})
	key, ok := ExtractNetworkKey(frame, tcKey)
	if !ok {
		t.Fatal("ExtractNetworkKey = false, want true")
	}
	if key.KeyType != KeyTypeHighSecurityNetwork || key.Key != netKey {
		t.Errorf("key = %+v", key)
	}
}

func TestExtractAPSKeyTransportKey(t *testing.T) {
	tcKey := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	netKey := [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	extSrc := [8]byte{0x00, 0x12, 0x4b, 0x00, 0x01, 0x6a, 0x41, 0x0c}
	frame := securedAPSFrame(tcKey, SecNone, SecEncMIC32, 2, 552963, extSrc,
		byte(KeyTypeStandardNetwork), netKey, 4, [8]byte{}, [8]byte{})

	key, ok := ExtractNetworkKey(frame, tcKey)
	if !ok {
		t.Fatal("ExtractNetworkKey = false, want true")
	}
	if key.Key != netKey || key.Sequence != 4 {
		t.Errorf("key = %+v", key)
	}
}

func TestExtractAPSKeyLoadKey(t *testing.T) {
	tcKey := [16]byte{'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}
	netKey := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	frame := securedAPSFrame(tcKey, SecNone, SecEncMIC64, 3, 7, [8]byte{8, 8, 8, 8, 8, 8, 8, 8},
		byte(KeyTypeStandardNetwork), netKey, 1, [8]byte{}, [8]byte{})

	key, ok := ExtractNetworkKey(frame, tcKey)
	if !ok {
		t.Fatal("ExtractNetworkKey = false, want true")
	}
	if key.Key != netKey {
		t.Errorf("key = %+v", key)
	}
}
