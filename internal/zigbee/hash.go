package zigbee

import "crypto/aes"

// aesMMOHash implements the AES-MMO-128 hash from ZigBee specification
// B.1.3/B.4. Inputs are short (the keyed hash feeds 17 and 32 bytes), so the
// 16-bit length field is sufficient.
func aesMMOHash(data []byte) [16]byte {
	padded := make([]byte, 0, len(data)+17)
	padded = append(padded, data...)
	padded = append(padded, 0x80)
	for len(padded)%aes.BlockSize != 14 {
		padded = append(padded, 0)
	}
	bitLen := uint16(len(data) * 8)
	padded = append(padded, byte(bitLen>>8), byte(bitLen))

	var digest [16]byte
	for i := 0; i < len(padded); i += aes.BlockSize {
		block, _ := aes.NewCipher(digest[:])
		var enc [16]byte
		block.Encrypt(enc[:], padded[i:i+aes.BlockSize])
		for j := range digest {
			digest[j] = enc[j] ^ padded[i+j]
		}
	}
	return digest
}

// keyedHash implements the ZigBee keyed hash (HMAC construction over
// AES-MMO), used to derive Key-Transport and Key-Load keys from a link key.
func keyedHash(key [16]byte, input byte) [16]byte {
	var inner [17]byte
	for i := range key {
		inner[i] = key[i] ^ 0x36
	}
	inner[16] = input

	var outer [32]byte
	for i := range key {
		outer[i] = key[i] ^ 0x5c
	}
	h := aesMMOHash(inner[:])
	copy(outer[16:], h[:])
	return aesMMOHash(outer[:])
}
