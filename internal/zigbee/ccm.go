// Package zigbee decodes IEEE 802.15.4 and ZigBee NWK headers and decrypts
// NWK-secured payloads with a network key.
package zigbee

import (
	"crypto/aes"
	"crypto/subtle"
	"fmt"
)

// Security levels from the ZigBee auxiliary security header. The level selects
// encryption and the MIC length.
const (
	SecNone      = 0 // no encryption, no MIC
	SecMIC32     = 1 // no encryption, 4-byte MIC
	SecMIC64     = 2 // no encryption, 8-byte MIC
	SecMIC128    = 3 // no encryption, 16-byte MIC
	SecEnc       = 4 // encryption, no MIC
	SecEncMIC32  = 5 // encryption, 4-byte MIC
	SecEncMIC64  = 6 // encryption, 8-byte MIC
	SecEncMIC128 = 7 // encryption, 16-byte MIC
)

// MICLen returns the MIC length for a ZigBee security level.
func MICLen(level uint8) int {
	switch level & 0x07 {
	case SecMIC32, SecEncMIC32:
		return 4
	case SecMIC64, SecEncMIC64:
		return 8
	case SecMIC128, SecEncMIC128:
		return 16
	default:
		return 0
	}
}

// Encrypted reports whether a security level encrypts the NWK payload.
func Encrypted(level uint8) bool {
	return (level & 0x07) >= SecEnc
}

// ccmStarDecrypt reverses the ZigBee CCM* transformation for a payload and
// verifies its MIC. Encryption levels 4-7 produce plaintext; integrity-only
// levels 1-3 return the unchanged payload after a successful MIC check.
func ccmStarDecrypt(key, nonce, aad, payload, mic []byte, level uint8) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil || len(nonce) != 13 {
		return nil, false
	}

	micLen := MICLen(level)
	if micLen != len(mic) {
		return nil, false
	}

	out := make([]byte, len(payload))
	copy(out, payload)

	// CCM* runs the payload through CTR mode whenever encryption is enabled.
	if Encrypted(level) && len(out) > 0 {
		var counter [16]byte
		counter[0] = 1 // L-1, L = 2
		copy(counter[1:14], nonce)
		var stream [16]byte
		for i := 0; i < len(out); i += aes.BlockSize {
			putUint16(counter[14:16], uint16(i/aes.BlockSize+1))
			block.Encrypt(stream[:], counter[:])
			n := len(out) - i
			if n > aes.BlockSize {
				n = aes.BlockSize
			}
			for j := 0; j < n; j++ {
				out[i+j] ^= stream[j]
			}
		}
	}

	if micLen == 0 {
		return out, true
	}

	// The MIC is the CBC-MAC tag XORed with the A0 key stream.
	var a0 [16]byte
	a0[0] = 1
	copy(a0[1:14], nonce)
	var s0 [16]byte
	block.Encrypt(s0[:], a0[:])

	want := ccmMAC(block, nonce, aad, out, micLen)
	for i := range want {
		want[i] ^= s0[i]
	}
	if subtle.ConstantTimeCompare(want, mic) != 1 {
		return nil, false
	}
	return out, true
}

// ccmMAC computes the CCM* CBC-MAC over B0, the additional authenticated data
// and the (plaintext) payload. The result is the unencrypted tag T.
func ccmMAC(block interface {
	Encrypt(dst, src []byte)
}, nonce, aad, payload []byte, micLen int) []byte {
	var b0 [16]byte
	flags := byte(1) // L = 2, so L-1 = 1
	if micLen > 0 {
		flags |= byte((micLen-2)/2) << 3
	}
	if len(aad) > 0 {
		flags |= 0x40
	}
	b0[0] = flags
	copy(b0[1:14], nonce)
	putUint16(b0[14:16], uint16(len(payload)))

	var x [16]byte
	block.Encrypt(x[:], b0[:])

	mac := cbcMAC{block: block, x: x}
	if len(aad) > 0 {
		var length [2]byte
		putUint16(length[:], uint16(len(aad)))
		mac.write(length[:])
		mac.write(aad)
		mac.pad()
	}
	mac.write(payload)
	mac.pad()
	return mac.x[:micLen]
}

type cbcMAC struct {
	block interface {
		Encrypt(dst, src []byte)
	}
	x   [16]byte
	buf [16]byte
	n   int
}

func (m *cbcMAC) write(p []byte) {
	for len(p) > 0 {
		n := copy(m.buf[m.n:], p)
		m.n += n
		p = p[n:]
		if m.n == aes.BlockSize {
			m.flush()
		}
	}
}

func (m *cbcMAC) pad() {
	if m.n == 0 {
		return
	}
	for i := m.n; i < aes.BlockSize; i++ {
		m.buf[i] = 0
	}
	m.flush()
}

func (m *cbcMAC) flush() {
	for i := range m.buf {
		m.buf[i] ^= m.x[i]
	}
	m.block.Encrypt(m.x[:], m.buf[:])
	m.n = 0
}

func putUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

// ParseKey accepts 16 bytes written as 32 hexadecimal digits, optionally
// separated by ':', '-', or spaces and optionally prefixed with "0x".
func ParseKey(s string) ([16]byte, error) {
	var key [16]byte
	digits := make([]byte, 0, 32)
	t := s
	if len(t) >= 2 && (t[0:2] == "0x" || t[0:2] == "0X") {
		t = t[2:]
	}
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case ':', '-', ' ', '\t':
			continue
		}
		digits = append(digits, t[i])
	}
	if len(digits) != 32 {
		return key, fmt.Errorf("key must be 16 bytes (32 hex digits), got %d hex digits", len(digits))
	}
	for i := 0; i < 16; i++ {
		hi, ok := hexNibble(digits[2*i])
		if !ok {
			return key, fmt.Errorf("network key contains non-hex character %q", digits[2*i])
		}
		lo, ok := hexNibble(digits[2*i+1])
		if !ok {
			return key, fmt.Errorf("network key contains non-hex character %q", digits[2*i+1])
		}
		key[i] = hi<<4 | lo
	}
	return key, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
