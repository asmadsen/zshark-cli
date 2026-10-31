package zigbee

import (
	"encoding/hex"
	"testing"
)

// The vectors below were generated independently with a CCM* reference
// implementation and cross-checked against AES-CCM (pycryptodome) for the
// encrypted levels. The authenticated data is the NWK header followed by the
// auxiliary security header, as ZigBee specifies.
var ccmVectors = []struct {
	level uint8
	mic   int
	aad   string
	nonce string
	ct    string
	mic16 string
}{
	{SecMIC32, 4, "0802000034121e2a0104030201dc8e95fffeac426a00", "dc8e95fffeac426a0403020101", "00112233445566778899", "73093c2b"},
	{SecMIC64, 8, "0802000034121e2a0204030201dc8e95fffeac426a00", "dc8e95fffeac426a0403020102", "00112233445566778899", "cf96ae8d1d2dc684"},
	{SecMIC128, 16, "0802000034121e2a0304030201dc8e95fffeac426a00", "dc8e95fffeac426a0403020103", "00112233445566778899", "58347ea9b8b3968d8865aacf10219365"},
	{SecEnc, 0, "0802000034121e2a0404030201dc8e95fffeac426a00", "dc8e95fffeac426a0403020104", "0e06358bb420b98095cc", ""},
	{SecEncMIC32, 4, "0802000034121e2a0504030201dc8e95fffeac426a00", "dc8e95fffeac426a0403020105", "d84e73b2721a271b61f4", "34982c1d"},
	{SecEncMIC64, 8, "0802000034121e2a0604030201dc8e95fffeac426a00", "dc8e95fffeac426a0403020106", "31c0ef4de9dbf1703b1a", "b0d9dae992d354e7"},
	{SecEncMIC128, 16, "0802000034121e2a0704030201dc8e95fffeac426a00", "dc8e95fffeac426a0403020107", "571278f3b9e68c827ffe", "d15fda0837cf5031725050aa6bb26b73"},
}

var testKey = [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
var testPlain = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}

func TestCCMStarDecrypt(t *testing.T) {
	for _, tc := range ccmVectors {
		aad := mustHex(t, tc.aad)
		nonce := mustHex(t, tc.nonce)
		ct := mustHex(t, tc.ct)
		mic := mustHex(t, tc.mic16)
		plain, ok := ccmStarDecrypt(testKey[:], nonce, aad, ct, mic, tc.level)
		if !ok {
			t.Errorf("level %d: decryption failed", tc.level)
			continue
		}
		if string(plain) != string(testPlain) {
			t.Errorf("level %d: plaintext = %x, want %x", tc.level, plain, testPlain)
		}

		// A single flipped MIC byte must be rejected.
		bad := append([]byte(nil), mic...)
		if len(bad) > 0 {
			bad[0] ^= 0x80
			if _, ok := ccmStarDecrypt(testKey[:], nonce, aad, ct, bad, tc.level); ok {
				t.Errorf("level %d: bad MIC accepted", tc.level)
			}
		}
	}
}

func TestCCMStarWrongKey(t *testing.T) {
	tc := ccmVectors[4]
	key := testKey
	key[0] ^= 0xff
	if _, ok := ccmStarDecrypt(key[:], mustHex(t, tc.nonce), mustHex(t, tc.aad),
		mustHex(t, tc.ct), mustHex(t, tc.mic16), tc.level); ok {
		t.Fatal("decryption with wrong key succeeded")
	}
}

func TestParseKey(t *testing.T) {
	for _, s := range []string{
		"00112233445566778899aabbccddeeff",
		"00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
		"0011-2233-4455-6677-8899-aabb-ccdd-eeff",
		"0x00112233445566778899aabbccddeeff",
	} {
		key, err := ParseKey(s)
		if err != nil {
			t.Errorf("ParseKey(%q) = %v", s, err)
			continue
		}
		if key != testKey {
			t.Errorf("ParseKey(%q) = %x", s, key)
		}
	}
	for _, s := range []string{"", "00", "00112233445566778899aabbccddee", "00112233445566778899aabbccddeefg"} {
		if _, err := ParseKey(s); err == nil {
			t.Errorf("ParseKey(%q) accepted", s)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}
