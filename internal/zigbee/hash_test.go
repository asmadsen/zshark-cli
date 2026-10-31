package zigbee

import (
	"encoding/hex"
	"testing"
)

func TestAESMMOHash(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"c0", "ae3a102a28d43ee0d4a09e22788b206c"},
		{"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", "a7977e88bc0b61e8210827109a228f2d"},
	} {
		got := aesMMOHash(mustHex(t, tc.in))
		if hex.EncodeToString(got[:]) != tc.want {
			t.Errorf("aesMMOHash(%s) = %x, want %s", tc.in, got, tc.want)
		}
	}
}

func TestKeyedHash(t *testing.T) {
	key := [16]byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}
	got := keyedHash(key, 0xc0)
	if hex.EncodeToString(got[:]) != "4512807bf94cb3400f0e2c25fb76e999" {
		t.Errorf("keyedHash = %x, want 4512807bf94cb3400f0e2c25fb76e999", got)
	}
}
