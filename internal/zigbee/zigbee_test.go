package zigbee

import (
	"encoding/hex"
	"testing"
)

// testWire is the frame from the CCM test vector. Its auxiliary header says
// security level 0, which is what ZigBee devices commonly transmit; decryption
// uses the configured level (5 by default).
const testWire = "6188012b1a000034120802000034121e2a2804030201dc8e95fffeac426a00aeb3b0a5f4788d9c9225217dd486"

// sampleWire is the first secured frame from the real ConBee II capture. Its
// NWK key is unknown, so only header decoding is asserted.
const sampleWire = "6188007fa300009f2d091a000050de1e92490323fefff55e156a57d0deb938c1a4281e6dd7056a42acfeff958edc00ea0b75df48f99c57"

// realSecureFrame is a real network-secured frame with a known network key.
// The plaintext ends in the ASCII text "HTB{Z1gB33_N3tw0rk_K3y_3xtr4ct3d}".
// It guards the CCM* authenticated-data boundary: ZigBee authenticates the NWK
// header and auxiliary header, not the MAC header.
const realSecureFrame = "6188012b1a00003412" +
	"0812000015000a071500000000000000" +
	"2d01000000150000000000000000" +
	"cb79821ab489734bc60b533b53b7a913041efdc992d156161ecea28c1f905920" +
	"b63b6ca0348b4f689b51f16fc781e72f98" +
	"f6572b06"

const realSecurePlain = "400101000004010718010105000042214854427b5a31674233335f4e33747730726b5f4b33795f3378747234637433647d"

func TestParseAndDecrypt(t *testing.T) {
	frame, err := Parse(mustHex(t, testWire))
	if err != nil {
		t.Fatal(err)
	}
	if frame.MAC.Type != "data" || frame.MAC.Seq == nil || *frame.MAC.Seq != 1 {
		t.Errorf("MAC = %+v", frame.MAC)
	}
	if frame.MAC.DstPAN != "0x1a2b" || frame.MAC.Dst != "0x0000" ||
		frame.MAC.SrcPAN != "0x1a2b" || frame.MAC.Src != "0x1234" || !frame.MAC.AckRequest {
		t.Errorf("MAC = %+v", frame.MAC)
	}
	if frame.NWK == nil || frame.NWK.Type != "data" ||
		frame.NWK.Dst != "0x0000" || frame.NWK.Src != "0x1234" {
		t.Fatalf("NWK = %+v", frame.NWK)
	}
	sec := frame.NWK.Security
	if sec == nil {
		t.Fatal("NWK security header missing")
	}
	if sec.Level != 0 || sec.KeyID != 1 || sec.KeyType != "network" ||
		sec.FrameCounter != 0x01020304 || sec.KeySeq != 0 {
		t.Errorf("security = %+v", sec)
	}
	if sec.ExtSrc != "dc:8e:95:ff:fe:ac:42:6a" {
		t.Errorf("extended source = %q", sec.ExtSrc)
	}

	dec := frame.Decrypt([][16]byte{testKey}, SecEncMIC32)
	if dec == nil || dec.Status != DecryptOK {
		t.Fatalf("decryption = %+v", dec)
	}
	if dec.KeyIndex == nil || *dec.KeyIndex != 0 || dec.Level != SecEncMIC32 {
		t.Errorf("decryption = %+v", dec)
	}
	if dec.Payload != hex.EncodeToString(testPlain) {
		t.Errorf("payload = %q, want %x", dec.Payload, testPlain)
	}
	if sec.MIC != "217dd486" {
		t.Errorf("MIC = %q, want 217dd486", sec.MIC)
	}
}

func TestDecryptWithoutKeys(t *testing.T) {
	frame, err := Parse(mustHex(t, testWire))
	if err != nil {
		t.Fatal(err)
	}
	dec := frame.Decrypt(nil, SecEncMIC32)
	if dec == nil || dec.Status != DecryptNoKey {
		t.Fatalf("decryption = %+v", dec)
	}
	if dec.Payload != "" {
		t.Errorf("payload = %q, want empty", dec.Payload)
	}
	if frame.NWK.Security.MIC != "217dd486" {
		t.Errorf("MIC = %q", frame.NWK.Security.MIC)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	frame, err := Parse(mustHex(t, testWire))
	if err != nil {
		t.Fatal(err)
	}
	key := testKey
	key[15] ^= 0xff
	dec := frame.Decrypt([][16]byte{key}, SecEncMIC32)
	if dec == nil || dec.Status != DecryptFailed {
		t.Fatalf("decryption = %+v", dec)
	}
}

func TestParseRealSampleFrame(t *testing.T) {
	frame, err := Parse(mustHex(t, sampleWire))
	if err != nil {
		t.Fatal(err)
	}
	if frame.MAC.DstPAN != "0xa37f" || frame.MAC.Dst != "0x0000" ||
		frame.MAC.SrcPAN != "0xa37f" || frame.MAC.Src != "0x2d9f" {
		t.Errorf("MAC = %+v", frame.MAC)
	}
	if frame.NWK == nil || frame.NWK.Type != "command" {
		t.Fatalf("NWK = %+v", frame.NWK)
	}
	if frame.NWK.ExtDst != "15:5e:f5:ff:fe:23:03:49" {
		t.Errorf("extended destination = %q", frame.NWK.ExtDst)
	}
	if frame.NWK.ExtSrc != "a4:c1:38:b9:de:d0:57:6a" {
		t.Errorf("extended source = %q", frame.NWK.ExtSrc)
	}
	sec := frame.NWK.Security
	if sec == nil {
		t.Fatal("security header missing")
	}
	if sec.Level != 0 || sec.KeyID != 1 || sec.FrameCounter != 98004254 ||
		sec.ExtSrc != "6a:42:ac:fe:ff:95:8e:dc" || sec.KeySeq != 0 {
		t.Errorf("security = %+v", sec)
	}
	dec := frame.Decrypt([][16]byte{testKey}, SecEncMIC32)
	if dec == nil || dec.Status != DecryptFailed {
		t.Fatalf("decryption = %+v", dec)
	}
	if sec.MIC != "48f99c57" {
		t.Errorf("MIC = %q, want 48f99c57", sec.MIC)
	}
}

func TestDecryptRealNetworkFrame(t *testing.T) {
	key, err := ParseKey("99df0108b1c4d6ad38cdc2fc078661a2")
	if err != nil {
		t.Fatal(err)
	}
	frame, err := Parse(mustHex(t, realSecureFrame))
	if err != nil {
		t.Fatal(err)
	}
	if frame.NWK == nil || frame.NWK.Security == nil {
		t.Fatal("NWK security header missing")
	}
	if frame.NWK.Security.KeyID != 1 || frame.NWK.Security.KeyType != "network" {
		t.Errorf("security = %+v", frame.NWK.Security)
	}
	dec := frame.Decrypt([][16]byte{key}, SecEncMIC32)
	if dec == nil || dec.Status != DecryptOK {
		t.Fatalf("decryption = %+v", dec)
	}
	if dec.Payload != realSecurePlain {
		t.Errorf("payload = %s, want %s", dec.Payload, realSecurePlain)
	}
	if frame.NWK.Security.MIC != "f6572b06" {
		t.Errorf("MIC = %q, want f6572b06", frame.NWK.Security.MIC)
	}
}

func TestParseAck(t *testing.T) {
	// ACK frames carry no NWK header.
	frame, err := Parse([]byte{0x02, 0x00, 0x2c})
	if err != nil {
		t.Fatal(err)
	}
	if frame.MAC.Type != "ack" || frame.NWK != nil {
		t.Errorf("frame = %+v", frame)
	}
}

func TestParseTruncated(t *testing.T) {
	for _, raw := range [][]byte{nil, {0x01}, {0x61, 0x88, 0x01, 0x2b}} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%x) succeeded", raw)
		}
	}
}
