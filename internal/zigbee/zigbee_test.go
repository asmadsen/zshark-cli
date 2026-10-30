package zigbee

import (
	"encoding/hex"
	"testing"
)

// testWire is the frame from the CCM test vector. Its auxiliary header says
// security level 0, which is what ZigBee devices commonly transmit; decryption
// uses the configured level (5 by default).
const testWire = "6188012b1a000034120802000034121e2a2804030201dc8e95fffeac426a00aeb3b0a5f4788d9c9225d771bbdc"

// sampleWire is the first secured frame from the real ConBee II capture. Its
// NWK key is unknown, so only header decoding is asserted.
const sampleWire = "6188007fa300009f2d091a000050de1e92490323fefff55e156a57d0deb938c1a4281e6dd7056a42acfeff958edc00ea0b75df48f99c57"

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
	if sec.MIC != "d771bbdc" {
		t.Errorf("MIC = %q, want d771bbdc", sec.MIC)
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
	if frame.NWK.Security.MIC != "d771bbdc" {
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
