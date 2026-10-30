# JSON Lines output (`--jsonl`)

`zshark capture --jsonl FILE` writes one JSON object per IEEE 802.15.4 frame,
one object per line, with no Ethernet, IPv4, UDP or ZEP wrapping. Use `-` as
FILE to write to stdout while logging stays on stderr. Each line is flushed as
soon as it is written, so a live capture can be tailed.

Every captured 802.15.4 frame is written, including ACKs and MAC commands;
filter on `mac.type` or `nwk.type` when only NWK data frames are wanted.

This format is an alternative to `--pcap` for consumers that want the ZigBee
data directly rather than a capture file. `--pcap`, `--jsonl` and ZEP over UDP
can be enabled at the same time.

## Line format

```json
{"ts":"2026-10-30T14:53:56.403697999Z","channel":11,"seq":171,"len":55,"radio":{"rssi":-98,"lqi":0,"fcsValid":true},"data":"6188007f...","mac":{"type":"data","seq":0,"dstPan":"0xa37f","dst":"0x0000","srcPan":"0xa37f","src":"0x2d9f","ackRequest":true},"nwk":{"type":"command","dst":"0x0000","src":"0xde50","extDst":"15:5e:f5:ff:fe:23:03:49","extSrc":"a4:c1:38:b9:de:d0:57:6a","security":{"level":0,"keyId":1,"keyType":"network","frameCounter":98004254,"extSrc":"6a:42:ac:fe:ff:95:8e:dc","keySeq":0,"mic":"48f99c57"}},"decryption":{"status":"no-key","level":5}}
```

Unknown or inapplicable fields are omitted.

| Field | Meaning |
|---|---|
| `ts` | Capture timestamp, RFC 3339 with nanoseconds, UTC. |
| `channel` | ZigBee channel selected with `--channel` (11–26). |
| `seq` | ZEP sequence number assigned by zshark. |
| `len` | Length of the 802.15.4 frame in `data`, in bytes. |
| `radio.rssi` | RSSI in dBm from the sniffer's CC24xx metadata. |
| `radio.lqi` | Link quality indication (0–127). |
| `radio.fcsValid` | Whether the sniffer reported a valid FCS. |
| `data` | The 802.15.4 frame as lowercase hex, without RSSI/FCS metadata. |
| `mac` | Decoded MAC header. |
| `nwk` | Decoded ZigBee NWK header; absent when the frame has no NWK layer. |
| `decryption` | Result of applying network keys; present when NWK security is present. |

### `mac`

| Field | Meaning |
|---|---|
| `type` | `beacon`, `data`, `ack`, `command`, `reserved`, `multipurpose`, `fragment`, or `extended`. |
| `seq` | MAC sequence number, omitted when suppressed. |
| `dstPan`, `srcPan` | PAN IDs formatted as `0x1234`. |
| `dst`, `src` | Short addresses (`0x1234`) or extended addresses (`aa:bb:...`). |
| `ackRequest` | ACK request bit. |
| `security` | MAC security-enabled bit. |

### `nwk`

| Field | Meaning |
|---|---|
| `type` | `data`, `command`, `reserved`, or `interpan`. |
| `dst`, `src` | Short NWK addresses. |
| `extDst`, `extSrc` | Extended NWK addresses when the frame carries them. |
| `security` | Auxiliary security header, when the NWK security bit is set. |

### `nwk.security`

`level` is the level **as transmitted**. ZigBee devices commonly transmit `0`
even for encrypted frames; the level used for decryption is reported in
`decryption.level` (see below).

| Field | Meaning |
|---|---|
| `level` | Transmitted security level (0–7). |
| `keyId` | Key identifier: 0 link, 1 network, 2 transport, 3 load. |
| `keyType` | `link`, `network`, `transport`, or `load`. |
| `frameCounter` | Security frame counter. |
| `extSrc` | Extended source address from the auxiliary header, most-significant byte first. |
| `keySeq` | Network key sequence number. |
| `mic` | MIC bytes as lowercase hex, sized by the decryption level. |

### `decryption`

`--network-key HEX` supplies one or more 16-byte ZigBee network keys. Keys are
tried in order and only network-key frames are decrypted. Key material is
never written to the output.

`--security-level N` selects the level used to interpret the security header
(0–7; default 5, AES-128 encryption with a 32-bit MIC). Like Wireshark, zshark
uses this configured level instead of the level bits in the header because
those bits are commonly zero even on encrypted networks.

| `status` | Meaning |
|---|---|
| `ok` | A key verified the MIC; `payload` is the decrypted NWK payload. |
| `no-key` | The frame is secured but no key was supplied. |
| `failed` | Keys were supplied, but none verified the MIC. |
| `unsupported-key` | The frame uses a link, transport, or load key rather than a network key. |
| `no-security` | `--security-level 0` was selected, so no decryption was attempted. |

`keyIndex` is the zero-based index of the matching `--network-key`, when one
matched. `payload` is the decrypted NWK payload as lowercase hex; for
integrity-only levels it is the unchanged plaintext payload. The payload is
normally an APS frame, which zshark does not parse further.

Decryption needs the sender's 64-bit address as the CCM* nonce. zshark takes it
from the auxiliary header's extended nonce, or from the NWK extended source
address when the extended nonce is absent. It does not keep a short-to-extended
address map, so a frame carrying neither cannot be decrypted.

## Examples

```sh
# Capture to a JSONL file with no UDP output.
zshark capture --no-zep --jsonl zigbee.jsonl

# Write JSONL to stdout and decrypt with a network key.
zshark capture --no-zep --jsonl - \
  --network-key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff

# Try a key and a different security level (AES-128 + 64-bit MIC).
zshark capture --no-zep --jsonl zigbee.jsonl \
  --network-key 00112233445566778899aabbccddeeff \
  --security-level 6

# Show decrypted payloads, one per line.
jq -r 'select(.decryption.status == "ok") | .decryption.payload' zigbee.jsonl

# Show only NWK data frames and their addresses.
jq -r 'select(.nwk.type == "data") | [.nwk.src, .nwk.dst] | @tsv' zigbee.jsonl
```

## Metadata and the raw frame

The dongle appends two CC24xx bytes to each 802.15.4 frame: RSSI and an
FCS-valid/LQI byte. ZEP carries those bytes in LQI/CRC mode (mode 0); Wireshark
removes them before dissecting. `--jsonl` does the same: `data` is the actual
802.15.4 frame and the two bytes are exposed as `radio.rssi`, `radio.lqi`, and
`radio.fcsValid`. In CRC mode (mode 1) the last two bytes are a CRC and are
also removed, but no `radio` object is emitted.
