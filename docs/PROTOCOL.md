# Wire protocol (reverse-engineered)

Source: `/usr/bin/zshark` 1.00.06 (ELF32 armhf, unstripped) and a real ConBee II
capture in `/tmp/opencode/zshark/zep-sample.pcap`. Symbols referenced below are
from the shipped binary. These paths are build-host provenance, not runtime
dependencies; the sample-based tests skip when the capture is absent.

Confidence markers: **observed** = seen in a capture or decoded from code;
**inferred** = best reading of disassembly; **unconfirmed** = must be validated.

## 1. Serial link

- 38400 baud, 8 data bits, no parity, 1 stop bit, no flow control
  (`Connection::openSerialPort` at `0x278e8`). **Observed**
- ConBee II appears as a USB CDC-ACM device (`1cf1:0030`), Linux `/dev/ttyACM*`.
  **Observed**

## 2. Text commands (host → dongle)

Commands are ASCII, framed with a leading and trailing `\n`:

| Purpose | Bytes | Evidence |
|---|---|---|
| Stop sniffing / idle | `\nidle\n` | `Connection::sendParameter`, `0x258cc` |
| Start sniffing | `\nsniff\n` | same |
| Set channel | `\nchan <n>\n` | `Connection::sendU8Parameter`, `0x25904` |
| Query parameters / banner | `\nparms\n` | `openSerialPort` writes it after `idle` |

On open the app sends `\nidle\n` then `\nparms\n`. **Observed**

### Text replies (dongle → host)

The firmware (`sniffer_v1_0.bin`) contains these formats:

- `Sniffer V%s [%s]` — banner with version and platform
- `Channel %u`, `IDLE`
- `fail` / `fail!` — invalid state or command; the app treats this as
  “no or wrong firmware” and offers to flash

Unknown: exact ConBee II banner string and startup timing. Treat any banner
containing `Sniffer` as success; treat `fail` or silence beyond ~2 s per
handshake attempt as failure. The CLI retries the handshake a few times because
a freshly opened CDC port can reset the dongle or still be draining frames.

### Stock ConBee II response (measured live)

The stock ConBee II (deCONZ firmware, `DE2490137`, reported `ConBee2 V2.0`) does
not emit a `Sniffer` banner. It echoes each command as `> <cmd>\r\n`, then
answers. `OK` is not newline-terminated:

```
> idle
OK
> parms

PLATFORM: ConBee2 V2.0
CURR_CMSK: 0x07fff800
CURR_CHAN: 11

OK
> chan 15
OK
> sniff
Receiving...OK
```

The CLI accepts either a `Sniffer` banner or a line containing `PLATFORM:` as
success. **Observed** (live, 2026-10-30).

## 3. Binary frame envelope (dongle → host)

`Connection::readData` at `0x24f50` is a byte-oriented state machine:

```
0x01  LEN  PAYLOAD[LEN]  0x04
```

- `0x01` starts a frame. **Observed in code**
- `LEN` is one byte; exactly `LEN` payload bytes follow. **Inferred**
- `0x04` terminates the frame and is consumed. **Observed in code**

Text lines (banner, `Channel …`, `IDLE`, `fail`) can appear interleaved with
binary frames, so the parser must treat any non-`0x01` byte as text until the
next `0x01`.

### PAYLOAD layout

The payload starts with a fixed 8-byte header followed by the raw 802.15.4
frame. On the live ConBee II the header is always `01 02 03 04 05 06 07 08`,
regardless of the selected channel: 18 frames captured on channels 11 and 15
all carried it, and byte 4 was constant `0x05`. It therefore does not encode
the channel (and `0x05` is not a valid 802.15.4 channel). The channel is
host-side state — the GUI's selected channel, or `--channel` — and belongs in
the ZEP header. **Observed** (live, 2026-10-30)

Offset 8 is confirmed by the frame control field at the start of the raw frame:
`02 00` (ACK) and `41 88`/`61 88` (data frames with PAN compression and
extended source addresses) are all sane. **Observed**

The final two bytes of the raw frame are not 802.15.4 data: the sniffer appends
ChipCon/TI CC24xx metadata (`RSSI`, then an FCS-valid bit plus LQI). Wireshark
interprets the last two bytes of a ZEP frame the same way, which is why its
dissection reports `FCS OK`/`FCS Bad` even though the dongle never sends the
real FCS. Protocol decoders must therefore parse forward from the start of the
frame and must not assume the final byte belongs to the MAC payload. The JSONL
sink exposes the bytes as `radio.rssi`/`radio.lqi`/`radio.fcsValid`.
**Observed** (real capture 31/31 frames and live pty replay: every frame ended
with `XX 80`, where `0x80` is FCS-valid and LQI 0).

The earlier reading that `PAYLOAD[4]` is the channel came from the sample ZEP
header, not from the serial stream; that datagram was built by the GUI from its
own channel setting.

## 4. ZEP v2 datagrams (host → Wireshark)

One UDP datagram per frame, destination port **17754**. **Observed**

32-byte header, then the 802.15.4 frame:

| Offset | Size | Field | Sample |
|---|---|---|---|
| 0 | 2 | magic `EX` | `45 58` |
| 2 | 1 | version = 2 | `02` |
| 3 | 1 | type = 1 (data) | `01` |
| 4 | 1 | channel | `0b` |
| 5 | 2 | device code (BE) | `00 00` |
| 7 | 1 | LQI/CRC mode (0 = LQI) | `00` |
| 8 | 1 | LQI | `00` |
| 9 | 8 | NTP timestamp (BE, seconds since 1900 + 32-bit fraction) | varies |
| 17 | 4 | sequence number (BE) | `00 00 00 ab` |
| 21 | 10 | reserved, zero | `00 ×10` |
| 31 | 1 | frame length, low 7 bits | `39` |

> Correction after validating against the real sample: an earlier revision of
> this table omitted the LQI/CRC mode byte and described the timestamp as a
> pair of Unix seconds/microseconds. Wireshark's ZEP dissector uses the layout
> above: byte 7 is the mode, byte 8 the LQI, bytes 9–16 the 64-bit NTP
> timestamp, and byte 31 the 7-bit frame length. The sample's first data frame
> is `45 58 02 01 0b 00 00 00 00 ee 8f 2e 04 67 58 c0 8b 00 00 00 ab ... 39`;
> its NTP timestamp decodes to 2026-10-30T14:53:56.403697999Z and its sequence
> to 171, matching Wireshark.

The sample also contains short 8-byte type-2 datagrams (`EX 02 02` + 4-byte
sequence) at capture start. They are acknowledgements and can be ignored for v0.

Wireshark decodes the capture as `ZEPv2 -> ZigBee` with
`tshark -r zep-sample.pcap -Y zep`.

## 5. Capture file output

The original does not write files; the sample pcap was produced by wrapping the
ZEP datagrams in synthetic Ethernet/IPv4/UDP headers. Do the same for pcapng:

- pcapng SHB + IDB (link type 1, Ethernet) + one EPB per frame.
- Ethernet II → IPv4 (proto 17) → UDP (src 48311, dst 17754) → ZEP payload.
- Compute the IPv4 header checksum; leave the UDP checksum 0 (allowed for IPv4).
- Timestamps from the ZEP header.

This lets `zshark capture --no-zep --pcap out.pcapng` work with no listener.

An alternative, `--jsonl FILE`, writes one JSON object per 802.15.4 frame with
no capture plumbing, and can decrypt NWK-secured payloads with `--network-key`.
See [JSONL.md](JSONL.md).

## 6. Device discovery

The original uses `deCONZ::DeviceEnumerator` plus `QSerialPortInfo`. For v0:

- Linux: `/dev/ttyACM*`; prefer the port whose USB IDs are `1cf1:0030`.
- macOS: `/dev/tty.usbmodem*` and `/dev/cu.usbmodem*`.
- Always allow an explicit `--port`.

## 7. Network key transport (sniffer aid)

When a device is adopted, the Trust Center sends it the network key in an APS
Transport-Key command. The command normally sits inside an APS frame that is
protected by the Trust Center Link Key, but while adopting a device it can be
sent with APS security disabled, which leaves the key readable on air. The
`keys` command decodes exactly that case.

Frame path for an unsecured transport (all fields **observed** in Wireshark for
a synthetic frame built from the formats below):

```
802.15.4 data frame
  MAC header (PAN ID, addresses)
  NWK data frame (security bit clear)
    APS command frame (security bit clear)
      Frame control       0x01
      APS counter         1 byte
      Command identifier  0x05 (Transport Key)
      Key type            0x01 standard network, 0x05 high-security network
      Key                 16 bytes
      Key sequence        1 byte
      Destination EUI-64  8 bytes, little endian on the wire
      Source EUI-64       8 bytes, little endian on the wire
```

Wireshark's field names are `zbee_aps.cmd.id == 0x05`,
`zbee_aps.cmd.key_type` (0x01 = Standard Network Key, 0x05 = High-Security
Network Key), `zbee_aps.cmd.key`, `zbee_aps.cmd.seqno`, `zbee_aps.cmd.dst` and
`zbee_aps.cmd.src`. This descriptor order (key, sequence, destination, source)
matches Wireshark and differs from the order in some older spec excerpts.

`internal/zigbee` parses the MAC, NWK and APS headers only far enough to find
this command. It rejects frames secured at any layer, other key types and
malformed/truncated frames. Because the commands are unencrypted, no keys are
stored or used to decrypt anything; the tool only reports what was already in
clear on the selected channel.
