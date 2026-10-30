# Wire protocol (reverse-engineered)

Source: `/usr/bin/zshark` 1.00.06 (ELF32 armhf, unstripped) and a real ConBee II
capture in `/tmp/opencode/zshark/zep-sample.pcap`. Symbols referenced below are
from the shipped binary.

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
containing `Sniffer` as success; treat `fail` or silence beyond ~2 s as failure.

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
strips them in ZEP LQI mode, and the JSONL sink exposes them as
`radio.rssi`/`radio.lqi`/`radio.fcsValid`. **Observed** (real capture and live
pty replay: every frame ended with `XX 80`, where `0x80` is FCS-valid and LQI
0).

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
