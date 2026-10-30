# zshark-cli

A headless, cross-platform reimplementation of the ZSHARK ZigBee sniffer in Go.

ZSHARK is a Qt GUI that reads 802.15.4 frames from a dresden elektronik ConBee
over a serial port and forwards them to Wireshark as ZEP v2 datagrams on UDP
17754. This project keeps the capture path and drops the GUI, X11 and VNC.

## Scope (v0)

- ConBee II on USB CDC-ACM (`1cf1:0030`, `/dev/ttyACM*`, macOS `tty.usbmodem*`).
- Channel selection 11–26, start/stop sniffing.
- ZEP v2 to a configurable UDP destination (default `127.0.0.1:17754`).
- Optional direct capture file (pcapng) that opens in Wireshark without a listener.
- Optional JSON Lines output with only ZigBee data, plus network-key
  decryption of NWK-secured payloads.
- Linux and macOS; no cgo, no system daemons.

Out of scope for now: firmware detection/flashing, ConBee I (FTDI) and RaspBee,
live channel switching, Windows.

## Command line

```
zshark list [--json]
zshark capture [--port PATH] [--channel N] [--dest IP:PORT]
               [--pcap FILE] [--jsonl FILE] [--network-key HEX]
               [--security-level N] [--no-zep] [--verbose]
```

- `list` prints candidate ports; `--json` emits the same data as an array.
  Port discovery prefers a ConBee II (`1cf1:0030`) when the USB IDs are readable.
- `--port` is auto-detected when omitted and always wins when given.
- `--channel` defaults to 11 and must be in 11–26.
- `--dest` defaults to `127.0.0.1:17754`.
- `--pcap` writes a pcapng file with synthetic Ethernet/IPv4/UDP framing so
  Wireshark dissects `zep -> zigbee` directly. The file is usable while the
  capture is still running.
- `--jsonl` writes one JSON object per 802.15.4 frame, without any capture
  plumbing (no Ethernet/IPv4/UDP/ZEP). Use `-` for stdout. See
  [docs/JSONL.md](docs/JSONL.md).
- `--network-key` supplies a ZigBee network key for `--jsonl` decryption.
  Repeat it to try several keys. Keys are 16 bytes of hex with optional `:`,
  `-`, or space separators.
- `--security-level` is the ZigBee security level used for decryption (0–7,
  default 5: AES-128 encryption with a 32-bit MIC). ZigBee devices commonly
  transmit level 0 in the auxiliary header, so this is configured out of band,
  as Wireshark does.
- `--no-zep` disables UDP output (requires `--pcap` or `--jsonl`).
- `--verbose` logs serial commands, dongle text and per-frame metadata. Frame
  payloads are never printed.
- Ctrl-C or SIGTERM sends `idle` to the dongle, closes the sink(s), prints a
  packet/error summary to stderr and exits cleanly.

Exit codes: `0` success, `1` runtime/file/socket error, `2` usage error,
`3` serial device unavailable, `4` dongle firmware/banner failure.

On startup the tool sends `idle` and `parms`, waits up to two seconds for a
banner (`Sniffer V...` from the dedicated sniffer firmware, or
`PLATFORM: ConBee2 ...` from the stock ConBee II firmware), then sends
`chan <n>` and `sniff`. After a serial
disconnect it re-enumerates an auto-detected port and reconnects with
exponential backoff; UDP send failures reconnect with backoff while dropped
packets are counted.

## Layout

```
cmd/zshark/            CLI entry point and flags
internal/serialport/   port enumeration and open (cross-platform)
internal/proto/        dongle text commands and 0x01/len/payload/0x04 framing
internal/zep/          ZEP v2 header construction
internal/zigbee/       802.15.4/NWK decoding and CCM* decryption
internal/sink/         UDP, pcapng and JSONL sinks
docs/PROTOCOL.md       reverse-engineered wire protocol
docs/JSONL.md          JSON Lines output format
```

## Build and test

```
go build -o zshark ./cmd/zshark
go test ./...
go vet ./...
gofmt -l .
GOOS=darwin GOARCH=arm64 go build -o zshark-darwin-arm64 ./cmd/zshark
GOOS=darwin GOARCH=amd64 go build -o zshark-darwin-amd64 ./cmd/zshark
```

Tests cover envelope framing and resynchronisation, ZEP header bytes, pcapng
block structure and IPv4 checksums, JSONL structure, 802.15.4/NWK header
decoding, CCM* decryption vectors, flag validation, and a golden replay of
`/tmp/opencode/zshark/zep-sample.pcap`. The replay test rebuilds every data
datagram from a synthetic serial stream and compares the result byte-for-byte
with the real capture; it is skipped when the sample file is absent. Set
`ZSHARK_SAMPLE=/path/to/capture.pcap` to use another sample. An additional
integration test writes the sample's datagrams through the pcapng sink and
checks the dissection with `tshark`; it is skipped when `tshark` is not
installed.

Typical use:

```
./zshark list
./zshark capture --channel 15
./zshark capture --no-zep --pcap zigbee.pcapng
./zshark capture --no-zep --jsonl zigbee.jsonl
./zshark capture --no-zep --jsonl - --network-key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
./zshark capture --dest 192.0.2.10:17754 --verbose
```

In Wireshark, listen on UDP port 17754 or open the pcapng file directly. The
capture dissects as `zep -> zigbee`.

## Reference material

The original binary, firmware and a real capture live on the build host:

- `/usr/bin/zshark` (unstripped armhf Qt5 binary)
- `/tmp/opencode/zshark/zep-sample.pcap` (real ConBee II capture)
- `/usr/share/zshark/fw/` (firmware images; not used by this tool)
