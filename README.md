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
- Linux and macOS; no cgo, no system daemons.

Out of scope for now: firmware detection/flashing, ConBee I (FTDI) and RaspBee,
live channel switching, Windows.

## Command line

```
zshark list [--json]
zshark capture [--port PATH] [--channel N] [--dest IP:PORT]
               [--pcap FILE] [--no-zep] [--verbose]
```

- `--port` is auto-detected when omitted.
- `--dest` defaults to `127.0.0.1:17754`.
- `--pcap` writes a pcapng file with synthetic Ethernet/IPv4/UDP framing so
  Wireshark dissects `zep -> zigbee` directly.
- `--no-zep` disables UDP output (requires `--pcap`).
- Ctrl-C sends `idle` to the dongle and exits cleanly.

## Layout

```
cmd/zshark/            CLI entry point and flags
internal/serialport/   port enumeration and open (cross-platform)
internal/proto/        dongle text commands and 0x01/len/payload/0x04 framing
internal/zep/          ZEP v2 header construction
internal/sink/         UDP and pcapng sinks
docs/PROTOCOL.md       reverse-engineered wire protocol
```

## Build and test

```
go build ./cmd/zshark
go test ./...
GOOS=darwin GOARCH=arm64 go build ./cmd/zshark
```

## Reference material

The original binary, firmware and a real capture live on the build host:

- `/usr/bin/zshark` (unstripped armhf Qt5 binary)
- `/tmp/opencode/zshark/zep-sample.pcap` (real ConBee II capture)
- `/usr/share/zshark/fw/` (firmware images; not used by this tool)
