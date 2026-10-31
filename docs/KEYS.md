# `keys` output

`zshark keys` listens for unsecured APS Transport-Key commands and prints each
network key it discovers. Set `--channel` to the network's channel. The command
does not emit ZEP and prints packet statistics to stderr when it exits.

By default each distinct key transport is printed once. A repeat is the same
key sent to the same destination with the same key sequence number. `--all`
prints repeats too, which is useful for observing retries or multiple deliveries.

`--json` switches stdout from the text format below to one JSON object per line
(NDJSON). Logging and statistics stay on stderr.

## Text format

```
2026-10-30T16:20:00Z channel=15 pan=0x1a2b dst=0x1234 src=0x0000 dst_ext=4d:3c:2b:1a:00:4b:12:00 src_ext=11:00:ff:ee:dd:cc:bb:aa type=standard-network key_seq=7 key=5a6967426565416c6c69616e63653039
```

Fields appear in that order. `dst` and `src` are omitted when the MAC header
used extended addresses instead of short ones; `src_ext` is omitted when the
transport does not carry a source address.

## JSON fields

```json
{"time":"2026-10-30T16:20:00Z","channel":15,"pan":"0x1a2b","destination_short":"0x1234","source_short":"0x0000","destination":"4d:3c:2b:1a:00:4b:12:00","source":"11:00:ff:ee:dd:cc:bb:aa","key_type":"standard-network","key":"5a6967426565416c6c69616e63653039","key_sequence":7}
```

| Field | Meaning |
|---|---|
| `time` | Time the key transport was received, RFC 3339 with nanoseconds, UTC. |
| `channel` | Channel selected with `--channel` (11–26). |
| `pan` | PAN ID from the MAC header, formatted as `0x1234`. |
| `destination_short` | Destination short address, when the MAC header carried one. |
| `source_short` | Source short address, when the MAC header carried one. |
| `destination` | Destination extended address (EUI-64), most-significant byte first. |
| `source` | Source extended address, when the transport carries one. |
| `key_type` | `standard-network` or `high-security-network`. |
| `key` | Network key as 32 lowercase hex characters. |
| `key_sequence` | Network key sequence number from the transport. |

`destination_short`, `source_short`, and `source` are omitted when absent. The
key is the same material the Trust Center sent over the air; the output
therefore contains key material and should be handled accordingly.

## Examples

```sh
# Watch the network's channel for an adopted device's network key.
zshark keys --channel 15

# Also decrypt APS-secured transports with the well-known Trust Center link key.
zshark keys --channel 15 --trust-center-key 5a6967426565416c6c69616e63653039

# Machine-readable output, including repeated transports.
zshark keys --channel 15 --json --all

# Show only the keys.
zshark keys --channel 15 --json | jq -r .key
```

## APS-secured transports

`--trust-center-key` supplies one or more 16-byte Trust Center link keys. The
keys command then decrypts Transport-Key commands secured at the APS layer and
extracts the network key from the plaintext. Key identifiers 0 (link key), 2
(Key-Transport Key) and 3 (Key-Load Key) are handled; the latter two are derived
from the supplied link key with the ZigBee keyed hash. The flag is repeatable so
several keys can be tried.

Many networks use the well-known ZigBee Alliance default:

```
5a6967426565416c6c69616e63653039
```

That is the ASCII string `ZigBeeAlliance09`; separators are optional. If the
network uses a random Trust Center link key or an install-code-derived key, pass
that key instead.

```sh
zshark keys --channel 15 \
  --trust-center-key 5a6967426565416c6c69616e63653039
```

The network key itself is only visible if the capture contains the Transport-Key
command sent while a device joins. A running network with no join in progress
produces no such command.

## What can be discovered

Clear Transport-Key commands are readable directly. APS-secured commands are
readable when their Trust Center link key is supplied, including transports
protected with the derived Key-Transport or Key-Load key. Commands encrypted
with the network key itself, non-network key descriptors, and frames secured at
the MAC or NWK layer are ignored. See
[PROTOCOL.md](PROTOCOL.md#7-network-key-transport-sniffer-aid) for the frame
layout and limitations.
