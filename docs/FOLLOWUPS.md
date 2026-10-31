# Verification follow-ups

The core paths are verified on macOS with a ConBee II on stock deCONZ
firmware, and the combined-sink capture in §1 is also verified on Linux:

- startup handshake, including the retry when the port opens noisily
- channel selection, capture, live ZEP, pcapng and JSONL
- unplug/replug reconnect while capturing
- APS-secured Transport-Key discovery with a Trust Center link key
  (including the derived Key-Transport key, identifier 2)
- NWK decryption and ZCL On/Off state reports with the discovered network key

The unit tests and macOS/Linux CI cover the protocol, ZEP, pcapng, CCM*,
AES-MMO key derivation, transport-key extraction and CLI parsing. The checks
below are optional follow-ups, not release blockers.

## 1. All sinks at once

Verified on Linux with a ConBee II on stock firmware and channel 25: 621
frames, with `frames=`, `pcap=`, `jsonl=` and `zep=` all 621 and
`dropped=0 errors=0 reconnects=0`. A light's ZCL OnOff Report Attributes
changed from `00` (Off) to `01` (On).

pcapng, JSONL and ZEP were previously verified separately. To run all three
together and compare the counts:

```sh
# tshark captures but does not bind the port. Keep a real listener on 17754,
# or the ICMP port-unreachable reply makes the UDP sink back off and drop ZEP
# frames while pcapng and JSONL keep going. socat or any UDP listener works.
socat -u UDP-RECV:17754 /dev/null &
tshark -i lo -f 'udp port 17754' -w /tmp/zep.pcapng -q &

./zshark capture --channel 25 --pcap /tmp/all.pcapng --jsonl /tmp/all.jsonl \
  --network-key <network-key>
```

Toggle a device and stop the capture with `SIGINT`, then compare the stats
line with:

```sh
tshark -r /tmp/all.pcapng | wc -l
wc -l /tmp/all.jsonl
tshark -r /tmp/zep.pcapng -Y 'zep.type == 1' | wc -l
jq -r 'select(.nwk.security != null) | .decryption.status' /tmp/all.jsonl \
  | sort | uniq -c
```

The sink counts should match `frames=`, `pcap=`, `jsonl=` and `zep=`, and
`dropped=`, `errors=` and `reconnects=` should be zero. Wireshark should show
the same frames live. Decryption failures for frames belonging to other PANs
sharing the channel are expected.

## 2. Linux hardware parity

The new startup retry, key discovery and CCM* changes were exercised on
macOS. `./zshark list` and the full three-sink capture (§1) now also pass on
Linux with a ConBee II on stock deCONZ firmware. The `keys` path still needs a
Linux run:

```sh
./zshark keys --channel 25 --trust-center-key <trust-center-link-key>
```

Run it while a device joins and confirm the discovered key matches the
coordinator's network key.

## 3. CLI edge cases

- Send `SIGTERM` during a capture and confirm the dongle receives `idle`, the
  sinks close and the stats line is printed.
- With no dongle attached, `zshark capture` should exit 3.
- During a join, `zshark keys --channel <n> --json --all --trust-center-key
  <key>` should emit valid NDJSON and print repeated transports when `--all`
  is set.

## 4. Conditional checks

- **Dedicated sniffer firmware.** The macOS run used the stock deCONZ
  firmware. The `Sniffer V...` firmware path is accepted but has not been
  exercised on macOS.
- **Release artifact.** Local builds run, but a downloaded CI archive should
  be checked for Gatekeeper/quarantine behavior before distributing it.
- **Network key rotation.** A key is only reported when a join or rejoin
  transports it while `keys` is running. Rejoining a device after a key
  rotation would exercise the same code path with a new sequence number.

## Known limitations

- JSONL decryption needs the sender's 64-bit address for the CCM* nonce. There
  is no short-to-EUI64 address map, so frames that carry neither an auxiliary
  extended nonce nor a NWK extended source remain encrypted. See
  [JSONL.md](JSONL.md).
- `keys` can decrypt APS transports with key identifiers 0, 2 and 3 when the
  Trust Center link key is supplied. Transports protected by an unknown link
  key, or by the network key itself, cannot be read.
- The network key is only visible during the adoption/rejoin exchange; a
  capture of steady-state traffic contains no Transport-Key command.
