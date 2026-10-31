# Verification follow-ups

The core paths are verified on macOS with a ConBee II on stock deCONZ
firmware:

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

pcapng, JSONL and ZEP have each been verified separately. Run all three
together and compare the counts:

```sh
# Start a ZEP listener first so the UDP sink has a destination.
./zshark capture --channel 25 --pcap /tmp/all.pcapng --jsonl /tmp/all.jsonl \
  --network-key <network-key>
```

Toggle a device, stop the capture, then compare the stats line with:

```sh
tshark -r /tmp/all.pcapng | wc -l
wc -l /tmp/all.jsonl
jq -r 'select(.decryption.status == "ok") | .nwk.src' /tmp/all.jsonl | wc -l
```

The pcapng and JSONL counts should match `frames=`/`pcap=` and `jsonl=`.
Wireshark should show the same frames live.

## 2. Linux hardware parity

The new startup retry, key discovery and CCM* changes were exercised on
macOS. The code is platform-independent, but a Linux smoke test with the
dongle is still worthwhile:

```sh
./zshark list
./zshark capture --channel 25 --no-zep --pcap /tmp/linux.pcapng
./zshark keys --channel 25 --trust-center-key <trust-center-link-key>
```

Run the last command while a device joins and confirm the discovered key
matches the coordinator's network key.

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
