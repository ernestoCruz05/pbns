# Isolated Pico W Network Diagnostic [RESOLVED HARDWARE DIAGNOSTIC REFERENCE]

## Status and scope

This document records the isolated hardware-level diagnostic harness utilized during early PHY/CYW43 pre-LAN bring-up. That initial bring-up issue was fully resolved in the production `CAFE:4011` firmware evaluated in the paper. This specification is retained for reproducibility and diagnostic verification of the hardware boundary.

The diagnostic has the distinct identity `CAFE:40D1`, product `PBNS Network Diagnostic v1`, and one CDC function. The CDC interface is only a DTR trigger. Firmware and the host oracle send and receive zero CDC payload bytes. The only result channels are a typed watchdog-scratch record and the terminal diagnostic `bcdDevice` identity.

The artifact uses the production credential decoder and network/TLS operations. It reads the two credential sectors through callbacks that cannot erase or program flash. Its linkable FLASH range ends at `0x001fe000`, before those sectors. The build also rejects linked flash erase/program functions and every CDC API that can enqueue, inspect, read, or clear payload. TinyUSB internally links its TX-flush helper, but the diagnostic links no function that can place a byte in that empty queue.

Production `CAFE:4011` firmware is the evaluated artifact that supports physical HIL and production pre-boot transport.

## Result codes

The host accepts these values only after verifying VID, PID, product, serial, and diagnostic profile.

| `bcdDevice` | Meaning |
|---:|---|
| `0x9100` | Awaiting CDC DTR; no terminal result |
| `0x9110` | Credential slot load/validation failed |
| `0x9120` | CYW43/network-adapter initialization failed |
| `0x9130` | CDC DTR was not observed before its bounded deadline |
| `0x9140` | WiFi start failed synchronously |
| `0x9141` | WiFi authentication failed |
| `0x9142` | WiFi network/link failure |
| `0x9143` | WiFi stage timed out |
| `0x9150` | TCP/DNS stage failed |
| `0x9151` | TCP/DNS stage timed out |
| `0x9160` | TLS stage failed |
| `0x9161` | TLS stage timed out |
| `0x9190` | TLS reached production `READY` state |
| `0x9199` | Internal diagnostic state or entropy failure |

No result encodes an SSID, PSK, hostname, address, certificate, key, credential byte, payload, or raw library error.

## Build and review

Build through the opt-in target only:

```bash
PICO_SDK_PATH=pbns/.deps/pico_sdk \
  ./pbns/tools/build-pico-diagnostic.sh
```

Before physical action, record SHA-256 for both diagnostic and production UF2/ELF artifacts. Independently inspect both ELF files and maps. Each must use FLASH length `0x001fe000`, reserve an exact 4 KiB stack, and have no loadable section ending at or above `0x101fe000`. A local artifact hash associates the reviewed file with the trial; it is not physical flash read-back.

## Diagnostic flash gate

Entering RP2040 ROM mode requires an explicit physical BOOTSEL/reset action. Before each copy, independently require all of the following for the removable target:

- block device is removable and has model `RP2`;
- partition label is `RPI-RP2`;
- USB identity is `2e8a:0003`, product `RP2 Boot`;
- ROM serial is `<PICO_BOOTROM_SERIAL>`;
- target is not the source of `/` and is not an installed OS disk;
- source UF2 digest equals the reviewed digest.

Copy only to the verified mounted ROM volume, synchronize, and unmount it if still mounted. Never use world-write device permissions. Restore access through a per-user ACL or the operating system's trusted device-access mechanism. Project scripts must not invoke `sudo`.

After the diagnostic copy, require exactly:

- VID:PID `CAFE:40D1`;
- product `PBNS Network Diagnostic v1`;
- serial `<PICO_DEVICE_SERIAL>`;
- initial `bcdDevice 9100`.

Any mismatch stops the run.

## One host-oracle run

Derive the current local server name without printing it, then run once:

```bash
diagnostic_sha256=$(sha256sum \
  pbns/pico/build-diagnostic/pbns-proxy-diagnostic.uf2 | awk '{print $1}')
server_name=$(ip route get 1.1.1.1 | \
  awk '{for (i=1; i<=NF; ++i) if ($i == "src") {print $(i+1); exit}}')
[[ -n $server_name ]]
python3 pbns/integration/hil/pico-network-diagnostic.py run \
  --port /dev/ttyACM0 \
  --expected-serial <PICO_DEVICE_SERIAL> \
  --firmware-uf2 pbns/pico/build-diagnostic/pbns-proxy-diagnostic.uf2 \
  --expected-uf2-sha256 "$diagnostic_sha256" \
  --record "$HOME/.pbns-provision/credentials.cbor" \
  --server-name "$server_name" \
  --results-dir pbns/integration/state/diagnostic-results
```

The oracle checks the private record only as a non-symlink mode-`0600` regular file and never reads it. It creates a temporary SAN-matching certificate with the already pinned test key, independently verifies the exact DER SPKI SHA-256, and deletes all temporary files. It opens the sole CDC port exclusively, asserts DTR, and transfers no bytes. Results and their SHA-256 manifests are atomically published with mode `0600` in a mode-`0700` directory.

Stop after the first typed result. Analyze that boundary with the systematic-debugging workflow before changing production code.

## Mandatory production restoration

Re-enter ROM mode physically. Repeat every removable-device, model, label, USB identity, ROM serial, root-disk exclusion, artifact-hash, and loadable-range check independently. Copy only the reviewed production UF2.

After re-enumeration require exactly:

- VID:PID `CAFE:4011`;
- product `PBNS Proxy v1`;
- serial `<PICO_DEVICE_SERIAL>`;
- `bcdDevice 0100`;
- the production two-CDC interface profile.

Restore per-user ACLs if needed. Do not resume HIL or QEMU from a diagnostic identity. Credential preservation is expected from the link and API restrictions, but neither USB identity nor a UF2 hash is represented as flash read-back proof.
