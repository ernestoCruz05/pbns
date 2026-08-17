# PBNS Pico W proxy

The prototype exposes two USB CDC/ACM functions under research-only identifier `CAFE:4011`:

- CDC instance 0 carries opaque PBNS bytes and is never interpreted by provisioning code.
- CDC instance 1 is reserved for physical provisioning and remains inert until a continuous 2-second runtime BOOTSEL press latches provisioning. Firmware then requires a fresh CDC1 session before it sends `READY` or accepts input.

A production device must obtain an assigned USB VID/PID. The UEFI transport additionally checks the CDC class/subclass and exact product string `PBNS Proxy v1`; the prototype identifier is not a production identity mechanism.

Credentials occupy two reserved 4 KiB flash sectors, one transactional slot per sector. The linker cannot place firmware in those sectors. A slot becomes active only after its data has been read back and a separate commit page has been programmed. Configuration records are canonical CBOR produced by an established encoder; `tools/provision-pico.py` transports an already encoded record and never prints its contents.

The firmware reserves the RP2040 scratch-Y bank's full 4 KiB for the stack. Exact ARM `-fstack-usage` measurements showed that stack-local transaction buffers would exceed that bank, so the single-threaded firmware build uses a fixed, wiped static credential workspace. Hosted builds retain stack-local workspaces and exercise the same transaction logic under sanitizers. The reproducible build records every emitted stack-usage report and rejects any individual frame that reaches the 4 KiB reservation; physical stack-watermark testing remains part of the hardware transport gate.

## Credential record

The deterministic CBOR map contains exactly these integer-labelled fields in order:

| Key | Type | Meaning | Limit |
|---:|---|---|---:|
| 1 | unsigned integer | format version | exactly `1` |
| 2 | byte string | WiFi SSID | 1–32 bytes, valid UTF-8, no NUL |
| 3 | byte string | WiFi PSK | 1–63 bytes, no NUL |
| 4 | text string | gateway hostname | 1–253 bytes, valid UTF-8, no NUL |
| 5 | unsigned integer | gateway TCP port | 1–65535 |
| 6 | byte string | SHA-256 of gateway SPKI | exactly 32 bytes |

Do not hold BOOTSEL during reset for provisioning: that enters the RP2040 ROM UF2 bootloader. Instead:

1. boot PBNS normally with the provisioning port closed;
2. hold BOOTSEL continuously for at least 2 seconds, then release it;
3. open `PBNS Provision` as a fresh session and send the encoded record.

If the provisioning port was open during the press, close it first; firmware will not send `READY` until a subsequent open. The stable research-device path can be used with:

```bash
python3 pbns/tools/provision-pico.py \
  --port /dev/serial/by-id/usb-PBNS_Research_PBNS_Proxy_v1_E66130100F527A26-if02 \
  --record credentials.cbor
```

The tool requires `pyserial`. It waits for the exact `PBNS-PROVISION-v1 READY` response, verifies the SHA-256 fingerprint returned after transactional read-back, and sends `REBOOT` only after an exact match. Provisioning enforces normal-boot silence, short-press rejection, pre-activation queue isolation, the fresh-session boundary, and reboot reset.

## WiFi and raw TCP tunnel

Normal mode starts networking only while CDC instance 0 is connected. It uses CYW43 threadsafe-background mode and raw lwIP TCP. CDC instance 0 is an opaque ordered path for TLS ciphertext: the Pico neither parses TLS nor sees PBNS plaintext. UEFI owns TLS, the gateway identity decision, and the immutable expected SAN and SPKI pin.

The credential SPKI field is decoded only for record compatibility and is not copied into the production network state. SSID and PSK connect WiFi; hostname and port select the route. The retained Pico TLS client, pin tests, and deterministic replay are historical baseline code and are not linked into `pbns-proxy`.

The network controller uses fixed WiFi, TCP/DNS, and session deadlines of 30, 10, and 15 seconds. Retry delay starts at 250 ms, doubles to an 8-second cap, and adds jitter from Pico's public RNG API. USB disconnection closes the active connection and resets retry state. The implementation retains the 18,432-byte raw TCP receive ring and bounded 4,096-byte tunnel rings; TCP receive-window credit is returned only after ciphertext is copied toward CDC0.

Cross-compilation and hosted state tests do not establish physical radio, DNS, TCP, UEFI TLS, throughput, or reconnect behavior. Those claims remain withheld until the hardware loopback gate.

## Reproducible cross-build

Fetch the exact external revisions from `dependencies.lock`; the Pico SDK fetch includes its pinned submodules:

```bash
./pbns/tools/bootstrap.sh --fetch-external pico_sdk
./pbns/tools/bootstrap.sh --fetch-external picotool
PICO_SDK_PATH=pbns/.deps/pico_sdk ./pbns/tools/build-pico.sh
```

The build script rejects modified or mismatched Pico SDK, Mbed TLS, TinyUSB, and picotool checkouts before producing `pbns/pico/build/pbns-proxy.elf` and `pbns/pico/build/pbns-proxy.uf2`.

## Test-only network diagnostic

`PBNS_BUILD_NETWORK_DIAGNOSTIC` is an opt-in, separate target for one typed physical diagnosis. It enumerates as `CAFE:40D1` / `PBNS Network Diagnostic v1`, has one DTR-only CDC function, reads credential slots through non-mutating callbacks, and never transfers CDC payload bytes. The build rejects diagnostic loadable sections in the final two flash sectors, flash mutation APIs, and CDC APIs that can enqueue, inspect, read, or clear payload.

Build it only with:

```bash
PICO_SDK_PATH=pbns/.deps/pico_sdk \
  ./pbns/tools/build-pico-diagnostic.sh
```

This artifact cannot establish any production transport claim. Its exact ROM-mode copy gate, typed result table, zero-byte host oracle, and mandatory restoration of reviewed `CAFE:4011` production firmware are documented in [`../docs/hardware/pico-network-diagnostic.md`](../docs/hardware/pico-network-diagnostic.md).
