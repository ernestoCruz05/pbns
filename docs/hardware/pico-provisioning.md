# PBNS Pico transport validation

## Safety and privacy boundary

This procedure provisions only the Pico W transport proxy. It does not enroll the host, authorize a boot, modify the installed loader, write an installed disk, or change UEFI boot variables.

Keep the SSID, WiFi PSK, credential CBOR, TLS private key, and PBNS payloads local. Do not paste them into issue trackers, chat, logs, or commits. The transport gate records only byte counts, timings, artifact hashes, the research USB identity, and explicit limitations.

Connect the Pico normally. Do not hold BOOTSEL while resetting or connecting it: that enters the RP2040 ROM reflashing mode. Runtime provisioning instead requires a continuous two-second BOOTSEL press after PBNS firmware is already running.

## Prerequisites

- a private 2.4 GHz WiFi network reachable from the Pico;
- a LAN address on this host that the 2.4 GHz network can reach;
- the selected TCP port allowed through the local firewall;
- `qemu-system-x86_64`, Go, Python with PySerial, OpenSSL, the ARM embedded GCC tools, CMake/Ninja, and the already bootstrapped pinned project dependencies;
- per-user read/write access to both PBNS CDC devices and the corresponding USB device node. Use a per-user ACL when needed; never make the devices world-writable.

The evaluated research device is:

```text
VID:PID   cafe:4011
product   PBNS Proxy v1
serial    <PICO_DEVICE_SERIAL>
CDC0      /dev/serial/by-id/usb-PBNS_Research_PBNS_Proxy_v1_<PICO_DEVICE_SERIAL>-if00
CDC1      /dev/serial/by-id/usb-PBNS_Research_PBNS_Proxy_v1_<PICO_DEVICE_SERIAL>-if02
```

The selected record port must equal `PBNS_ECHO_LISTEN` and `PBNS_GATEWAY_LISTEN`. The record host must be the LAN-reachable address, not `127.0.0.1`.

## Prepare the private record

Run one shell-independent executable from the implementation worktree:

```bash
./pbns/tools/prepare-pico-record.sh
```

If `$HOME/.pbns-provision/ssid.bin` and `psk.bin` are both absent, the helper prompts locally for the SSID, a hidden PSK, and this host's LAN-reachable IPv4. If both files already exist, it requires non-symlink regular files with exact mode `0600` and prompts only for the IPv4. A partial or incorrectly permissioned pair fails closed.

The helper fixes the evaluated port to `8443`, generates canonical integer-keyed CBOR with the pinned test-gateway SPKI, and validates it through the same C/QCBOR decoder used by the Pico. It refuses to overwrite an output and never prints credential values or record bytes. On failure it retains existing source files for retry and removes prompted staging inputs. On success it deletes all SSID/PSK inputs and leaves only:

```text
$HOME/.pbns-provision/credentials.cbor
```

The private record has mode `0600`. The helper stops before BOOTSEL activation and never opens CDC1.

## Software-only gate

Run this without activating provisioning:

```bash
./pbns/tools/verify-transport.sh --software-only
```

The final line is deliberately:

```text
TRANSPORT SOFTWARE-ONLY CHECKS PASS; HARDWARE DEFERRED
```

This mode builds and tests the hosted core under GCC, Clang, ASan+UBSan, and the applicable race/TSan checks; builds the exact Pico dependency graph; builds the PBNS UEFI probe; runs the TLS proxy simulator; builds pinned OVMF; and boots the probe from a disposable FAT directory with no installed OS disk attached. It must not print `TRANSPORT PASS`.

## Physical provisioning and gate

The physical transition has two explicit checkpoints because the provisioning reboot creates new USB nodes and invalidates temporary ACLs.

1. Complete `--software-only` before touching BOOTSEL.
2. Verify that no process has CDC1 open.
3. With PBNS firmware running normally, hold BOOTSEL continuously for two seconds, then release it.
4. Do not open CDC1 manually. Immediately consume the fresh session:

```bash
./pbns/tools/verify-transport.sh \
  --provision-now \
  --record "$HOME/.pbns-provision/credentials.cbor"
```

The tool opens CDC1 exclusively. If the first session is completely silent because firmware classified it as present at activation, the tool closes it, waits 100 ms, and opens exactly one fresh session. It retries only zero-byte silence: any nonempty wrong banner fails immediately. Neither session receives credential bytes before exact `PBNS-PROVISION-v1 READY\n`.

5. Wait for the Pico to re-enumerate after its intentional reboot.
6. Restore the per-user ACL on the new nodes; do not make them world-writable.
7. Without another BOOTSEL action, run the post-provision gate:

```bash
PBNS_ECHO_LISTEN=0.0.0.0:8443 \
PBNS_GATEWAY_LISTEN=0.0.0.0:8443 \
./pbns/tools/verify-transport.sh \
  --require-hardware \
  --record "$HOME/.pbns-provision/credentials.cbor"
```

The immediate checkpoint requires the exact USB identity, provisions transactionally, checks the returned record fingerprint, requests a reboot, and stops without a transport-pass claim. The post-provision hardware path never opens CDC1 and exercises:

- TLS 1.2 with ALPN `pbns/1` and the exact ECDHE-ECDSA-AES128-GCM-SHA256 profile;
- baseline and fragmented deterministic byte fidelity;
- cancellation followed by a fresh CDC0 session;
- physical rejection of a same-endpoint certificate with the wrong SPKI, followed by recovery with the pinned identity;
- gateway restart and reconnect;
- a correlated broker request through OVMF/QEMU, xHCI, the physical CDC0 interface, Pico WiFi/TLS, and the Go gateway.

QEMU uses only copied OVMF variables and a temporary `fat:rw:` directory containing the probe. It attaches no installed disk and uses no UEFI variable-writing project API.
