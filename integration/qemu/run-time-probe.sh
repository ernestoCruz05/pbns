#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)

if (( $# != 0 )); then
    printf 'usage: %s\n' "$0" >&2
    exit 2
fi
if [[ -z ${PBNS_EDK2_DIR:-} ]]; then
    printf '%s\n' 'PBNS_EDK2_DIR is required' >&2
    exit 2
fi
if [[ $PBNS_EDK2_DIR != /* && ! -d $PBNS_EDK2_DIR ]]; then
    PBNS_EDK2_DIR="$REPO_ROOT/$PBNS_EDK2_DIR"
fi
PBNS_EDK2_DIR=$(cd -- "$PBNS_EDK2_DIR" && pwd -P)
for tool in qemu-system-x86_64 timeout; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing QEMU trusted-time probe tool: %s\n' "$tool" >&2
        exit 1
    }
done

CODE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"
VARS_TEMPLATE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_VARS.fd"
PROBE="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsTime.efi"
for artifact in "$CODE" "$VARS_TEMPLATE" "$PROBE"; do
    if [[ ! -f $artifact ]]; then
        printf 'missing QEMU trusted-time artifact: %s\n' "$artifact" >&2
        exit 1
    fi
done

STATE_DIR="$PBNS_ROOT/integration/state/qemu"
mkdir -p "$STATE_DIR"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-qemu-time-XXXXXX")
ESP="$RUN_DIR/esp"
VARS="$RUN_DIR/OVMF_VARS.fd"
LOG="$STATE_DIR/time-probe.log"
cleanup() {
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$ESP/EFI/BOOT"
cp -- "$PROBE" "$ESP/PbnsTime.efi"
cp -- "$PROBE" "$ESP/EFI/BOOT/BOOTX64.EFI"
printf 'fs0:\\PbnsTime.efi\r\nreset -s\r\n' >"$ESP/startup.nsh"
cp -- "$VARS_TEMPLATE" "$VARS"

set +e
timeout --signal=TERM --kill-after=5s 45s qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -cpu max \
    -m 256M \
    -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
    -drive "if=pflash,format=raw,file=$VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    -nic none \
    -display none \
    -serial stdio \
    -monitor none \
    -no-reboot >"$LOG" 2>&1
qemu_status=$?
set -e
if [[ $qemu_status != 0 && $qemu_status != 124 ]]; then
    printf 'QEMU trusted-time probe exited unexpectedly: %s\n' "$qemu_status" >&2
    exit 1
fi
if ! grep -Fq 'PBNS TRUSTED TIME INTERVAL PASS' "$LOG"; then
    printf '%s\n' 'QEMU trusted-time serial oracle missing' >&2
    exit 1
fi
if grep -Fq 'PBNS TRUSTED TIME PROBE FAIL' "$LOG"; then
    printf '%s\n' 'QEMU trusted-time probe reported failure' >&2
    exit 1
fi
printf '[PASS] signed UTC assertion produced a conservative interval under OVMF\n'
printf '[PASS] EFI CPU timer measured elapsed time without RTC access or modification\n'
printf '%s\n' 'UEFI TRUSTED TIME SOFTWARE CHECKPOINT PASS'
