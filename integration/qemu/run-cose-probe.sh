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
for tool in python3 qemu-system-x86_64 timeout; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing QEMU COSE probe tool: %s\n' "$tool" >&2
        exit 1
    }
done

CODE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"
VARS_TEMPLATE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_VARS.fd"
PROBE="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsCoseProbe.efi"
UEFI_ENCRYPT_VECTOR="$PBNS_ROOT/tests/vectors/cose-encrypt-v1/uefi-to-cosec.cbor"
for artifact in "$CODE" "$VARS_TEMPLATE" "$PROBE" "$UEFI_ENCRYPT_VECTOR"; do
    if [[ ! -f $artifact ]]; then
        printf 'missing QEMU COSE artifact: %s\n' "$artifact" >&2
        exit 1
    fi
done

STATE_DIR="$PBNS_ROOT/integration/state/qemu"
mkdir -p "$STATE_DIR"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-qemu-cose-XXXXXX")
ESP="$RUN_DIR/esp"
VARS="$RUN_DIR/OVMF_VARS.fd"
LOG="$STATE_DIR/cose-probe.log"
cleanup() {
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$ESP/EFI/BOOT"
cp -- "$PROBE" "$ESP/PbnsCoseProbe.efi"
cp -- "$PROBE" "$ESP/EFI/BOOT/BOOTX64.EFI"
printf 'fs0:\\PbnsCoseProbe.efi\r\nreset -s\r\n' >"$ESP/startup.nsh"
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
    printf 'QEMU COSE probe exited unexpectedly: %s\n' "$qemu_status" >&2
    exit 1
fi
for oracle in \
    'PBNS COSE SIGN1 VERIFY PASS' \
    'PBNS COSE ENCRYPT ROUNDTRIP PASS' \
    'PBNS COSE ENCRYPT NEGATIVE PASS'; do
    if ! grep -Fq "$oracle" "$LOG"; then
        printf 'QEMU COSE serial oracle missing: %s\n' "$oracle" >&2
        exit 1
    fi
done
if grep -Fq 'PBNS COSE PROBE FAIL' "$LOG"; then
    printf '%s\n' 'QEMU COSE probe reported failure' >&2
    exit 1
fi
python3 - "$LOG" "$UEFI_ENCRYPT_VECTOR" <<'PY'
import pathlib
import sys

prefix = "PBNS UEFI ENCRYPT VECTOR "
lines = pathlib.Path(sys.argv[1]).read_text(errors="replace").splitlines()
encoded = next((line[len(prefix):] for line in lines if line.startswith(prefix)), None)
if encoded is None or bytes.fromhex(encoded) != pathlib.Path(sys.argv[2]).read_bytes():
    raise SystemExit("UEFI encryption output differs from the COSE-C oracle vector")
PY
printf '[PASS] disposable FAT, copied OVMF variables, TCG, and no installed OS disk\n'
printf '[PASS] go-cose to UEFI verify and UEFI identity callback to exact go-cose vector\n'
printf '[PASS] COSE-C to UEFI and UEFI to COSE-C encryption vectors\n'
printf '[PASS] t_cose ECDH-ES+A128KW/A128GCM round trip and negative rejection\n'
printf '%s\n' 'UEFI COSE INTEROP PASS'
