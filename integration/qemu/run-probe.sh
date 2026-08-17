#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)

usage() {
    printf 'usage: %s --self-test | --require-hardware\n' "$0" >&2
}

if (( $# != 1 )) || [[ $1 != --self-test && $1 != --require-hardware ]]; then
    usage
    exit 2
fi
MODE=$1
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
        printf 'missing QEMU probe tool: %s\n' "$tool" >&2
        exit 1
    }
done

CODE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"
VARS_TEMPLATE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_VARS.fd"
PROBE="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsProbe.efi"
for artifact in "$CODE" "$VARS_TEMPLATE" "$PROBE"; do
    if [[ ! -f $artifact ]]; then
        printf 'missing QEMU probe artifact: %s\n' "$artifact" >&2
        exit 1
    fi
done

STATE_DIR="$PBNS_ROOT/integration/state/qemu"
mkdir -p "$STATE_DIR"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-qemu-probe-XXXXXX")
ESP="$RUN_DIR/esp"
VARS="$RUN_DIR/OVMF_VARS.fd"
LOG="$STATE_DIR/probe-${MODE#--}.log"
GATEWAY_PID=

cleanup() {
    if [[ -n $GATEWAY_PID ]] && kill -0 "$GATEWAY_PID" 2>/dev/null; then
        kill "$GATEWAY_PID" 2>/dev/null || true
        wait "$GATEWAY_PID" 2>/dev/null || true
    fi
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$ESP/EFI/BOOT"
cp -- "$PROBE" "$ESP/PbnsProbe.efi"
cp -- "$PROBE" "$ESP/EFI/BOOT/BOOTX64.EFI"
printf 'fs0:\\PbnsProbe.efi\r\nreset -s\r\n' >"$ESP/startup.nsh"
cp -- "$VARS_TEMPLATE" "$VARS"

qemu_arguments=(
    -machine q35,accel=tcg
    -cpu max
    -m 256M
    -drive "if=pflash,format=raw,readonly=on,file=$CODE"
    -drive "if=pflash,format=raw,file=$VARS"
    -drive "format=raw,file=fat:rw:$ESP"
    -device qemu-xhci,id=xhci
    -nic none
    -display none
    -serial stdio
    -monitor none
    -no-reboot
)

if [[ $MODE == --require-hardware ]]; then
    GATEWAY_LISTEN=${PBNS_GATEWAY_LISTEN:-0.0.0.0:8443}
    if [[ -z ${PBNS_GATEWAY_SERVER_NAME:-} ]]; then
        printf '%s\n' 'PBNS_GATEWAY_SERVER_NAME is required for physical QEMU' >&2
        exit 2
    fi
    "$PBNS_ROOT/integration/tls/make-test-pki.sh" \
        "$RUN_DIR/test-pki" "$PBNS_GATEWAY_SERVER_NAME" \
        >"$RUN_DIR/test-pki.log"
    GATEWAY_CERT="$RUN_DIR/test-pki/gateway-reissued-cert.pem"
    GATEWAY_KEY="$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-key.pem"
    python3 "$PBNS_ROOT/integration/tls/verify-spki.py" \
        "$GATEWAY_CERT" \
        "$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-spki.sha256"
    GATEWAY_BINARY="$RUN_DIR/pbns-gateway"
    (
        cd -- "$PBNS_ROOT/gateway"
        go build -trimpath -o "$GATEWAY_BINARY" ./cmd/pbns-gateway
    )
    "$GATEWAY_BINARY" \
        --listen "$GATEWAY_LISTEN" \
        --tls-cert "$GATEWAY_CERT" \
        --tls-key "$GATEWAY_KEY" \
        >"$STATE_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!
    sleep 1
    if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
        printf '%s\n' 'PBNS gateway failed to start for QEMU probe' >&2
        exit 1
    fi
    qemu_arguments+=(
        -device usb-host,bus=xhci.0,vendorid=0xcafe,productid=0x4011
    )
    oracle='PBNS probe: correlated unimplemented response'
else
    oracle='PBNS probe: CDC0 adapter unavailable'
fi

set +e
timeout --signal=TERM --kill-after=5s 45s \
    qemu-system-x86_64 "${qemu_arguments[@]}" >"$LOG" 2>&1
qemu_status=$?
set -e
if [[ $qemu_status != 0 && $qemu_status != 124 ]]; then
    printf 'QEMU probe exited unexpectedly: %s\n' "$qemu_status" >&2
    exit 1
fi
if ! grep -Fq "$oracle" "$LOG"; then
    printf 'QEMU probe serial oracle missing: %s\n' "$oracle" >&2
    exit 1
fi
if grep -Eiq 'ticket|unlock|BootOrder|SetVariable' "$LOG"; then
    printf '%s\n' 'QEMU probe emitted forbidden authorization or NVRAM text' >&2
    exit 1
fi
printf '[PASS] disposable FAT probe with no installed OS disk\n'
printf '[PASS] serial oracle %s\n' "$oracle"
printf '%s\n' 'QEMU PROBE PASS'
