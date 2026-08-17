#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
MODE=
RECORD=
BUILT_UF2_SHA256=
PHYSICAL_SERVER_NAME=
EXPECTED_SERIAL=${PBNS_PICO_SERIAL:-E66130100F527A26}
EXPECTED_SPKI="$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-spki.sha256"
export PBNS_EDK2_DIR=${PBNS_EDK2_DIR:-$PBNS_ROOT/.deps/edk2}
export PICO_SDK_PATH=${PICO_SDK_PATH:-$PBNS_ROOT/.deps/pico_sdk}

usage() {
    printf 'usage: %s --software-only | --provision-now --record FILE | --require-hardware --record FILE\n' "$0" >&2
}

while (( $# > 0 )); do
    case $1 in
    --software-only | --provision-now | --require-hardware)
        if [[ -n $MODE ]]; then
            usage
            exit 2
        fi
        MODE=$1
        shift
        ;;
    --record)
        if (( $# < 2 )) || [[ -n $RECORD ]]; then
            usage
            exit 2
        fi
        RECORD=$2
        shift 2
        ;;
    *)
        usage
        exit 2
        ;;
    esac
done
MODE=${MODE:---software-only}
if [[ $MODE == --software-only && -n $RECORD ]] ||
   [[ $MODE != --software-only && -z $RECORD ]]; then
    usage
    exit 2
fi
if [[ $MODE == --require-hardware ]]; then
    PHYSICAL_SERVER_NAME=${PBNS_ECHO_SERVER_NAME:-}
    if [[ -z $PHYSICAL_SERVER_NAME ]]; then
        command -v ip >/dev/null 2>&1 || {
            printf '%s\n' 'missing required hardware tool: ip' >&2
            exit 1
        }
        PHYSICAL_SERVER_NAME=$(ip route get 1.1.1.1 2>/dev/null |
            awk '{ for (i = 1; i <= NF; ++i) if ($i == "src") { print $(i + 1); exit } }')
    fi
    if [[ -z $PHYSICAL_SERVER_NAME ]]; then
        printf '%s\n' 'cannot determine physical TLS server name' >&2
        exit 1
    fi
fi

run_stage() {
    local name=$1
    shift
    printf '[RUN] %s\n' "$name"
    "$@"
    printf '[PASS] %s\n' "$name"
}

verify_byte_pump() {
    "$PBNS_ROOT/tools/verify-foundations.sh"
}

build_pico() {
    "$PBNS_ROOT/tools/build-pico.sh"
    BUILT_UF2_SHA256=$(sha256sum "$PBNS_ROOT/pico/build/pbns-proxy.uf2" | awk '{ print $1 }')
    if [[ ! $BUILT_UF2_SHA256 =~ ^[0-9a-f]{64}$ ]]; then
        printf '%s\n' 'invalid built UF2 digest' >&2
        return 1
    fi
    printf '[PASS] built UF2 SHA-256 %s\n' "$BUILT_UF2_SHA256"
}

build_uefi() {
    "$PBNS_ROOT/tools/build-uefi.sh"
}

verify_gateway_race() {
    (
        cd -- "$PBNS_ROOT/gateway"
        go test -mod=readonly -race ./...
    )
}

verify_proxy_sim() {
    "$PBNS_ROOT/integration/run-proxy-sim.sh" --self-test
}

verify_record() {
    if [[ ! -f $RECORD || -L $RECORD ]] ||
       [[ $(stat -c '%F' "$RECORD") != 'regular file' ]] ||
       [[ $(stat -c '%a' "$RECORD") != 600 ]]; then
        printf '%s\n' 'private credential record must be a non-symlink mode-0600 regular file' >&2
        return 1
    fi
}

verify_usb_identity() {
    python3 "$PBNS_ROOT/integration/hil/pico-loopback.py" preflight \
        --expected-serial "$EXPECTED_SERIAL" \
        --expected-bcd-device 0100
}

provision_now() {
    verify_record
    verify_usb_identity
    local cdc0=${PBNS_CDC0_PORT:-/dev/serial/by-id/usb-PBNS_Research_PBNS_Proxy_v1_${EXPECTED_SERIAL}-if00}
    local cdc1=${PBNS_PROVISION_PORT:-/dev/serial/by-id/usb-PBNS_Research_PBNS_Proxy_v1_${EXPECTED_SERIAL}-if02}
    if [[ ! -r $cdc0 || ! -w $cdc0 || ! -r $cdc1 || ! -w $cdc1 ]]; then
        printf '%s\n' 'CDC0/CDC1 access is unavailable; grant a per-user ACL' >&2
        return 1
    fi
    local validator="$PBNS_ROOT/build/dev/pbns-pico-record-validate"
    if [[ ! -x $validator ]]; then
        printf '%s\n' 'missing Pico C validator; run --software-only first' >&2
        return 1
    fi
    "$validator" "$RECORD" "$EXPECTED_SPKI"
    python3 "$PBNS_ROOT/tools/provision-pico.py" \
        --port "$cdc1" \
        --record "$RECORD"
    printf '%s\n' '[PASS] transactional Pico credential write and reboot request'
    printf '%s\n' '[ACTION] wait for USB re-enumeration, then restore the per-user ACL'
    printf '%s\n' 'PICO PROVISIONING CHECKPOINT PASS; TRANSPORT HARDWARE DEFERRED'
}

verify_post_provision_inputs() {
    verify_record
    verify_usb_identity
    local cdc0=${PBNS_CDC0_PORT:-/dev/serial/by-id/usb-PBNS_Research_PBNS_Proxy_v1_${EXPECTED_SERIAL}-if00}
    if [[ ! -r $cdc0 || ! -w $cdc0 ]]; then
        printf '%s\n' 'CDC0 access is unavailable; restore the post-reboot per-user ACL' >&2
        return 1
    fi
}

verify_pico_loopback() {
    if [[ $MODE == --software-only ]]; then
        "$PBNS_ROOT/integration/hil/pico-loopback.sh" --self-test
        return
    fi
    local cdc0=${PBNS_CDC0_PORT:-/dev/serial/by-id/usb-PBNS_Research_PBNS_Proxy_v1_${EXPECTED_SERIAL}-if00}
    PBNS_CDC0_PORT="$cdc0" \
    PBNS_PICO_SERIAL="$EXPECTED_SERIAL" \
    PBNS_EXPECTED_UF2_SHA256="$BUILT_UF2_SHA256" \
    PBNS_ECHO_LISTEN="${PBNS_ECHO_LISTEN:-0.0.0.0:8443}" \
    PBNS_ECHO_SERVER_NAME="$PHYSICAL_SERVER_NAME" \
        "$PBNS_ROOT/integration/hil/pico-loopback.sh" --require-hardware
}

verify_qemu_probe() {
    "$PBNS_ROOT/integration/qemu/bootstrap-iasl.sh"
    "$PBNS_ROOT/integration/qemu/build-ovmf.sh"
    if [[ $MODE == --software-only ]]; then
        "$PBNS_ROOT/integration/qemu/run-probe.sh" --self-test
    else
        PBNS_GATEWAY_LISTEN="${PBNS_GATEWAY_LISTEN:-${PBNS_ECHO_LISTEN:-0.0.0.0:8443}}" \
        PBNS_GATEWAY_SERVER_NAME="$PHYSICAL_SERVER_NAME" \
            "$PBNS_ROOT/integration/qemu/run-probe.sh" --require-hardware
    fi
}

if [[ $MODE == --provision-now ]]; then
    provision_now
    exit 0
fi
if [[ $MODE == --require-hardware ]]; then
    verify_post_provision_inputs
fi
run_stage "byte-pump" verify_byte_pump
if [[ $MODE == --require-hardware ]]; then
    "$PBNS_ROOT/build/dev/pbns-pico-record-validate" "$RECORD" "$EXPECTED_SPKI"
fi
run_stage "pico-build" build_pico
run_stage "uefi-build" build_uefi
run_stage "gateway-race" verify_gateway_race
run_stage "proxy-sim" verify_proxy_sim
run_stage "pico-loopback" verify_pico_loopback
run_stage "qemu-probe" verify_qemu_probe

if [[ $MODE == --software-only ]]; then
    printf '%s\n' '[DEFERRED] physical transport: provisioning, WiFi, pinned-SPKI TLS, reconnect, throughput, cancellation, and UEFI USB loopback require hardware'
    printf '%s\n' 'TRANSPORT SOFTWARE-ONLY CHECKS PASS; HARDWARE DEFERRED'
    exit 0
fi
printf '[PASS] hardware results are redacted under %s\n' "$PBNS_ROOT/integration/state/results"
printf '%s\n' 'TRANSPORT PASS'
