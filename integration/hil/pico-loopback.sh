#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
LOOPBACK="$SCRIPT_DIR/pico-loopback.py"
TLS_DRIVER="$SCRIPT_DIR/uefi-tls-tunnel.py"
RAW_UF2_SHA256=e99ced85ba0c91c3b8d914ec3fcd7b7b5531e81a87a72830e181eb43de3ecd14
UEFI_PROBE_SHA256=245db7d544efcd4f2fb8d69f292d14bf5bf1f4aac81ed07e4ec6f301da5ce1c7
ARTIFACT_SHA256=d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3
EXPECTED_SERIAL=E66130100F527A26
EXPECTED_SAN=192.168.1.180
DIRECT_BYTES=1048576
WARMUP_BYTES=65536
ARTIFACT_BYTES=26553920
STOP_GRACE_ATTEMPTS=50
CONNECT_DELAY_SECONDS=3
CDC_SETTLE_SECONDS=1
SERVER_PID=
CLIENT_PID=
SIGNAL_STATUS=0

stop_tracked_pid() {
    local variable=$1
    local pid=${!variable:-}
    printf -v "$variable" '%s' ''
    if [[ -z $pid ]] || ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        return 0
    fi
    kill -TERM "$pid" 2>/dev/null || true
    for (( attempt = 0; attempt < STOP_GRACE_ATTEMPTS; ++attempt )); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

usage() {
    printf 'usage: %s --self-test | --require-hardware\n' "$0" >&2
}

if (( $# != 1 )); then
    usage
    exit 2
fi

if [[ $1 == --cleanup-self-test ]]; then
    if [[ -z ${PBNS_CLEANUP_TEST_PID_FILE:-} ]]; then
        exit 2
    fi
    trap 'stop_tracked_pid CLIENT_PID; exit 143' TERM
    sleep 300 &
    CLIENT_PID=$!
    printf '%s\n' "$CLIENT_PID" >"$PBNS_CLEANUP_TEST_PID_FILE"
    wait "$CLIENT_PID"
    exit 1
fi

if [[ $1 == --self-test ]]; then
    python3 "$LOOPBACK" self-test
    python3 -m unittest discover -s "$PBNS_ROOT/tools/tests" -p "test_pico_loopback.py" -v
    python3 -m unittest discover -s "$PBNS_ROOT/tools/tests" -p "test_uefi_tls_transport.py" -v
    printf '%s\n' 'PICO RAW TUNNEL SOFTWARE PASS'
    exit 0
fi
if [[ $1 != --require-hardware ]]; then
    usage
    exit 2
fi

required=(
    PBNS_CDC0_PORT
    PBNS_PROVISION_PORT
    PBNS_PICO_SERIAL
    PBNS_GATEWAY_SERVER_NAME
)
for name in "${required[@]}"; do
    if [[ -z ${!name:-} ]]; then
        printf 'missing required hardware setting: %s\n' "$name" >&2
        exit 2
    fi
done
if [[ $PBNS_CDC0_PORT != /dev/ttyACM0 ||
      $PBNS_PROVISION_PORT != /dev/ttyACM1 ||
      $PBNS_PICO_SERIAL != "$EXPECTED_SERIAL" ||
      $PBNS_GATEWAY_SERVER_NAME != "$EXPECTED_SAN" ]]; then
    printf '%s\n' 'physical identity inputs do not match the reviewed profile' >&2
    exit 2
fi

FIRMWARE_UF2="$PBNS_ROOT/pico/build/pbns-proxy.uf2"
UEFI_PROBE="$PBNS_ROOT/.deps/edk2/Build/PbnsPkg/RELEASE_GCC/X64/PbnsTlsProbe.efi"
ARTIFACT=${PBNS_RECOVERY_ARTIFACT:-$PBNS_ROOT/integration/state/task14c-signed-final-20260810T022831Z.DBx3aC/cases/signed-trusted/repository/artifacts/$ARTIFACT_SHA256}
PIN="$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-spki.sha256"
SERVER_KEY="$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-key.pem"
RESULTS_ROOT="$PBNS_ROOT/integration/state/results"
LISTEN_ADDRESS=0.0.0.0:8443
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-uefi-tls-raw.XXXXXX")
chmod 700 "$STATE_DIR"
RUN_DIR=
FAILED=1

stop_server() {
    stop_tracked_pid SERVER_PID
}

wait_server_success() {
    local pid=$SERVER_PID
    local status=0
    if [[ -z $pid ]]; then
        return 1
    fi
    wait "$pid" || status=$?
    SERVER_PID=
    return "$status"
}

cleanup() {
    local saved=$?
    trap - EXIT INT TERM
    stop_tracked_pid CLIENT_PID
    stop_server
    if (( FAILED != 0 )) && [[ -n $RUN_DIR && -d $RUN_DIR && ! -e $RUN_DIR/rollback-needed.json ]]; then
        python3 "$LOOPBACK" publish-failure \
            --results-dir "$RUN_DIR" --error-code "$([[ $SIGNAL_STATUS -ne 0 ]] && printf signal || printf internal)" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$STATE_DIR"
    if (( FAILED != 0 )); then
        printf '%s\n' '[FAIL] raw-tunnel gate stopped; controlled Stage 6 rollback is required' >&2
    fi
    return "$saved"
}
handle_signal() {
    local number=$1
    SIGNAL_STATUS=$((128 + number))
    stop_tracked_pid CLIENT_PID
    stop_server
    exit "$SIGNAL_STATUS"
}
trap cleanup EXIT
trap 'handle_signal 2' INT
trap 'handle_signal 15' TERM

RUN_DIR=$(python3 "$LOOPBACK" create-run --results-root "$RESULTS_ROOT")

python3 "$LOOPBACK" raw-preflight \
    --cdc0 "$PBNS_CDC0_PORT" \
    --cdc1 "$PBNS_PROVISION_PORT" \
    --expected-serial "$PBNS_PICO_SERIAL" \
    --expected-san "$PBNS_GATEWAY_SERVER_NAME" \
    --firmware "$FIRMWARE_UF2" \
    --uefi-probe "$UEFI_PROBE" \
    --artifact "$ARTIFACT" \
    --pin "$PIN"

"$PBNS_ROOT/integration/tls/make-test-pki.sh" \
    "$STATE_DIR/test-pki" "$PBNS_GATEWAY_SERVER_NAME" \
    >"$STATE_DIR/pki.log" 2>&1
CORRECT_CERT="$STATE_DIR/test-pki/gateway-reissued-cert.pem"
WRONG_SPKI_CERT="$STATE_DIR/test-pki/wrong-key-cert.pem"
WRONG_SPKI_KEY="$STATE_DIR/test-pki/wrong-key.pem"
WRONG_SAN_CERT="$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-cert.pem"

start_server() {
    local certificate=$1
    local key=$2
    local variant=$3
    local ready="$STATE_DIR/server.ready"
    local proof="$STATE_DIR/wrong-cipher.proof"
    local proof_args=()
    stop_server
    rm -f -- "$ready"
    if [[ $variant == wrong-cipher ]]; then
        if [[ -e $proof || -L $proof ]]; then
            printf '%s\n' 'wrong-cipher proof path is not fresh' >&2
            return 1
        fi
        proof_args=(--cipher-proof "$proof")
    fi
    python3 "$TLS_DRIVER" server \
        --listen "$LISTEN_ADDRESS" \
        --certificate "$certificate" \
        --private-key "$key" \
        --artifact "$ARTIFACT" \
        --ready-file "$ready" \
        --variant "$variant" \
        "${proof_args[@]}" \
        >"$STATE_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    for _attempt in $(seq 1 100); do
        if [[ -f $ready ]]; then
            sleep 2
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            printf '%s\n' 'raw TLS test server failed' >&2
            return 1
        fi
        sleep 0.05
    done
    printf '%s\n' 'raw TLS test server readiness timed out' >&2
    return 1
}

client_trial() {
    local trial=$1
    local filename=$2
    local mode=$3
    local total_bytes=$4
    local expected_digest=$5
    shift 5
    python3 "$TLS_DRIVER" client \
        --port "$PBNS_CDC0_PORT" \
        --mode "$mode" \
        --total-bytes "$total_bytes" \
        --expected-sha256 "$expected_digest" \
        --expected-san "$PBNS_GATEWAY_SERVER_NAME" \
        --expected-serial "$PBNS_PICO_SERIAL" \
        --pin "$PIN" \
        --results-dir "$RUN_DIR" \
        --filename "$filename" \
        --trial "$trial" \
        --connect-delay "$CONNECT_DELAY_SECONDS" \
        "$@" &
    CLIENT_PID=$!
    local client_status=0
    wait "$CLIENT_PID" || client_status=$?
    CLIENT_PID=
    if (( client_status != 0 )); then
        return "$client_status"
    fi
    sleep "$CDC_SETTLE_SECONDS"
}

WARMUP_DIGEST=$(python3 "$TLS_DRIVER" deterministic-digest --bytes "$WARMUP_BYTES")
DIRECT_DIGEST=$(python3 "$TLS_DRIVER" deterministic-digest --bytes "$DIRECT_BYTES")
RECONNECT_BYTES=131072
RECONNECT_DIGEST=$(python3 "$TLS_DRIVER" deterministic-digest --bytes "$RECONNECT_BYTES")

start_server "$CORRECT_CERT" "$SERVER_KEY" normal
client_trial upstream upstream-warmup.json upstream "$WARMUP_BYTES" "$WARMUP_DIGEST" --warmup
client_trial downstream downstream-warmup.json downstream "$WARMUP_BYTES" "$WARMUP_DIGEST" --warmup
client_trial upstream upstream.json upstream "$DIRECT_BYTES" "$DIRECT_DIGEST"
client_trial downstream downstream.json downstream "$DIRECT_BYTES" "$DIRECT_DIGEST"
client_trial artifact artifact.json artifact "$ARTIFACT_BYTES" "$ARTIFACT_SHA256" --timeout 180
client_trial cancellation cancellation.json upstream "$RECONNECT_BYTES" "$RECONNECT_DIGEST" \
    --cancel-after 8192 --expected-rejection cancelled
sleep 2
client_trial fresh-reconnect fresh-reconnect.json downstream "$RECONNECT_BYTES" "$RECONNECT_DIGEST"
stop_server

start_server "$WRONG_SAN_CERT" "$SERVER_KEY" normal
client_trial wrong-san wrong-san.json downstream "$WARMUP_BYTES" "$WARMUP_DIGEST" \
    --expected-rejection wrong-san
stop_server

start_server "$WRONG_SPKI_CERT" "$WRONG_SPKI_KEY" normal
client_trial wrong-spki wrong-spki.json downstream "$WARMUP_BYTES" "$WARMUP_DIGEST" \
    --expected-rejection wrong-spki
stop_server

start_server "$CORRECT_CERT" "$SERVER_KEY" wrong-alpn
client_trial wrong-alpn wrong-alpn.json downstream "$WARMUP_BYTES" "$WARMUP_DIGEST" \
    --expected-rejection wrong-alpn
stop_server

start_server "$CORRECT_CERT" "$SERVER_KEY" wrong-cipher
client_trial wrong-cipher wrong-cipher.json downstream "$WARMUP_BYTES" "$WARMUP_DIGEST" \
    --expected-rejection wrong-cipher --cipher-proof "$STATE_DIR/wrong-cipher.proof"
wait_server_success

start_server "$CORRECT_CERT" "$SERVER_KEY" truncation
client_trial truncation truncation.json downstream "$WARMUP_BYTES" "$WARMUP_DIGEST" \
    --expected-rejection truncated
stop_server

start_server "$CORRECT_CERT" "$SERVER_KEY" digest-mismatch
client_trial digest-mismatch digest-mismatch.json downstream "$WARMUP_BYTES" "$WARMUP_DIGEST" \
    --expected-rejection digest-mismatch
stop_server

python3 "$TLS_DRIVER" validate-results --results-dir "$RUN_DIR"
FAILED=0
printf '[PASS] locked raw UF2 %s and UEFI probe provenance %s\n' \
    "$RAW_UF2_SHA256" "$UEFI_PROBE_SHA256"
printf '[PASS] exact USB identity, CDC0 data role, and CDC1 verification-only role\n'
printf '[PASS] warmed upstream and downstream are each at least 0.60 MiB/s\n'
printf '[PASS] exact %s-byte downstream artifact digest %s\n' \
    "$ARTIFACT_BYTES" "$ARTIFACT_SHA256"
printf '[PASS] wrong-san, wrong-spki, wrong-alpn, wrong-cipher, cancellation, fresh-reconnect, truncation, digest-mismatch\n'
printf '[LIMITATION] %s models the UEFI TLS wire profile; UEFI execution is %s until Task 6\n' \
    host-python-ssl-memorybio not-run
printf '[PASS] sanitized HIL metadata %s\n' "$RUN_DIR"
printf '%s\n' 'PICO RAW TUNNEL HARDWARE PASS'
