#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
DRIVER="$SCRIPT_DIR/raw-tunnel-diagnostic.py"
TLS_DRIVER="$SCRIPT_DIR/uefi-tls-tunnel.py"
LOCK="$SCRIPT_DIR/raw-tunnel-diagnostic-lock.json"
DIAGNOSTIC_UF2="$PBNS_ROOT/pico/build-raw-diagnostic/pbns-raw-tunnel-diagnostic.uf2"
PRODUCTION_RAW="$PBNS_ROOT/pico/build/pbns-proxy.uf2"
ROLLBACK_UF2="$PBNS_ROOT/integration/state/rollback-artifacts/stage6/f388ceb17afa441d916dc6c41c278ccf583e8668f7f2387b32e0f0bbaf5cae74.uf2"
STOP_ATTEMPTS=50
SERVER_PID=
CLIENT_PID=
STATE_DIR=
ROLLBACK_REQUIRED=0

if ! command -v ps >/dev/null 2>&1; then
    printf '%s\n' 'required process-status tool is unavailable' >&2
    exit 1
fi

pid_is_running() {
    local pid=$1
    local state
    kill -0 "$pid" 2>/dev/null || return 1
    state=$(ps -o stat= -p "$pid" 2>/dev/null || true)
    [[ -n $state && $state != Z* ]]
}

stop_pid() {
    local variable=$1
    local pid=${!variable:-}
    printf -v "$variable" '%s' ''
    if [[ -z $pid ]]; then
        return 0
    fi
    if pid_is_running "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        for ((attempt = 0; attempt < STOP_ATTEMPTS; ++attempt)); do
            if ! pid_is_running "$pid"; then
                wait "$pid" 2>/dev/null || true
                return 0
            fi
            sleep 0.1
        done
        kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

wait_pid_bounded() {
    local variable=$1
    local attempts=$2
    local pid=${!variable:-}
    local status=0
    if [[ -z $pid ]]; then
        return 1
    fi
    for ((attempt = 0; attempt < attempts; ++attempt)); do
        if ! pid_is_running "$pid"; then
            if wait "$pid"; then
                status=0
            else
                status=$?
            fi
            printf -v "$variable" '%s' ''
            return "$status"
        fi
        sleep 0.1
    done
    stop_pid "$variable"
    return 124
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    stop_pid CLIENT_PID
    stop_pid SERVER_PID
    if [[ -n $STATE_DIR && -d $STATE_DIR ]]; then
        rm -rf -- "$STATE_DIR"
    fi
    if ((ROLLBACK_REQUIRED != 0)); then
        printf '%s\n' '[ROLLBACK REQUIRED] restore and verify exact Stage 6 before diagnosis' >&2
    fi
    return "$status"
}
handle_signal() {
    local number=$1
    exit $((128 + number))
}
trap cleanup EXIT
trap 'handle_signal 2' INT
trap 'handle_signal 15' TERM

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
    sleep 300 &
    SERVER_PID=$!
    printf '%s\n' "$SERVER_PID" >"$PBNS_CLEANUP_TEST_PID_FILE"
    wait "$SERVER_PID"
    exit 1
fi
if [[ $1 == --wait-timeout-self-test ]]; then
    sleep 300 &
    SERVER_PID=$!
    status=0
    wait_pid_bounded SERVER_PID 2 || status=$?
    if ((status != 124)) || [[ -n $SERVER_PID ]]; then
        exit 1
    fi
    printf '%s\n' 'RAW TUNNEL DIAGNOSTIC WAIT TIMEOUT PASS'
    exit 0
fi
if [[ $1 == --self-test ]]; then
    python3 "$DRIVER" self-test
    python3 "$TLS_DRIVER" self-test
    python3 -m unittest \
        "$PBNS_ROOT/tools/tests/test_raw_tunnel_diagnostic.py" \
        "$PBNS_ROOT/tools/tests/test_pico_raw_diagnostic.py" \
        "$PBNS_ROOT/tools/tests/test_verify_uf2_range.py" -v
    printf '%s\n' 'RAW TUNNEL DIAGNOSTIC SOFTWARE PASS'
    exit 0
fi
if [[ $1 != --require-hardware ]]; then
    usage
    exit 2
fi

required=(
    PBNS_RAW_DIAGNOSTIC_AUTHORIZED
    PBNS_RAW_DIAGNOSTIC_RUN_DIR
    PBNS_RAW_DIAGNOSTIC_LISTEN
    PBNS_RAW_DIAGNOSTIC_CERTIFICATE
    PBNS_RAW_DIAGNOSTIC_PRIVATE_KEY
    PBNS_RAW_DIAGNOSTIC_PIN
)
for name in "${required[@]}"; do
    if [[ -z ${!name:-} ]]; then
        printf 'missing diagnostic setting: %s\n' "$name" >&2
        exit 2
    fi
done
if [[ $PBNS_RAW_DIAGNOSTIC_AUTHORIZED != exactly-one-reviewed-run ]]; then
    printf '%s\n' 'separate physical diagnostic authorization is absent' >&2
    exit 2
fi

python3 "$DRIVER" verify-lock \
    --lock "$LOCK" \
    --uf2 "$DIAGNOSTIC_UF2" \
    --rollback "$ROLLBACK_UF2" \
    --production-raw "$PRODUCTION_RAW"

STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-raw-diagnostic.XXXXXX")
chmod 700 "$STATE_DIR"
EVENT_JOURNAL="$STATE_DIR/server-events.jsonl"
CLIENT_STATE="$STATE_DIR/client.json"
SERVER_LOG="$STATE_DIR/server.log"
ROLLBACK_REQUIRED=1

python3 "$TLS_DRIVER" diagnostic-server \
    --listen "$PBNS_RAW_DIAGNOSTIC_LISTEN" \
    --certificate "$PBNS_RAW_DIAGNOSTIC_CERTIFICATE" \
    --private-key "$PBNS_RAW_DIAGNOSTIC_PRIVATE_KEY" \
    --event-journal "$EVENT_JOURNAL" \
    --timeout 60 >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _attempt in $(seq 1 200); do
    if [[ -s $EVENT_JOURNAL ]] && grep -Fq '"ready":true' "$EVENT_JOURNAL"; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        printf '%s\n' 'diagnostic server failed before readiness' >&2
        exit 1
    fi
    sleep 0.05
done
if [[ ! -s $EVENT_JOURNAL ]] ||
   ! grep -Fq '"ready":true' "$EVENT_JOURNAL"; then
    printf '%s\n' 'diagnostic server readiness timed out' >&2
    exit 1
fi

client_status=0
python3 "$DRIVER" client \
    --state-file "$CLIENT_STATE" \
    --pin "$PBNS_RAW_DIAGNOSTIC_PIN" \
    --expected-san 192.168.1.180 \
    --timeout 60 &
CLIENT_PID=$!
wait_pid_bounded CLIENT_PID 1000 || client_status=$?
server_status=0
wait_pid_bounded SERVER_PID 600 || server_status=$?

python3 "$DRIVER" publish-diagnostic \
    --run-dir "$PBNS_RAW_DIAGNOSTIC_RUN_DIR" \
    --client-state "$CLIENT_STATE" \
    --event-journal "$EVENT_JOURNAL" \
    --uf2 "$DIAGNOSTIC_UF2" \
    --lock "$LOCK" \
    --rollback "$ROLLBACK_UF2" \
    --production-raw "$PRODUCTION_RAW"
rm -rf -- "$STATE_DIR"
STATE_DIR=

printf '[DIAGNOSTIC RECORDED] client=%s server=%s\n' \
    "$client_status" "$server_status"
printf '%s\n' '[ROLLBACK REQUIRED] enter BOOTSEL, restore exact Stage 6, then record rollback.json'
exit 3
