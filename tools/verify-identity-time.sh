#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)
REQUIRE_PHYSICAL=0
if (( $# > 1 )); then
    printf 'usage: %s [--require-physical-tpm]\n' "$0" >&2
    exit 2
fi
if (( $# == 1 )); then
    [[ $1 == --require-physical-tpm ]] || {
        printf 'usage: %s [--require-physical-tpm]\n' "$0" >&2
        exit 2
    }
    REQUIRE_PHYSICAL=1
fi
if [[ -z ${PBNS_EDK2_DIR:-} ]]; then
    printf '%s\n' 'PBNS_EDK2_DIR is required for qemu-swtpm gates' >&2
    exit 2
fi
if [[ $PBNS_EDK2_DIR != /* && ! -d $PBNS_EDK2_DIR ]]; then
    PBNS_EDK2_DIR="$REPO_ROOT/$PBNS_EDK2_DIR"
fi
PBNS_EDK2_DIR=$(cd -- "$PBNS_EDK2_DIR" && pwd -P)

printf '%s\n' '[RUN] store'
(
    cd -- "$PBNS_ROOT/gateway"
    go test -race ./internal/store ./internal/token ./cmd/pbnsctl -count=5
)
printf '%s\n' '[PASS] store'

printf '%s\n' '[RUN] identity'
ctest --test-dir "$PBNS_ROOT/build/dev" --output-on-failure \
    -R 'identity|tss2-tcti'
printf '%s\n' '[PASS] identity'

printf '%s\n' '[RUN] tpm-policy'
ctest --test-dir "$PBNS_ROOT/build/dev" --output-on-failure \
    -R 'tpm-policy|tpm-storage'
printf '%s\n' '[PASS] tpm-policy'

printf '%s\n' '[RUN] enrollment-negative'
(
    cd -- "$PBNS_ROOT/gateway"
    go test -race ./internal/enrollment ./internal/store -count=5
)
ctest --test-dir "$PBNS_ROOT/build/dev" --output-on-failure -R enrollment
printf '%s\n' '[PASS] enrollment-negative'

printf '%s\n' '[RUN] time-negative'
(
    cd -- "$PBNS_ROOT/gateway"
    go test -race ./internal/time ./internal/keys -count=5
)
ctest --test-dir "$PBNS_ROOT/build/dev" --output-on-failure -R trusted-time
if rg -n \
    'SetTime|gRT->SetTime|GetPerformanceCounter|GetPerformanceCounterProperties|GetTimeInNanoSecond|BaseCpuTimerLib' \
    "$PBNS_ROOT/src" "$PBNS_ROOT/uefi" "$PBNS_ROOT/PbnsPkg.dsc"; then
    printf '%s\n' 'forbidden RTC/performance-counter path found' >&2
    exit 1
fi
printf '%s\n' '[PASS] time-negative'

printf '%s\n' '[RUN] uefi-debug'
PBNS_BUILD_TARGET=DEBUG "$PBNS_ROOT/tools/build-uefi.sh"
printf '%s\n' '[PASS] uefi-debug'

printf '%s\n' '[RUN] qemu-swtpm'
for mode in s t; do
    PBNS_ENROLLMENT_LOCAL_MODE=$mode \
        "$PBNS_ROOT/integration/qemu/run-enrollment-local-probe.sh"
    PBNS_TIME_LIVE_LOCAL_MODE=$mode \
        "$PBNS_ROOT/integration/qemu/run-time-live-local-probe.sh"
done
printf '%s\n' '[PASS] qemu-swtpm'

if (( REQUIRE_PHYSICAL == 1 )); then
    printf '%s\n' '[RUN] physical-tpm'
    "$PBNS_ROOT/integration/physical/run-identity-time.sh"
    printf '%s\n' '[PASS] physical-tpm'
    printf '%s\n' 'IDENTITY TIME PASS'
else
    printf '%s\n' '[SKIP] physical-tpm — PHYSICAL GATE REQUIRED'
    printf '%s\n' 'IDENTITY TIME SOFTWARE GATES PASS'
fi
