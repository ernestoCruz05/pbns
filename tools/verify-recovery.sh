#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --require-hardware && $1 != --hosted-only ) ]]; then
    printf 'usage: %s [--require-hardware|--hosted-only]\n' "$0" >&2
    exit 2
fi
require_hardware=0
hosted_only=0
if [[ $# -eq 1 && $1 == --require-hardware ]]; then
    require_hardware=1
elif [[ $# -eq 1 && $1 == --hosted-only ]]; then
    hosted_only=1
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/.." && pwd -P)
state_root="$pbns_root/integration/state"
mkdir -p "$state_root"
all_passed=true

pass() {
    printf '[PASS] %s\n' "$1"
}
blocked() {
    printf '[BLOCKED] %s — %s\n' "$1" "$2"
    all_passed=false
}

run_uki_policy() {
    if python3 -m unittest "$pbns_root/tools/tests/test_recovery_policy.py" -q; then
        pass uki-policy
    else
        blocked uki-policy 'read-only UKI source policy failed'
    fi
}

if ctest --test-dir "$pbns_root/build/dev" --output-on-failure \
    -R 'launcher-policy|boot-config'; then
    pass launcher
else
    blocked launcher 'hosted launcher tests failed'
fi
if ctest --test-dir "$pbns_root/build/dev" --output-on-failure \
    -R '^recovery-manifest$'; then
    pass manifest
else
    blocked manifest 'manifest tests failed'
fi
if ctest --test-dir "$pbns_root/build/dev" --output-on-failure \
    -R '^recovery-stream$|^recovery-client$'; then
    pass stream
else
    blocked stream 'stream/client tests failed'
fi

if (
    cd "$pbns_root/gateway"
    go test -race ./internal/server ./cmd/pbns-gateway \
        -run 'TestRecoveryEndToEnd' -count=1
); then
    pass live-recovery-service
else
    blocked live-recovery-service 'hosted TLS/proxy recovery integration failed'
fi

if (( hosted_only == 1 )); then
    run_uki_policy
    blocked anti-rollback 'not-run; hosted-only mode does not start swtpm'
    blocked secureboot-memory-load 'not-run; hosted-only mode does not start QEMU'
    blocked disk-immutability 'not-run; hosted-only mode does not run the recovery disk matrix'
    blocked normal-pico-absent 'not-run; launcher runtime matrix has not run'
    blocked physical-recovery 'not-run; hosted-only mode never runs physical recovery'
    printf '%s\n' 'RECOVERY BLOCKED'
    exit 1
fi

anti_state="$state_root/verify-recovery-swtpm-$$"
anti_cleanup() {
    "$pbns_root/integration/swtpm/stop-swtpm.sh" "$anti_state" \
        >/dev/null 2>&1 || true
}
trap anti_cleanup EXIT
if "$pbns_root/integration/swtpm/start-swtpm.sh" "$anti_state" >/dev/null &&
   "$pbns_root/integration/swtpm/run-recovery-policy.sh" "$anti_state" \
        >/dev/null; then
    pass anti-rollback
else
    blocked anti-rollback 'disposable swtpm policy gate failed'
fi
anti_cleanup
trap - EXIT

run_uki_policy

matrix_log=$(mktemp "$state_root/recovery-matrix.XXXXXX.log")
chmod 0600 "$matrix_log"
policy_runtime_passed=false
if "$pbns_root/integration/qemu/run-recovery-matrix.sh" \
    >"$matrix_log" 2>&1; then
    if [[ ${PBNS_RECOVERY_POLICY_ONLY:-NO} == YES ]]; then
        pass uki-policy-runtime
        policy_runtime_passed=true
        blocked secureboot-memory-load 'policy-only run does not test Secure Boot handoff'
    else
        pass secureboot-memory-load
    fi
else
    blocked secureboot-memory-load "$(tail -1 "$matrix_log")"
fi
rm -f -- "$matrix_log"

hash_dir=$(mktemp -d "$state_root/hash-self-test.XXXXXX")
chmod 0700 "$hash_dir"
hash_image="$hash_dir/disposable.raw"
printf '%s' 'PBNS immutable disposable disk fixture' >"$hash_image"
chmod 0600 "$hash_image"
before=$("$pbns_root/tools/hash-disk-image.sh" "$hash_image" | awk '{ print $1 }')
after=$("$pbns_root/tools/hash-disk-image.sh" "$hash_image" | awk '{ print $1 }')
if [[ $policy_runtime_passed == true ]]; then
    pass disk-immutability
elif [[ $before == "$after" ]]; then
    blocked disk-immutability 'hash helper self-test passed; recovery disk matrix not run'
else
    blocked disk-immutability 'self-test hash changed'
fi
rm -rf -- "$hash_dir"

blocked normal-pico-absent 'launcher runtime matrix has not run'
if (( require_hardware == 1 )); then
    if "$pbns_root/integration/physical/run-recovery.sh"; then
        pass physical-recovery
    else
        blocked physical-recovery 'reviewed mode-0600 physical result is required'
    fi
else
    blocked physical-recovery 'not-run; use --require-hardware with reviewed evidence'
fi

if [[ $all_passed == true ]]; then
    printf '%s\n' 'RECOVERY PASS'
    exit 0
fi
printf '%s\n' 'RECOVERY BLOCKED'
exit 1
