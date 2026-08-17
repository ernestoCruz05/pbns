#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
    printf 'usage: %s --self-test\n' "$0" >&2
    exit 2
fi
if [[ "$1" != --self-test ]]; then
    printf 'usage: %s --self-test\n' "$0" >&2
    exit 2
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
GATEWAY_ROOT=$(cd -- "$SCRIPT_DIR/../gateway" && pwd -P)
(
    cd -- "$GATEWAY_ROOT"
    go test -race -count=1 \
        ./internal/proxysim \
        ./internal/server \
        ./cmd/pbns-proxy-sim
    go test -race ./internal/server ./cmd/pbns-gateway \
        -run 'TestRecoveryEndToEnd' -count=1
)
printf '%s\n' 'PROXY SIM PASS'
