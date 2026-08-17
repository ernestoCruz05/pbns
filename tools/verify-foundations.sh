#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
GATEWAY_ROOT="$PBNS_ROOT/gateway"
DEV_BUILD="$PBNS_ROOT/build/dev"
CLANG_BUILD="$PBNS_ROOT/build/dev-clang"
SAN_BUILD="$PBNS_ROOT/build/san"
TSAN_BUILD="$PBNS_ROOT/build/tsan"
PROJECT_TESTS='^(identity|identity-record|software-identity|primitives|frame|record-reader|stream|broker|byte-pump|usb-transport|uefi-clock-math|credentials|pico-record-validate|diagnostic|spki-pin|tls-policy|tls-handshake-observer|tls-transport|reconnect|provision-gate|entropy|object|sign1|encrypt)$'

if [[ -d /usr/lib/llvm/22/bin ]]; then
    PATH="/usr/lib/llvm/22/bin:$PATH"
else
    for llvm_bin in /usr/lib/llvm/*/bin; do
        if [[ -d "$llvm_bin" ]]; then
            PATH="$llvm_bin:$PATH"
        fi
    done
fi
export PATH

run_stage() {
    local name=$1
    shift
    "$@"
    printf '[PASS] %s\n' "$name"
}

stage_dependency_lock() {
    python3 -m unittest discover -s "$SCRIPT_DIR/tests" -v
    python3 "$SCRIPT_DIR/check_dependencies.py" \
        --root "$PBNS_ROOT" --verify-submodules --verify-licenses
    python3 "$SCRIPT_DIR/make_frame_vectors.py" \
        --verify "$PBNS_ROOT/tests/vectors/frame-v1.json"
}

configure_build() {
    local build_dir=$1
    local c_compiler=$2
    local cxx_compiler=$3
    local sanitizer=$4
    cmake -S "$PBNS_ROOT" -B "$build_dir" -G Ninja \
        -DCMAKE_C_COMPILER="$c_compiler" \
        -DCMAKE_CXX_COMPILER="$cxx_compiler" \
        -DPBNS_WERROR=ON \
        -DPBNS_SANITIZE="$sanitizer"
}

stage_dev() {
    rm -rf -- "$DEV_BUILD" "$CLANG_BUILD"
    configure_build "$DEV_BUILD" gcc g++ ""
    cmake --build "$DEV_BUILD" -j2
    ctest --test-dir "$DEV_BUILD" --output-on-failure

    configure_build "$CLANG_BUILD" clang clang++ ""
    cmake --build "$CLANG_BUILD" -j2
    ctest --test-dir "$CLANG_BUILD" --output-on-failure
}

stage_sanitize() {
    rm -rf -- "$SAN_BUILD" "$TSAN_BUILD"
    configure_build "$SAN_BUILD" clang clang++ address,undefined
    cmake --build "$SAN_BUILD" -j2
    ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:strict_string_checks=1 \
        UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
        ctest --test-dir "$SAN_BUILD" --output-on-failure -R "$PROJECT_TESTS"

    configure_build "$TSAN_BUILD" clang clang++ thread
    cmake --build "$TSAN_BUILD" --target pbns-test-encrypt -j2
    TSAN_OPTIONS=halt_on_error=1 \
        ctest --test-dir "$TSAN_BUILD" --output-on-failure -R '^encrypt$'
}

stage_go() {
    (
        cd -- "$GATEWAY_ROOT"
        go test -mod=readonly -count=1 ./...
        go vet -mod=readonly ./...
    )
}

stage_race() {
    (
        cd -- "$GATEWAY_ROOT"
        CGO_ENABLED=1 go test -mod=readonly -race -count=1 ./...
    )
}

stage_interop() {
    cmake --build "$DEV_BUILD" --target \
        pbns-cose-upstream-tests pbns-cose-vectors -j2
    ctest --test-dir "$DEV_BUILD" --output-on-failure -R '^encrypt$'
    ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 \
        UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
        ctest --test-dir "$SAN_BUILD" --output-on-failure -R '^encrypt$'
    (
        cd -- "$GATEWAY_ROOT"
        CGO_ENABLED=1 go test -mod=readonly ./internal/cosebridge -count=100
    )
    (
        cd -- "$PBNS_ROOT"
        printf '%s\n' \
            '2ec45eacfd581bdcf0ddc5afd0c619123621ffa580bc94c842395b59fa34ddd2  tests/vectors/cose-encrypt-v1/cosec-to-tcose.cbor' \
            'b37b3d7543e53db14459d6fa7eed966fd8e74e3ea4b42867be5e6fc495b9c5c4  tests/vectors/cose-encrypt-v1/tcose-to-cosec.cbor' \
            | sha256sum -c -
    )
}

run_stage "dependency-lock" stage_dependency_lock
run_stage "dev" stage_dev
run_stage "sanitize" stage_sanitize
run_stage "go" stage_go
run_stage "race" stage_race
run_stage "interop" stage_interop
printf '%s\n' '[DEFERRED] parser-robustness: blocked by platform execution policy; no campaign evidence'
printf '%s\n' 'FOUNDATIONS CONDITIONAL PASS'
