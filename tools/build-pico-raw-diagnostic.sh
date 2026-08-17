#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# != 0 )); then
    printf 'usage: %s\n' "$0" >&2
    exit 2
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)
PICO_ROOT="$PBNS_ROOT/pico"
BUILD_DIR="$PICO_ROOT/build-raw-diagnostic"
LOCK_FILE="$PBNS_ROOT/dependencies.lock"
PICOTOOL_PATH="$PBNS_ROOT/.deps/picotool"
PRODUCTION_UF2="$PICO_ROOT/build/pbns-proxy.uf2"
ROLLBACK_UF2="$PBNS_ROOT/integration/state/rollback-artifacts/stage6/f388ceb17afa441d916dc6c41c278ccf583e8668f7f2387b32e0f0bbaf5cae74.uf2"
DIAGNOSTIC_LOCK="$PBNS_ROOT/integration/hil/raw-tunnel-diagnostic-lock.json"
EXPECTED_PRODUCTION_SHA256=e99ced85ba0c91c3b8d914ec3fcd7b7b5531e81a87a72830e181eb43de3ecd14
EXPECTED_PRODUCTION_SIZE=792576

for tool in git cmake ninja arm-none-eabi-nm arm-none-eabi-objdump \
    arm-none-eabi-size arm-none-eabi-strings sha256sum python3 stat; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing raw diagnostic build tool: %s\n' "$tool" >&2
        exit 1
    }
done
if [[ -z ${PICO_SDK_PATH:-} ]]; then
    printf '%s\n' 'PICO_SDK_PATH is required' >&2
    exit 2
fi
PICO_SDK_PATH=$(cd -- "$PICO_SDK_PATH" && pwd -P)
export PICO_SDK_PATH

lock_revision() {
    local dependency=$1
    awk -F'|' -v dependency="$dependency" \
        '$1 == dependency { print $3; found = 1 } END { if (!found) exit 1 }' \
        "$LOCK_FILE"
}

"$SCRIPT_DIR/build-pico.sh"
if [[ $(sha256sum "$PRODUCTION_UF2" | awk '{print $1}') != \
      "$EXPECTED_PRODUCTION_SHA256" ||
      $(stat -c %s "$PRODUCTION_UF2") != "$EXPECTED_PRODUCTION_SIZE" ]]; then
    printf '%s\n' 'production raw artifact changed while building diagnostic' >&2
    exit 1
fi

export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)
rm -rf -- "$BUILD_DIR"
cmake -S "$PICO_ROOT" -B "$BUILD_DIR" -G Ninja \
    -DPICO_SDK_PATH="$PICO_SDK_PATH" \
    -DPICOTOOL_GIT_REPOSITORY_URL="$PICOTOOL_PATH" \
    -DPICOTOOL_GIT_BRANCH="$(lock_revision picotool)" \
    -DPBNS_BUILD_RAW_TUNNEL_DIAGNOSTIC=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build "$BUILD_DIR" --target pbns-raw-tunnel-diagnostic -j2

ELF="$BUILD_DIR/pbns-raw-tunnel-diagnostic.elf"
MAP="$BUILD_DIR/pbns-raw-tunnel-diagnostic.elf.map"
UF2="$BUILD_DIR/pbns-raw-tunnel-diagnostic.uf2"
for artifact in "$ELF" "$MAP" "$UF2"; do
    [[ -f $artifact ]] || {
        printf 'missing raw diagnostic artifact: %s\n' "$artifact" >&2
        exit 1
    }
done

arm-none-eabi-size -A "$ELF" | tee "$BUILD_DIR/pbns-raw-tunnel-diagnostic.sections"
ninja -C "$BUILD_DIR" -t commands >"$BUILD_DIR/pbns-raw-tunnel-diagnostic.commands"
arm-none-eabi-nm "$ELF" >"$BUILD_DIR/pbns-raw-tunnel-diagnostic.symbols"
arm-none-eabi-strings "$ELF" >"$BUILD_DIR/pbns-raw-tunnel-diagnostic.strings"

if ! grep -Fq -- '-DPBNS_RAW_TUNNEL_DIAGNOSTIC' \
    "$BUILD_DIR/pbns-raw-tunnel-diagnostic.commands"; then
    printf '%s\n' 'raw diagnostic instrumentation guard is absent' >&2
    exit 1
fi
if grep -Eq '[[:space:]](lwip_socket|lwip_connect|lwip_send|lwip_recv)$' \
    "$BUILD_DIR/pbns-raw-tunnel-diagnostic.symbols"; then
    printf '%s\n' 'lwIP socket API linked into raw diagnostic' >&2
    exit 1
fi
if grep -Eq '[[:space:]](flash_range_erase|flash_range_program|flash_safe_execute)$' \
    "$BUILD_DIR/pbns-raw-tunnel-diagnostic.symbols"; then
    printf '%s\n' 'flash mutation API linked into raw diagnostic' >&2
    exit 1
fi
if grep -Eq '[[:space:]](mbedtls_ssl_|mbedtls_x509_|pbns_tls_)' \
    "$BUILD_DIR/pbns-raw-tunnel-diagnostic.symbols"; then
    printf '%s\n' 'TLS or X.509 termination linked into raw diagnostic' >&2
    exit 1
fi
for forbidden in \
    'PBNS Proxy v1' 'PBNS Provision' 'PBNS Network Diagnostic v1' \
    'TLS-ECDHE' 'PBNS_INSECURE'; do
    if grep -Fq "$forbidden" "$BUILD_DIR/pbns-raw-tunnel-diagnostic.strings"; then
        printf 'forbidden raw diagnostic string: %s\n' "$forbidden" >&2
        exit 1
    fi
done
if ! grep -Fxq 'PBNS Raw Tunnel Diagnostic v1' \
    "$BUILD_DIR/pbns-raw-tunnel-diagnostic.strings"; then
    printf '%s\n' 'exact raw diagnostic product is absent' >&2
    exit 1
fi
if [[ $(grep -c 'TUD_CDC_DESCRIPTOR' \
          "$PICO_ROOT/src/raw_tunnel_diagnostic_usb_descriptors.c") != 1 ]]; then
    printf '%s\n' 'raw diagnostic must expose exactly one CDC function' >&2
    exit 1
fi

mapfile -d '' stack_files < <(find "$BUILD_DIR" -type f -name '*.su' -print0)
if [[ ${#stack_files[@]} -eq 0 ]]; then
    printf '%s\n' 'missing raw diagnostic stack reports' >&2
    exit 1
fi
stack_report=$(awk -F '\t' '
    NF >= 2 && ($2 + 0) > maximum {
        maximum = $2 + 0
        function_name = $1
    }
    END { printf "%u|%s", maximum, function_name }
' "${stack_files[@]}")
maximum_stack_frame=${stack_report%%|*}
maximum_stack_function=${stack_report#*|}
if ((maximum_stack_frame >= 4096)); then
    printf 'raw diagnostic stack frame exceeds 4 KiB: %s (%s bytes)\n' \
        "$maximum_stack_function" "$maximum_stack_frame" >&2
    exit 1
fi
stack_size=$(arm-none-eabi-objdump -h "$ELF" |
    awk '$2 == ".stack_dummy" { print $3 }')
flash_length=$(awk '$1 == "FLASH" { print $3; exit }' "$MAP")
if [[ $stack_size != 00001000 || $flash_length != 0x001fe000 ]]; then
    printf 'raw diagnostic memory boundary mismatch: stack=%s flash=%s\n' \
        "$stack_size" "$flash_length" >&2
    exit 1
fi
python3 "$SCRIPT_DIR/verify_uf2_range.py" "$UF2"
python3 "$PBNS_ROOT/integration/hil/raw-tunnel-diagnostic.py" verify-lock \
    --lock "$DIAGNOSTIC_LOCK" \
    --uf2 "$UF2" \
    --rollback "$ROLLBACK_UF2" \
    --production-raw "$PRODUCTION_UF2"
sha256sum "$UF2" "$ELF" >"$BUILD_DIR/ARTIFACTS.sha256"
chmod 600 "$BUILD_DIR/ARTIFACTS.sha256"

printf '[PASS] production raw artifact remains %s (%s bytes)\n' \
    "$EXPECTED_PRODUCTION_SHA256" "$EXPECTED_PRODUCTION_SIZE"
printf '[PASS] raw diagnostic source epoch %s\n' "$SOURCE_DATE_EPOCH"
printf '[PASS] raw diagnostic stack %s, maximum frame %s bytes (%s)\n' \
    "$stack_size" "$maximum_stack_frame" "$maximum_stack_function"
printf '[PASS] raw diagnostic linkable flash %s; UF2 excludes credentials\n' \
    "$flash_length"
printf '[PASS] one CDC, TLS opaque, no flash mutation or provisioning symbols\n'
printf '[PASS] raw diagnostic firmware %s\n' "$UF2"
printf '%s\n' 'PICO RAW TUNNEL DIAGNOSTIC BUILD PASS'
