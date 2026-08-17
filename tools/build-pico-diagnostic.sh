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
BUILD_DIR="$PICO_ROOT/build-diagnostic"
LOCK_FILE="$PBNS_ROOT/dependencies.lock"
PICOTOOL_PATH="$PBNS_ROOT/.deps/picotool"

for tool in git cmake ninja arm-none-eabi-nm arm-none-eabi-objdump \
    arm-none-eabi-size arm-none-eabi-strings sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required Pico diagnostic build tool: %s\n' "$tool" >&2
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

export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)
rm -rf -- "$BUILD_DIR"
cmake -S "$PICO_ROOT" -B "$BUILD_DIR" -G Ninja \
    -DPICO_SDK_PATH="$PICO_SDK_PATH" \
    -DPICOTOOL_GIT_REPOSITORY_URL="$PICOTOOL_PATH" \
    -DPICOTOOL_GIT_BRANCH="$(lock_revision picotool)" \
    -DPBNS_BUILD_NETWORK_DIAGNOSTIC=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build "$BUILD_DIR" --target pbns-proxy-diagnostic -j2

ELF="$BUILD_DIR/pbns-proxy-diagnostic.elf"
MAP="$BUILD_DIR/pbns-proxy-diagnostic.elf.map"
UF2="$BUILD_DIR/pbns-proxy-diagnostic.uf2"
for artifact in "$ELF" "$MAP" "$UF2"; do
    if [[ ! -f $artifact ]]; then
        printf 'missing Pico diagnostic artifact: %s\n' "$artifact" >&2
        exit 1
    fi
done
for artifact in \
    "$PICO_ROOT/build/pbns-proxy.elf" \
    "$PICO_ROOT/build/pbns-proxy.uf2"; do
    if [[ ! -f $artifact ]]; then
        printf 'missing production restore artifact: %s\n' "$artifact" >&2
        exit 1
    fi
done

arm-none-eabi-size "$ELF"
ninja -C "$BUILD_DIR" -t commands >"$BUILD_DIR/pbns-proxy-diagnostic.commands"
arm-none-eabi-nm "$ELF" >"$BUILD_DIR/pbns-proxy-diagnostic.symbols"
arm-none-eabi-strings "$ELF" >"$BUILD_DIR/pbns-proxy-diagnostic.strings"

expected_config="-DMBEDTLS_CONFIG_FILE=\\\"$PICO_ROOT/include/mbedtls_config.h\\\""
if ! grep -Fq -- "$expected_config" \
    "$BUILD_DIR/pbns-proxy-diagnostic.commands"; then
    printf '%s\n' 'Pico diagnostic did not select the project Mbed TLS config' >&2
    exit 1
fi
if grep -Eq '[[:space:]](lwip_socket|lwip_connect|lwip_send|lwip_recv)$' \
    "$BUILD_DIR/pbns-proxy-diagnostic.symbols"; then
    printf '%s\n' 'plaintext lwIP socket API linked into Pico diagnostic' >&2
    exit 1
fi
if grep -Eq '[[:space:]](flash_range_erase|flash_range_program)$' \
    "$BUILD_DIR/pbns-proxy-diagnostic.symbols"; then
    printf '%s\n' 'flash mutation API linked into Pico diagnostic' >&2
    exit 1
fi
for payload_api in \
    tud_cdc_n_available tud_cdc_n_peek \
    tud_cdc_n_read tud_cdc_n_read_char tud_cdc_n_read_flush \
    tud_cdc_n_write tud_cdc_n_write_available tud_cdc_n_write_char \
    tud_cdc_n_write_clear; do
    if grep -Eq "[[:space:]]${payload_api}$" \
        "$BUILD_DIR/pbns-proxy-diagnostic.symbols"; then
        printf 'CDC payload API linked into Pico diagnostic: %s\n' \
            "$payload_api" >&2
        exit 1
    fi
done
if grep -q 'PBNS_INSECURE' "$BUILD_DIR/pbns-proxy-diagnostic.symbols" \
    "$BUILD_DIR/pbns-proxy-diagnostic.strings"; then
    printf '%s\n' 'insecure transport mode linked into Pico diagnostic' >&2
    exit 1
fi
if grep -q 'mbedtls_ssl_tls13' "$BUILD_DIR/pbns-proxy-diagnostic.symbols"; then
    printf '%s\n' 'unapproved TLS 1.3 linked into Pico diagnostic' >&2
    exit 1
fi
if grep -Fq 'PBNS Proxy v1' "$BUILD_DIR/pbns-proxy-diagnostic.strings" ||
   grep -Fq 'PBNS Provision' "$BUILD_DIR/pbns-proxy-diagnostic.strings"; then
    printf '%s\n' 'production or provisioning identity linked into diagnostic' >&2
    exit 1
fi
if ! grep -Fxq 'PBNS Network Diagnostic v1' \
    "$BUILD_DIR/pbns-proxy-diagnostic.strings"; then
    printf '%s\n' 'exact diagnostic product is absent' >&2
    exit 1
fi
if [[ $(grep -c 'TUD_CDC_DESCRIPTOR' \
          "$PICO_ROOT/src/diagnostic_usb_descriptors.c") != 1 ]]; then
    printf '%s\n' 'diagnostic descriptor does not contain exactly one CDC function' >&2
    exit 1
fi
hardware_poll_count=$(grep -Ec \
    '[[:space:]]T[[:space:]]+mbedtls_hardware_poll$' \
    "$BUILD_DIR/pbns-proxy-diagnostic.symbols" || true)
if [[ $hardware_poll_count != 1 ]]; then
    printf 'unexpected diagnostic entropy adapter count: %s\n' \
        "$hardware_poll_count" >&2
    exit 1
fi
mapfile -t tls_names < <(
    grep -E '^TLS-' "$BUILD_DIR/pbns-proxy-diagnostic.strings"
)
if [[ ${#tls_names[@]} -ne 1 ||
      ${tls_names[0]:-} != TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 ]]; then
    printf '%s\n' 'unexpected linked Pico diagnostic TLS profile' >&2
    exit 1
fi

mapfile -d '' stack_files < <(find "$BUILD_DIR" -type f -name '*.su' -print0)
if [[ ${#stack_files[@]} -eq 0 ]]; then
    printf '%s\n' 'missing Pico diagnostic stack-usage reports' >&2
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
    printf 'Pico diagnostic stack frame exceeds 4 KiB: %s (%s bytes)\n' \
        "$maximum_stack_function" "$maximum_stack_frame" >&2
    exit 1
fi
stack_size=$(arm-none-eabi-objdump -h "$ELF" |
    awk '$2 == ".stack_dummy" { print $3 }')
flash_length=$(awk '$1 == "FLASH" { print $3; exit }' "$MAP")
if [[ $stack_size != 00001000 ]]; then
    printf 'unexpected Pico diagnostic stack reservation: %s\n' \
        "$stack_size" >&2
    exit 1
fi
if [[ $flash_length != 0x001fe000 ]]; then
    printf 'diagnostic credential sectors are not excluded: %s\n' \
        "$flash_length" >&2
    exit 1
fi

sha256sum "$UF2" "$ELF" >"$BUILD_DIR/ARTIFACTS.sha256"
chmod 600 "$BUILD_DIR/ARTIFACTS.sha256"
printf '[PASS] diagnostic reproducible source epoch %s\n' "$SOURCE_DATE_EPOCH"
printf '[PASS] diagnostic stack %s, maximum frame %s bytes (%s)\n' \
    "$stack_size" "$maximum_stack_frame" "$maximum_stack_function"
printf '[PASS] diagnostic linkable flash %s and read-only credential policy\n' \
    "$flash_length"
printf '[PASS] diagnostic exact TLS 1.2 profile and entropy adapter\n'
printf '[PASS] diagnostic firmware %s\n' "$UF2"
printf '%s\n' 'PICO NETWORK DIAGNOSTIC BUILD PASS'
