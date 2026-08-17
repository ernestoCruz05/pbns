#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)
PICO_ROOT="$PBNS_ROOT/pico"
BUILD_DIR="$PICO_ROOT/build"
LOCK_FILE="$PBNS_ROOT/dependencies.lock"

for tool in git cmake ninja arm-none-eabi-gcc arm-none-eabi-nm arm-none-eabi-objdump arm-none-eabi-size arm-none-eabi-strings; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required Pico build tool: %s\n' "$tool" >&2
        exit 1
    }
done

lock_revision() {
    local dependency=$1
    awk -F'|' -v dependency="$dependency" \
        '$1 == dependency { print $3; found = 1 } END { if (!found) exit 1 }' \
        "$LOCK_FILE"
}

verify_checkout() {
    local dependency=$1
    local checkout=$2
    local expected actual
    expected=$(lock_revision "$dependency")
    if [[ ! -d "$checkout/.git" && ! -f "$checkout/.git" ]]; then
        printf 'missing %s checkout: %s\n' "$dependency" "$checkout" >&2
        return 1
    fi
    actual=$(git -C "$checkout" rev-parse HEAD)
    if [[ "$actual" != "$expected" ]]; then
        printf '%s revision mismatch: expected %s, found %s\n' \
            "$dependency" "$expected" "$actual" >&2
        return 1
    fi
    if [[ -n $(git -C "$checkout" status --porcelain) ]]; then
        printf '%s checkout is dirty: %s\n' "$dependency" "$checkout" >&2
        return 1
    fi
    printf '[PASS] %s %s\n' "$dependency" "$actual"
}

if [[ -z ${PICO_SDK_PATH:-} ]]; then
    printf 'PICO_SDK_PATH is required\n' >&2
    exit 2
fi
PICO_SDK_PATH=$(cd -- "$PICO_SDK_PATH" && pwd -P)
PICOTOOL_PATH="$PBNS_ROOT/.deps/picotool"
verify_checkout pico_sdk "$PICO_SDK_PATH"
verify_checkout mbedtls "$PICO_SDK_PATH/lib/mbedtls"
verify_checkout tinyusb "$PICO_SDK_PATH/lib/tinyusb"
verify_checkout picotool "$PICOTOOL_PATH"
if [[ $(git -C "$PICOTOOL_PATH" rev-parse --is-shallow-repository) != false ||
      $(git -C "$PICOTOOL_PATH" config --get remote.origin.promisor || true) == true ]]; then
    printf 'picotool must be a complete checkout for the offline Pico build\n' >&2
    exit 1
fi
if git -C "$PICO_SDK_PATH" submodule status --recursive | grep -Eq '^[-+U]'; then
    printf 'Pico SDK submodule checkout mismatch\n' >&2
    exit 1
fi
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)

rm -rf -- "$BUILD_DIR"
cmake -S "$PICO_ROOT" -B "$BUILD_DIR" -G Ninja \
    -DPICO_SDK_PATH="$PICO_SDK_PATH" \
    -DPICOTOOL_GIT_REPOSITORY_URL="$PICOTOOL_PATH" \
    -DPICOTOOL_GIT_BRANCH="$(lock_revision picotool)" \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" -j2

test -f "$BUILD_DIR/pbns-proxy.elf"
test -f "$BUILD_DIR/pbns-proxy.elf.map"
test -f "$BUILD_DIR/pbns-proxy.uf2"
section_report=$(arm-none-eabi-size -A "$BUILD_DIR/pbns-proxy.elf")
printf '%s\n' "$section_report"
section_size() {
    local section=$1
    local matches
    mapfile -t matches < <(awk -v section="$section" '
        $1 == section && $2 ~ /^[0-9]+$/ { print $2 }
    ' <<<"$section_report")
    if [[ ${#matches[@]} -ne 1 ]]; then
        printf 'could not determine unique Pico section size for %s\n' "$section" >&2
        exit 1
    fi
    printf '%s\n' "${matches[0]}"
}

text_size=$(section_size .text)
data_size=$(section_size .data)
raw_bss_size=$(section_size .bss)
ram_vector_table_size=$(section_size .ram_vector_table)
uninitialized_data_size=$(section_size .uninitialized_data)
heap_size=$(section_size .heap)
bss_size=$((raw_bss_size + ram_vector_table_size + uninitialized_data_size))
main_sram_bytes=262144
minimum_heap_bytes=2048
expected_data_bytes=6208
expected_bss_bytes=165036
expected_free_sram_bytes=88852

if [[ "$data_size" != "$expected_data_bytes" ]]; then
    printf 'unexpected Pico data: expected %s bytes, found %s\n' \
        "$expected_data_bytes" "$data_size" >&2
    exit 1
fi
if [[ "$bss_size" != "$expected_bss_bytes" ]]; then
    printf 'unexpected Pico BSS: expected %s bytes, found %s\n' \
        "$expected_bss_bytes" "$bss_size" >&2
    exit 1
fi
if [[ "$heap_size" != "$minimum_heap_bytes" ]]; then
    printf 'unexpected Pico minimum heap: expected %s bytes, found %s\n' \
        "$minimum_heap_bytes" "$heap_size" >&2
    exit 1
fi
free_sram_bytes=$((main_sram_bytes - data_size - bss_size - heap_size))
if [[ "$free_sram_bytes" != "$expected_free_sram_bytes" ]]; then
    printf 'unexpected Pico free SRAM: expected %s bytes, found %s\n' \
        "$expected_free_sram_bytes" "$free_sram_bytes" >&2
    exit 1
fi
ninja -C "$BUILD_DIR" -t commands >"$BUILD_DIR/pbns-proxy.commands"
arm-none-eabi-nm "$BUILD_DIR/pbns-proxy.elf" >"$BUILD_DIR/pbns-proxy.symbols"
arm-none-eabi-strings "$BUILD_DIR/pbns-proxy.elf" >"$BUILD_DIR/pbns-proxy.strings"
expected_config="-DMBEDTLS_CONFIG_FILE=\\\"$PICO_ROOT/include/mbedtls_config.h\\\""
if ! grep -Fq -- "$expected_config" "$BUILD_DIR/pbns-proxy.commands"; then
    printf 'Pico firmware did not select the project Mbed TLS config\n' >&2
    exit 1
fi
if grep -Eq '[[:space:]](lwip_socket|lwip_connect|lwip_send|lwip_recv)$' \
    "$BUILD_DIR/pbns-proxy.symbols"; then
    printf 'plaintext lwIP socket API linked into Pico firmware\n' >&2
    exit 1
fi
if grep -q 'PBNS_INSECURE' "$BUILD_DIR/pbns-proxy.symbols" \
    "$BUILD_DIR/pbns-proxy.strings"; then
    printf 'insecure transport mode linked into Pico firmware\n' >&2
    exit 1
fi
if grep -Eq '[[:space:]](mbedtls_ssl_|mbedtls_x509_|pbns_tls_)' \
    "$BUILD_DIR/pbns-proxy.symbols"; then
    printf 'TLS, X.509, or Pico trust symbol linked into raw production firmware\n' >&2
    exit 1
fi
if grep -Eq '[[:space:]]T[[:space:]]+mbedtls_hardware_poll$' \
    "$BUILD_DIR/pbns-proxy.symbols"; then
    printf 'Pico TLS entropy adapter linked into raw production firmware\n' >&2
    exit 1
fi
if grep -Eq '^TLS-' "$BUILD_DIR/pbns-proxy.strings"; then
    printf 'TLS profile string linked into raw production firmware\n' >&2
    exit 1
fi
mapfile -d '' stack_files < <(find "$BUILD_DIR" -type f -name '*.su' -print0)
if [[ ${#stack_files[@]} -eq 0 ]]; then
    printf 'missing Pico stack-usage reports\n' >&2
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
    printf 'Pico stack frame exceeds the 4 KiB reservation: %s (%s bytes)\n' \
        "$maximum_stack_function" "$maximum_stack_frame" >&2
    exit 1
fi
stack_size=$(arm-none-eabi-objdump -h "$BUILD_DIR/pbns-proxy.elf" |
    awk '$2 == ".stack_dummy" { print $3 }')
flash_length=$(awk '$1 == "FLASH" { print $3; exit }' \
    "$BUILD_DIR/pbns-proxy.elf.map")
if [[ "$stack_size" != "00001000" ]]; then
    printf 'unexpected Pico stack reservation: %s\n' "$stack_size" >&2
    exit 1
fi
if [[ "$flash_length" != "0x001fe000" ]]; then
    printf 'credential sectors are not excluded from the linker: %s\n' \
        "$flash_length" >&2
    exit 1
fi
printf '[PASS] Pico SDK dependency graph is exact\n'
printf '[PASS] reproducible source epoch %s\n' "$SOURCE_DATE_EPOCH"
printf '[PASS] SRAM: text %s bytes, data %s bytes, BSS %s bytes, heap %s bytes; free %s bytes (= %s - %s - %s - %s)\n' \
    "$text_size" "$data_size" "$bss_size" "$heap_size" "$free_sram_bytes" \
    "$main_sram_bytes" "$data_size" "$bss_size" "$heap_size"
printf '[PASS] stack %s, maximum frame %s bytes (%s)\n' \
    "$stack_size" "$maximum_stack_frame" "$maximum_stack_function"
printf '[PASS] linkable flash %s, no lwIP socket API\n' "$flash_length"
printf '[PASS] production raw target has no TLS, X.509, or Pico trust symbols\n'
printf '[PASS] firmware %s\n' "$BUILD_DIR/pbns-proxy.uf2"
printf 'PICO BUILD PASS\n'
