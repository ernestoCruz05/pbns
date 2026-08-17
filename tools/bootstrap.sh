#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)
LOCK_FILE="$PBNS_ROOT/dependencies.lock"

for llvm_bin in /usr/lib/llvm/*/bin; do
    if [[ -d "$llvm_bin" ]]; then
        PATH="$llvm_bin:$PATH"
    fi
done
export PATH

required_tools=(git cmake ninja gcc clang clang-tidy go python3 openssl curl sha256sum patch)
optional_tools=(qemu-system-x86_64 swtpm tpm2_getcap arm-none-eabi-gcc)

lock_field() {
    local dependency=$1
    local field=$2
    awk -F'|' -v dependency="$dependency" -v field="$field" \
        '$1 == dependency { print $field; found = 1 } END { if (!found) exit 1 }' \
        "$LOCK_FILE"
}

check_tools() {
    local missing=0
    local tool
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '[OK] required %s\n' "$tool"
        else
            printf '[MISSING] required %s\n' "$tool"
            missing=1
        fi
    done
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '[OK] optional %s\n' "$tool"
        else
            printf '[MISSING] optional %s\n' "$tool"
        fi
    done
    if ((missing != 0)); then
        return 1
    fi
    printf 'TOOL CHECK PASS\n'
}

init_submodules() {
    if [[ ! -d "$PBNS_ROOT/vendor/QCBOR" || ! -f "$PBNS_ROOT/vendor/QCBOR/inc/qcbor/qcbor.h" ]]; then
        git -C "$PBNS_ROOT" submodule update --init -- \
            vendor/QCBOR \
            vendor/t_cose \
            vendor/COSE-C \
            vendor/cn-cbor \
            vendor/cose-examples 2>/dev/null || true
    fi
    python3 "$SCRIPT_DIR/check_dependencies.py" --root "$PBNS_ROOT" --verify-submodules
}

fetch_external() {
    local dependency=$1
    local destination
    case "$dependency" in
        edk2) destination="$PBNS_ROOT/.deps/edk2" ;;
        pico_sdk) destination="$PBNS_ROOT/.deps/pico_sdk" ;;
        picotool) destination="$PBNS_ROOT/.deps/picotool" ;;
        tpm2_tss) destination="$PBNS_ROOT/.deps/tpm2-tss" ;;
        *)
            printf 'Unsupported external dependency: %s\n' "$dependency" >&2
            return 2
            ;;
    esac

    local repository commit
    repository=$(lock_field "$dependency" 2)
    commit=$(lock_field "$dependency" 3)
    if [[ ! -d "$destination/.git" ]]; then
        mkdir -p "$(dirname -- "$destination")"
        if [[ "$dependency" == "picotool" ]]; then
            git clone --no-checkout "$repository" "$destination"
        else
            git clone --filter=blob:none --no-checkout "$repository" "$destination"
        fi
    fi
    if [[ "$dependency" == "picotool" ]]; then
        git -C "$destination" fetch origin "$commit"
    else
        git -C "$destination" fetch --depth 1 origin "$commit"
    fi
    git -C "$destination" checkout --detach "$commit"
    git -C "$destination" submodule update --init --recursive --depth 1
    local actual
    actual=$(git -C "$destination" rev-parse HEAD)
    if [[ "$actual" != "$commit" ]]; then
        printf '%s: expected %s, found %s\n' "$dependency" "$commit" "$actual" >&2
        return 1
    fi
    printf '[PASS] %s %s\n' "$dependency" "$actual"
}

license_source() {
    local dependency=$1
    case "$dependency" in
        qcbor) printf '%s\n' "$PBNS_ROOT/vendor/QCBOR/LICENSE" ;;
        t_cose) printf '%s\n' "$PBNS_ROOT/vendor/t_cose/LICENSE" ;;
        cose_c) printf '%s\n' "$PBNS_ROOT/vendor/COSE-C/LICENSE" ;;
        cn_cbor) printf '%s\n' "$PBNS_ROOT/vendor/cn-cbor/LICENSE" ;;
        cose_examples) printf '%s\n' "$PBNS_ROOT/vendor/cose-examples/LICENSE" ;;
        edk2) printf '%s\n' "$PBNS_ROOT/.deps/edk2/License.txt" ;;
        pico_sdk) printf '%s\n' "$PBNS_ROOT/.deps/pico_sdk/LICENSE.TXT" ;;
        mbedtls) printf '%s\n' "$PBNS_ROOT/.deps/pico_sdk/lib/mbedtls/LICENSE" ;;
        tinyusb) printf '%s\n' "$PBNS_ROOT/.deps/pico_sdk/lib/tinyusb/LICENSE" ;;
        picotool) printf '%s\n' "$PBNS_ROOT/.deps/picotool/LICENSE.TXT" ;;
        tpm2_tss) printf '%s\n' "$PBNS_ROOT/.deps/tpm2-tss/LICENSE" ;;
        *) return 2 ;;
    esac
}

license_raw_url() {
    local dependency=$1
    local commit
    commit=$(lock_field "$dependency" 3)
    case "$dependency" in
        edk2) printf 'https://raw.githubusercontent.com/tianocore/edk2/%s/License.txt\n' "$commit" ;;
        pico_sdk) printf 'https://raw.githubusercontent.com/raspberrypi/pico-sdk/%s/LICENSE.TXT\n' "$commit" ;;
        mbedtls) printf 'https://raw.githubusercontent.com/Mbed-TLS/mbedtls/%s/LICENSE\n' "$commit" ;;
        tinyusb) printf 'https://raw.githubusercontent.com/hathach/tinyusb/%s/LICENSE\n' "$commit" ;;
        picotool) printf 'https://raw.githubusercontent.com/raspberrypi/picotool/%s/LICENSE.TXT\n' "$commit" ;;
        tpm2_tss) printf 'https://raw.githubusercontent.com/tpm2-software/tpm2-tss/%s/LICENSE\n' "$commit" ;;
        *) return 2 ;;
    esac
}

sync_licenses() {
    mkdir -p "$PBNS_ROOT/LICENSES"
    local dependency source destination expected actual temporary
    while IFS='|' read -r dependency _repository _commit _license expected; do
        [[ -z "$dependency" || "$dependency" == \#* ]] && continue
        destination="$PBNS_ROOT/LICENSES/$dependency.txt"
        source=$(license_source "$dependency")
        if [[ -f "$source" ]]; then
            cp -- "$source" "$destination"
        elif [[ "$dependency" == "edk2" || "$dependency" == "pico_sdk" ||
                "$dependency" == "mbedtls" || "$dependency" == "tinyusb" ||
                "$dependency" == "picotool" || "$dependency" == "tpm2_tss" ]]; then
            temporary=$(mktemp)
            curl -fsSL "$(license_raw_url "$dependency")" -o "$temporary"
            mv -- "$temporary" "$destination"
        else
            printf 'Missing submodule license for %s: %s\n' "$dependency" "$source" >&2
            return 1
        fi
        actual=$(sha256sum "$destination" | awk '{print $1}')
        if [[ "$actual" != "$expected" ]]; then
            printf 'License digest mismatch for %s: expected %s, found %s\n' \
                "$dependency" "$expected" "$actual" >&2
            return 1
        fi
        printf '[PASS] retained %s license %s\n' "$dependency" "$actual"
    done < "$LOCK_FILE"
    python3 "$SCRIPT_DIR/check_dependencies.py" --root "$PBNS_ROOT" --verify-licenses
    printf 'LICENSE CHECK PASS\n'
}

usage() {
    cat <<'USAGE'
Usage: bootstrap.sh --check
       bootstrap.sh --init-submodules
       bootstrap.sh --fetch-external edk2|pico_sdk|picotool|tpm2_tss
       bootstrap.sh --sync-licenses
USAGE
}

case "${1:-}" in
    --check)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        check_tools
        ;;
    --init-submodules)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        init_submodules
        ;;
    --fetch-external)
        [[ $# -eq 2 ]] || { usage >&2; exit 2; }
        fetch_external "$2"
        ;;
    --sync-licenses)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        sync_licenses
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
