#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)
EXPECTED_COMMIT=b03a21a63e3bd001f52c527e5a57feddb53a690b
EXPECTED_IASL_SHA256=9dc25808684701d5a009a9e984385a7b5d36fbd1e398810028c5d163b7553dff

if [[ -z ${PBNS_EDK2_DIR:-} ]]; then
    printf '%s\n' 'PBNS_EDK2_DIR is required' >&2
    exit 2
fi
if [[ $PBNS_EDK2_DIR != /* && ! -d $PBNS_EDK2_DIR ]]; then
    PBNS_EDK2_DIR="$REPO_ROOT/$PBNS_EDK2_DIR"
fi
PBNS_EDK2_DIR=$(cd -- "$PBNS_EDK2_DIR" && pwd -P)
PBNS_IASL_DIR=${PBNS_IASL_DIR:-$PBNS_ROOT/.deps/tools/iasl-20190215.0.0}
if [[ $PBNS_IASL_DIR != /* && ! -d $PBNS_IASL_DIR ]]; then
    PBNS_IASL_DIR="$REPO_ROOT/$PBNS_IASL_DIR"
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' 'missing OVMF build tool: sha256sum' >&2
    exit 1
fi
if [[ ! -x $PBNS_IASL_DIR/iasl ]]; then
    printf '%s\n' 'missing pinned iasl; run integration/qemu/bootstrap-iasl.sh' >&2
    exit 1
fi
actual_iasl_sha256=$(sha256sum "$PBNS_IASL_DIR/iasl")
actual_iasl_sha256=${actual_iasl_sha256%% *}
if [[ $actual_iasl_sha256 != "$EXPECTED_IASL_SHA256" ]] ||
   ! "$PBNS_IASL_DIR/iasl" -v 2>&1 |
       grep -Fq 'ASL+ Optimizing Compiler/Disassembler version 20190215'; then
    printf '%s\n' 'pinned iasl validation failed' >&2
    exit 1
fi
export PATH="$PBNS_IASL_DIR:$PATH"
if [[ $(git -C "$PBNS_EDK2_DIR" rev-parse HEAD) != "$EXPECTED_COMMIT" ]]; then
    printf '%s\n' 'EDK II revision mismatch' >&2
    exit 1
fi
expected_skipped='-9c87f979a7f1d3a6d786b260653d566c1d31a1c4 TcgTpmPkg/Library/TpmLib/TPM/external/wolfssl'
submodule_status=$(git -C "$PBNS_EDK2_DIR" submodule status --recursive)
while IFS= read -r line; do
    if [[ -n $line && $line != " "* && $line != "$expected_skipped" ]]; then
        printf 'EDK II recursive submodule mismatch: %s\n' "$line" >&2
        exit 1
    fi
done <<<"$submodule_status"
if [[ -n $(git -C "$PBNS_EDK2_DIR" status --porcelain) ]] ||
   [[ -n $(git -C "$PBNS_EDK2_DIR" submodule foreach --recursive --quiet 'git status --porcelain') ]]; then
    printf '%s\n' 'EDK II checkout is dirty' >&2
    exit 1
fi
if [[ ! -x $PBNS_EDK2_DIR/BaseTools/BinWrappers/PosixLike/build ]]; then
    printf '%s\n' 'EDK II BaseTools are not built' >&2
    exit 1
fi
for tool in gcc nasm; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing OVMF build tool: %s\n' "$tool" >&2
        exit 1
    }
done

export WORKSPACE="$PBNS_EDK2_DIR"
export PACKAGES_PATH="$PBNS_EDK2_DIR"
export EDK_TOOLS_PATH="$PBNS_EDK2_DIR/BaseTools"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$PBNS_EDK2_DIR" show -s --format=%ct "$EXPECTED_COMMIT")
rm -f -- "$PBNS_EDK2_DIR/Conf/.AutoGenIdFile.txt"
set +u
source "$PBNS_EDK2_DIR/edksetup.sh" BaseTools
set -u

STATE_DIR="$PBNS_ROOT/integration/state/qemu"
mkdir -p "$STATE_DIR"
LOG="$STATE_DIR/ovmf-build.log"
rm -rf -- "$PBNS_EDK2_DIR/Build/OvmfX64"
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -b DEBUG -t GCC -n "$(nproc)" \
    -D TPM2_ENABLE=TRUE -D SECURE_BOOT_ENABLE=TRUE 2>&1 | tee "$LOG"
CODE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"
VARS="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_VARS.fd"
if [[ ! -f $CODE || ! -f $VARS ]]; then
    printf '%s\n' 'OVMF build did not produce split firmware images' >&2
    exit 1
fi
sha256sum "$CODE" "$VARS" >"$STATE_DIR/ovmf.sha256"
printf '[PASS] OVMF_CODE.fd %s\n' "$CODE"
printf '[PASS] OVMF_VARS.fd %s\n' "$VARS"
printf '%s\n' 'OVMF BUILD PASS'
