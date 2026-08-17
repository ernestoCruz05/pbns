#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
EDK2_DIR="$PBNS_ROOT/.deps/edk2"
EXPECTED_COMMIT=b03a21a63e3bd001f52c527e5a57feddb53a690b

if [[ $# -ne 1 || $1 != --check-or-fetch ]]; then
    printf 'usage: %s --check-or-fetch\n' "$0" >&2
    exit 2
fi
if [[ ! -d "$EDK2_DIR/.git" ]]; then
    "$SCRIPT_DIR/bootstrap.sh" --fetch-external edk2
fi
actual=$(git -C "$EDK2_DIR" rev-parse HEAD)
if [[ $actual != "$EXPECTED_COMMIT" ]]; then
    printf 'edk2: expected %s, found %s\n' "$EXPECTED_COMMIT" "$actual" >&2
    exit 1
fi
git -C "$EDK2_DIR" submodule update --init --recursive
expected_skipped='-9c87f979a7f1d3a6d786b260653d566c1d31a1c4 TcgTpmPkg/Library/TpmLib/TPM/external/wolfssl'
submodule_status=$(git -C "$EDK2_DIR" submodule status --recursive)
unexpected_status=
while IFS= read -r line; do
    if [[ -n $line && $line != " "* && $line != "$expected_skipped" ]]; then
        unexpected_status+="$line"$'\n'
    fi
done <<<"$submodule_status"
if [[ -n $unexpected_status ]]; then
    printf 'edk2: recursive submodule mismatch:\n%s' "$unexpected_status" >&2
    exit 1
fi
if [[ -n $(git -C "$EDK2_DIR" status --porcelain) ]]; then
    printf '%s\n' 'edk2: checkout is dirty' >&2
    exit 1
fi
if [[ -n $(git -C "$EDK2_DIR" submodule foreach --recursive --quiet 'git status --porcelain') ]]; then
    printf '%s\n' 'edk2: recursive submodule is dirty' >&2
    exit 1
fi
make -C "$EDK2_DIR/BaseTools" -j"$(nproc)"
test -x "$EDK2_DIR/BaseTools/Source/C/bin/GenFfs"
test -x "$EDK2_DIR/BaseTools/BinWrappers/PosixLike/build"
printf '[PASS] edk2 %s and BaseTools\n' "$actual"
