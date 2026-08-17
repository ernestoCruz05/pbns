#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
VERSION=20190215.0.0
EXPECTED_SHA256=0f207af637358f32c93f09f3df12056452964e6a5242de484508e91d352946cb
EXPECTED_BINARY_SHA256=9dc25808684701d5a009a9e984385a7b5d36fbd1e398810028c5d163b7553dff
URL="https://api.nuget.org/v3-flatcontainer/iasl/$VERSION/iasl.$VERSION.nupkg"
DESTINATION=${PBNS_IASL_DIR:-$PBNS_ROOT/.deps/tools/iasl-$VERSION}
BINARY="$DESTINATION/iasl"
EXPECTED_VERSION='ASL+ Optimizing Compiler/Disassembler version 20190215'

verify_binary() {
    if [[ ! -x $BINARY ]] || ! command -v sha256sum >/dev/null 2>&1; then
        return 1
    fi
    local actual
    actual=$(sha256sum "$BINARY")
    actual=${actual%% *}
    [[ $actual == "$EXPECTED_BINARY_SHA256" ]] &&
        "$BINARY" -v 2>&1 | grep -Fq "$EXPECTED_VERSION"
}

if ! verify_binary; then
    for tool in curl sha256sum unzip; do
        command -v "$tool" >/dev/null 2>&1 || {
            printf 'missing iasl bootstrap tool: %s\n' "$tool" >&2
            exit 1
        }
    done
    temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/pbns-iasl-XXXXXX")
    trap 'rm -rf -- "$temp_dir"' EXIT INT TERM
    package="$temp_dir/iasl.nupkg"
    curl -fL --proto '=https' --tlsv1.2 -o "$package" "$URL"
    printf '%s  %s\n' "$EXPECTED_SHA256" "$package" | sha256sum -c -
    mkdir -p "$DESTINATION"
    unzip -p "$package" iasl/Linux-x86/iasl >"$BINARY.tmp"
    chmod 0755 "$BINARY.tmp"
    mv -f -- "$BINARY.tmp" "$BINARY"
fi
if ! verify_binary; then
    printf '%s\n' 'bootstrapped iasl version mismatch' >&2
    exit 1
fi
printf '[PASS] %s\n' "$EXPECTED_VERSION"
printf '[PASS] pinned package SHA-256 %s\n' "$EXPECTED_SHA256"
printf '[PASS] pinned iasl SHA-256 %s\n' "$EXPECTED_BINARY_SHA256"
printf 'PBNS_IASL_DIR=%s\n' "$DESTINATION"
printf '%s\n' 'IASL BOOTSTRAP PASS'
