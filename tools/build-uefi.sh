#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

require_safe_absolute_path() {
    local name=$1
    local path=$2
    if [[ -z $path || $path != /* || ! $path =~ ^/[A-Za-z0-9/._-]+$ ]]; then
        printf 'Unsafe absolute path %s: %q\n' "$name" "$path" >&2
        exit 2
    fi
}

owned_directory_0700() {
    local metadata
    metadata=$(stat -c '%F:%a:%u' -- "$1" 2>/dev/null) || return 1
    [[ $metadata == "directory:700:$(id -u)" ]]
}

owned_regular_mode() {
    local path=$1
    local expected_mode=$2
    local metadata
    metadata=$(stat -c '%F:%a:%u' -- "$path" 2>/dev/null) || return 1
    [[ $metadata == "regular file:${expected_mode}:$(id -u)" ]]
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)
require_safe_absolute_path PBNS_ROOT "$PBNS_ROOT"
require_safe_absolute_path REPO_ROOT "$REPO_ROOT"
EXPECTED_COMMIT=b03a21a63e3bd001f52c527e5a57feddb53a690b

if [[ -z ${PBNS_EDK2_DIR:-} ]]; then
    printf '%s\n' 'PBNS_EDK2_DIR is required' >&2
    exit 2
fi
if [[ -z ${PBNS_DEPLOYMENT_BUNDLE:-} ]]; then
    printf '%s\n' 'PBNS_DEPLOYMENT_BUNDLE is required' >&2
    exit 2
fi
if [[ $PBNS_DEPLOYMENT_BUNDLE != /* ]]; then
    PBNS_DEPLOYMENT_BUNDLE="$(pwd -P)/$PBNS_DEPLOYMENT_BUNDLE"
fi
require_safe_absolute_path PBNS_DEPLOYMENT_BUNDLE "$PBNS_DEPLOYMENT_BUNDLE"
if [[ -L $PBNS_DEPLOYMENT_BUNDLE || ! -f $PBNS_DEPLOYMENT_BUNDLE ]]; then
    printf '%s\n' 'PBNS_DEPLOYMENT_BUNDLE must be a canonical public bundle' >&2
    exit 2
fi
if [[ -z ${PBNS_ENROLLMENT_BUNDLE:-} ]]; then
    printf '%s\n' 'PBNS_ENROLLMENT_BUNDLE is required' >&2
    exit 2
fi
if [[ $PBNS_ENROLLMENT_BUNDLE != /* ]]; then
    PBNS_ENROLLMENT_BUNDLE="$(pwd -P)/$PBNS_ENROLLMENT_BUNDLE"
fi
require_safe_absolute_path PBNS_ENROLLMENT_BUNDLE "$PBNS_ENROLLMENT_BUNDLE"
if [[ -L $PBNS_ENROLLMENT_BUNDLE || ! -f $PBNS_ENROLLMENT_BUNDLE ]]; then
    printf '%s\n' 'PBNS_ENROLLMENT_BUNDLE must be a canonical public bundle' >&2
    exit 2
fi
BUILD_TARGET=${PBNS_BUILD_TARGET:-DEBUG}
if [[ $BUILD_TARGET != DEBUG && $BUILD_TARGET != RELEASE ]]; then
    printf 'Unsupported PBNS_BUILD_TARGET: %s\n' "$BUILD_TARGET" >&2
    exit 2
fi
if [[ $PBNS_EDK2_DIR != /* ]]; then
    PBNS_EDK2_DIR="$REPO_ROOT/$PBNS_EDK2_DIR"
fi
PBNS_EDK2_DIR=$(cd -- "$PBNS_EDK2_DIR" && pwd -P)
require_safe_absolute_path PBNS_EDK2_DIR "$PBNS_EDK2_DIR"
if [[ $(git -C "$PBNS_EDK2_DIR" rev-parse HEAD) != "$EXPECTED_COMMIT" ]]; then
    printf '%s\n' 'EDK II revision mismatch' >&2
    exit 1
fi
expected_skipped='-9c87f979a7f1d3a6d786b260653d566c1d31a1c4 TcgTpmPkg/Library/TpmLib/TPM/external/wolfssl'
submodule_status=$(git -C "$PBNS_EDK2_DIR" submodule status --recursive)
unexpected_status=
while IFS= read -r line; do
    if [[ -n $line && $line != " "* && $line != "$expected_skipped" ]]; then
        unexpected_status+="$line"$'\n'
    fi
done <<<"$submodule_status"
if [[ -n $unexpected_status ]]; then
    printf 'EDK II recursive submodule mismatch:\n%s' "$unexpected_status" >&2
    exit 1
fi
if [[ -n $(git -C "$PBNS_EDK2_DIR" status --porcelain) ]] ||
   [[ -n $(git -C "$PBNS_EDK2_DIR" submodule foreach --recursive --quiet 'git status --porcelain') ]]; then
    printf '%s\n' 'EDK II checkout is dirty' >&2
    exit 1
fi
if [[ ! -x "$PBNS_EDK2_DIR/BaseTools/BinWrappers/PosixLike/build" ]] ||
   [[ ! -x "$PBNS_EDK2_DIR/BaseTools/Source/C/bin/GenFw" ]]; then
    printf '%s\n' 'EDK II BaseTools are not built' >&2
    exit 1
fi
for tool in cmake patch; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing UEFI build tool: %s\n' "$tool" >&2
        exit 1
    fi
done
umask 077
if [[ ! -e $PBNS_ROOT/build && ! -L $PBNS_ROOT/build ]]; then
    mkdir -m 0700 -- "$PBNS_ROOT/build"
fi
if ! owned_directory_0700 "$PBNS_ROOT/build"; then
    printf '%s\n' 'PBNS build parent must be an owned, non-symlink, mode 0700 directory' >&2
    exit 1
fi
PBNS_DEPLOYMENT_GENERATED_ABS=$(mktemp -d "$PBNS_ROOT/build/deployment.XXXXXXXX")
PBNS_ENROLLMENT_GENERATED_ABS=$(mktemp -d "$PBNS_ROOT/build/enrollment.XXXXXXXX")
require_safe_absolute_path PBNS_DEPLOYMENT_GENERATED_ABS "$PBNS_DEPLOYMENT_GENERATED_ABS"
require_safe_absolute_path PBNS_ENROLLMENT_GENERATED_ABS "$PBNS_ENROLLMENT_GENERATED_ABS"
cleanup_trust_generated() {
    local generated_path
    for generated_path in \
        "$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.h" \
        "$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.c" \
        "$PBNS_DEPLOYMENT_GENERATED_ABS/.replacement" \
        "$PBNS_ENROLLMENT_GENERATED_ABS/PbnsEnrollmentTrust.h" \
        "$PBNS_ENROLLMENT_GENERATED_ABS/PbnsEnrollmentTrust.c" \
        "$PBNS_ENROLLMENT_GENERATED_ABS/.replacement"; do
        if [[ -e $generated_path || -L $generated_path ]]; then
            chmod u+w "$generated_path" 2>/dev/null || true
            rm -f -- "$generated_path"
        fi
    done
    rmdir -- "$PBNS_DEPLOYMENT_GENERATED_ABS" 2>/dev/null || true
    rmdir -- "$PBNS_ENROLLMENT_GENERATED_ABS" 2>/dev/null || true
}
trap cleanup_trust_generated EXIT
if ! owned_directory_0700 "$PBNS_DEPLOYMENT_GENERATED_ABS" ||
   ! owned_directory_0700 "$PBNS_ENROLLMENT_GENERATED_ABS"; then
    printf '%s\n' 'Generated trust directory is not private and owned' >&2
    exit 1
fi
DEPLOYMENT_HEADER="$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.h"
DEPLOYMENT_SOURCE="$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.c"
require_safe_absolute_path DEPLOYMENT_HEADER "$DEPLOYMENT_HEADER"
require_safe_absolute_path DEPLOYMENT_SOURCE "$DEPLOYMENT_SOURCE"
require_safe_absolute_path GATEWAY_ROOT "$PBNS_ROOT/gateway"
(
    cd "$PBNS_ROOT/gateway"
    go run ./cmd/pbns-deployment render-c \
        --bundle "$PBNS_DEPLOYMENT_BUNDLE" \
        --header "$DEPLOYMENT_HEADER" \
        --source "$DEPLOYMENT_SOURCE"
)
ENROLLMENT_HEADER="$PBNS_ENROLLMENT_GENERATED_ABS/PbnsEnrollmentTrust.h"
ENROLLMENT_SOURCE="$PBNS_ENROLLMENT_GENERATED_ABS/PbnsEnrollmentTrust.c"
require_safe_absolute_path ENROLLMENT_HEADER "$ENROLLMENT_HEADER"
require_safe_absolute_path ENROLLMENT_SOURCE "$ENROLLMENT_SOURCE"
(
    cd "$PBNS_ROOT/gateway"
    go run ./cmd/pbns-deployment render-enrollment-c \
        --bundle "$PBNS_ENROLLMENT_BUNDLE" \
        --header "$ENROLLMENT_HEADER" \
        --source "$ENROLLMENT_SOURCE"
)
DEPLOYMENT_WRAPPER="$PBNS_ROOT/uefi/Applications/PbnsAttest/PbnsDeploymentTrustBuild.c"
DEPLOYMENT_INF="$PBNS_ROOT/uefi/Applications/PbnsAttest/PbnsAttest.inf"
ENROLLMENT_DEPLOYMENT_WRAPPER="$PBNS_ROOT/uefi/Applications/PbnsEnroll/PbnsDeploymentTrustBuild.c"
ENROLLMENT_WRAPPER="$PBNS_ROOT/uefi/Applications/PbnsEnroll/PbnsEnrollmentTrustBuild.c"
ENROLLMENT_INF="$PBNS_ROOT/uefi/Applications/PbnsEnroll/PbnsEnroll.inf"
for trusted_path in "$DEPLOYMENT_WRAPPER" "$DEPLOYMENT_INF" \
    "$ENROLLMENT_DEPLOYMENT_WRAPPER" "$ENROLLMENT_WRAPPER" "$ENROLLMENT_INF"; do
    require_safe_absolute_path TRUST_INPUT "$trusted_path"
done
verify_trust_input_metadata() {
    local phase=$1
    local generated_path
    for generated_path in "$DEPLOYMENT_HEADER" "$DEPLOYMENT_SOURCE" \
        "$ENROLLMENT_HEADER" "$ENROLLMENT_SOURCE"; do
        if ! owned_regular_mode "$generated_path" 444; then
            printf 'Unsafe %s trust input: %s\n' "$phase" "$generated_path" >&2
            exit 1
        fi
    done
    for generated_path in "$DEPLOYMENT_WRAPPER" "$DEPLOYMENT_INF" \
        "$ENROLLMENT_DEPLOYMENT_WRAPPER" "$ENROLLMENT_WRAPPER" "$ENROLLMENT_INF"; do
        if ! owned_regular_mode "$generated_path" 644; then
            printf 'Unsafe %s trust input: %s\n' "$phase" "$generated_path" >&2
            exit 1
        fi
    done
}
verify_trust_input_metadata pre-build
if ! grep -Fxq '#include <PbnsDeploymentTrust.c>' "$DEPLOYMENT_WRAPPER" ||
   ! grep -Fxq '#include <PbnsDeploymentTrust.c>' "$ENROLLMENT_DEPLOYMENT_WRAPPER" ||
   ! grep -Fxq '#include <PbnsEnrollmentTrust.c>' "$ENROLLMENT_WRAPPER"; then
    printf '%s\n' 'Trust wrapper does not use its fresh include directory' >&2
    exit 1
fi
TRUST_BUILD_INPUT_SHA256=$(sha256sum \
    "$DEPLOYMENT_HEADER" "$DEPLOYMENT_SOURCE" \
    "$ENROLLMENT_HEADER" "$ENROLLMENT_SOURCE" \
    "$DEPLOYMENT_WRAPPER" "$DEPLOYMENT_INF" \
    "$ENROLLMENT_DEPLOYMENT_WRAPPER" "$ENROLLMENT_WRAPPER" "$ENROLLMENT_INF")
PBNS_UEFI_TCOSE_SOURCE="$PBNS_ROOT/build/uefi-t-cose"
PBNS_TCOSE_PATCH_1="$PBNS_ROOT/patches/t_cose/0001-free-openssl-ec-temporaries.patch"
PBNS_TCOSE_PATCH_2="$PBNS_ROOT/patches/t_cose/0002-zero-transient-encryption-material.patch"
PBNS_TCOSE_PATCHES="$PBNS_TCOSE_PATCH_1;$PBNS_TCOSE_PATCH_2"
require_safe_absolute_path PBNS_UEFI_TCOSE_SOURCE "$PBNS_UEFI_TCOSE_SOURCE"
require_safe_absolute_path PBNS_T_COSE_SOURCE "$PBNS_ROOT/vendor/t_cose"
require_safe_absolute_path PBNS_TCOSE_PATCH_1 "$PBNS_TCOSE_PATCH_1"
require_safe_absolute_path PBNS_TCOSE_PATCH_2 "$PBNS_TCOSE_PATCH_2"
require_safe_absolute_path PREPARE_T_COSE_SCRIPT "$PBNS_ROOT/cmake/PrepareTCose.cmake"
cmake \
    -DPBNS_T_COSE_SOURCE="$PBNS_ROOT/vendor/t_cose" \
    -DPBNS_T_COSE_DESTINATION="$PBNS_UEFI_TCOSE_SOURCE" \
    -DPBNS_T_COSE_PATCHES="$PBNS_TCOSE_PATCHES" \
    -P "$PBNS_ROOT/cmake/PrepareTCose.cmake"
if ! grep -Fq 't_cose_crypto_secure_zero(cek_buffer)' \
    "$PBNS_UEFI_TCOSE_SOURCE/src/t_cose_encrypt_enc.c"; then
    printf '%s\n' 'Prepared UEFI t_cose source lacks transient-key zeroization' >&2
    exit 1
fi

export WORKSPACE="$PBNS_EDK2_DIR"
export PACKAGES_PATH="$REPO_ROOT:$PBNS_EDK2_DIR"
export PBNS_DEPLOYMENT_GENERATED_ABS
export PBNS_ENROLLMENT_GENERATED_ABS
export EDK_TOOLS_PATH="$PBNS_EDK2_DIR/BaseTools"
require_safe_absolute_path WORKSPACE "$WORKSPACE"
require_safe_absolute_path PACKAGES_PATH_REPO_ROOT "$REPO_ROOT"
require_safe_absolute_path PACKAGES_PATH_PBNS_EDK2_DIR "$PBNS_EDK2_DIR"
require_safe_absolute_path EDK_TOOLS_PATH "$EDK_TOOLS_PATH"
require_safe_absolute_path EDK_SETUP "$PBNS_EDK2_DIR/edksetup.sh"
require_safe_absolute_path PBNS_DSC "$PBNS_ROOT/PbnsPkg.dsc"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$PBNS_EDK2_DIR" show -s --format=%ct "$EXPECTED_COMMIT")
# shellcheck disable=SC1091
set +u
source "$PBNS_EDK2_DIR/edksetup.sh" BaseTools
set -u

STATE_DIR="$PBNS_ROOT/uefi/Build"
LOG="$STATE_DIR/uefi-build.log"
require_safe_absolute_path STATE_DIR "$STATE_DIR"
require_safe_absolute_path LOG "$LOG"
require_safe_absolute_path EDK_OUTPUT_ROOT "$PBNS_EDK2_DIR/Build/PbnsPkg"
mkdir -p "$STATE_DIR"
build -p "$PBNS_ROOT/PbnsPkg.dsc" -a X64 -b "$BUILD_TARGET" -t GCC \
    -D "PBNS_DEPLOYMENT_GENERATED_ABS=$PBNS_DEPLOYMENT_GENERATED_ABS" \
    -D "PBNS_ENROLLMENT_GENERATED_ABS=$PBNS_ENROLLMENT_GENERATED_ABS" cleanall >/dev/null
build -p "$PBNS_ROOT/PbnsPkg.dsc" -a X64 -b "$BUILD_TARGET" -t GCC \
    -D "PBNS_DEPLOYMENT_GENERATED_ABS=$PBNS_DEPLOYMENT_GENERATED_ABS" \
    -D "PBNS_ENROLLMENT_GENERATED_ABS=$PBNS_ENROLLMENT_GENERATED_ABS" \
    -n "$(nproc)" 2>&1 | tee "$LOG"
verify_trust_input_metadata post-build
if [[ $(sha256sum \
          "$DEPLOYMENT_HEADER" "$DEPLOYMENT_SOURCE" \
          "$ENROLLMENT_HEADER" "$ENROLLMENT_SOURCE" \
          "$DEPLOYMENT_WRAPPER" "$DEPLOYMENT_INF" \
          "$ENROLLMENT_DEPLOYMENT_WRAPPER" "$ENROLLMENT_WRAPPER" \
          "$ENROLLMENT_INF") != "$TRUST_BUILD_INPUT_SHA256" ]]; then
    printf '%s\n' 'Trust build input changed during compilation' >&2
    exit 1
fi
if grep -Eiq '(^|[^[:alnum:]_])warning([^[:alnum:]_]|$)' "$LOG"; then
    printf '%s\n' 'UEFI build emitted a warning' >&2
    exit 1
fi
GENFW="$PBNS_EDK2_DIR/BaseTools/Source/C/bin/GenFw"
require_safe_absolute_path GENFW "$GENFW"
for application in PbnsProbe PbnsIdentityProbe PbnsCoseProbe PbnsTlsProbe PbnsTime PbnsTimeLive PbnsBaseline PbnsAttest PbnsEnroll PBNSLauncher PBNSRecovery PbnsBootSetup; do
    OUTPUT="$PBNS_EDK2_DIR/Build/PbnsPkg/${BUILD_TARGET}_GCC/X64/${application}.efi"
    require_safe_absolute_path OUTPUT "$OUTPUT"
    if [[ ! -f "$OUTPUT" ]]; then
        printf 'Missing %s.efi: %s\n' "$application" "$OUTPUT" >&2
        exit 1
    fi
    "$GENFW" -z -r "$OUTPUT"
    if LC_ALL=C grep -aFq "$REPO_ROOT" "$OUTPUT"; then
        printf '%s.efi retains an absolute checkout path\n' "$application" >&2
        exit 1
    fi
    printf '[PASS] %s.efi %s\n' "$application" "$OUTPUT"
done
printf '%s\n' 'UEFI BUILD PASS'
