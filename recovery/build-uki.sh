#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    printf 'usage: %s --kernel FILE --initrd FILE --output FILE [--cmdline FILE] [--os-release FILE] [--stub FILE]\n' \
        "$0" >&2
    exit 2
}

kernel=
initramfs=
output=
cmdline=
os_release=
stub=
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel) [[ $# -ge 2 ]] || usage; kernel=$2; shift 2 ;;
        --initrd) [[ $# -ge 2 ]] || usage; initramfs=$2; shift 2 ;;
        --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
        --cmdline) [[ $# -ge 2 ]] || usage; cmdline=$2; shift 2 ;;
        --os-release) [[ $# -ge 2 ]] || usage; os_release=$2; shift 2 ;;
        --stub) [[ $# -ge 2 ]] || usage; stub=$2; shift 2 ;;
        *) usage ;;
    esac
done
[[ -n $kernel && -n $initramfs && -n $output ]] || usage

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/.." && pwd -P)
cmdline=${cmdline:-$script_dir/uki.conf}
os_release=${os_release:-/etc/os-release}
stub=${stub:-/usr/lib/systemd/boot/efi/linuxx64.efi.stub}
for input in "$kernel" "$initramfs" "$cmdline" "$os_release" "$stub"; do
    [[ -f $input && -r $input ]] || {
        printf 'UKI input is not a readable regular file: %s\n' "$input" >&2
        exit 1
    }
done
[[ ! -e $output && ! -e ${output}.inputs.sha256 ]] || {
    printf 'refusing to replace recovery UKI output\n' >&2
    exit 1
}
if [[ ${PBNS_BUILD_PROFILE:-development} == release ]]; then
    printf 'release builds reject the TEST ONLY recovery image key\n' >&2
    exit 1
fi

for tool in openssl sha256sum sbverify; do
    command -v "$tool" >/dev/null
done
ukify_tool=$(command -v ukify || command -v systemd-ukify || true)
[[ -n $ukify_tool ]] || {
    printf 'systemd ukify is required\n' >&2
    exit 1
}
readonly expected_test_fingerprint='2C:A0:2D:42:49:A2:E4:3D:EE:A5:9E:BA:8D:6D:D7:EC:0E:5F:25:CB:22:C3:FD:42:83:8F:74:63:65:EC:88:25'
fixture_key="$pbns_root/tests/fixtures/keys/uki-secureboot-test-key.pem"
fixture_certificate="$pbns_root/tests/fixtures/keys/uki-secureboot-test-cert.pem"
actual_fingerprint=$(openssl x509 -in "$fixture_certificate" -noout \
    -fingerprint -sha256 | awk -F= '{ print $2 }')
[[ $actual_fingerprint == "$expected_test_fingerprint" ]] || {
    printf 'unexpected TEST ONLY recovery certificate fingerprint\n' >&2
    exit 1
}

output_dir=$(dirname -- "$output")
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd -P)
output="$output_dir/$(basename -- "$output")"
private_dir=$(mktemp -d "$output_dir/.pbns-recovery-signing.XXXXXX")
chmod 0700 "$private_dir"
private_key="$private_dir/image-key.pem"
install -m 0600 "$fixture_key" "$private_key"
temporary="$private_dir/PBNSRecovery.efi"
manifest_temporary="$private_dir/PBNSRecovery.inputs.sha256"
cleanup() {
    rm -rf -- "$private_dir"
    rm -f -- "$temporary" "$manifest_temporary"
}
trap cleanup EXIT

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
"$ukify_tool" build \
    --linux="$kernel" \
    --initrd="$initramfs" \
    --cmdline="@$cmdline" \
    --os-release="@$os_release" \
    --stub="$stub" \
    --secureboot-private-key="$private_key" \
    --secureboot-certificate="$fixture_certificate" \
    --output="$temporary"
[[ -f $temporary ]] || {
    printf 'ukify did not produce an output\n' >&2
    exit 1
}
sbverify --list "$temporary" >"$private_dir/sbverify.txt"
grep -Fq 'signature certificates' "$private_dir/sbverify.txt"

hash_label() {
    sha256sum "$1" | awk -v label="$2" '{ print $1 "  " label }'
}
{
    hash_label "$kernel" kernel
    hash_label "$initramfs" initramfs
    hash_label "$cmdline" cmdline
    hash_label "$os_release" os-release
    hash_label "$stub" stub
    hash_label "$fixture_certificate" test-signing-certificate
    hash_label "$temporary" signed-output
} >"$manifest_temporary"
chmod 0644 "$temporary" "$manifest_temporary"
mv -n -- "$temporary" "$output"
[[ ! -e $temporary ]] || {
    printf 'recovery UKI output appeared during build\n' >&2
    exit 1
}
mv -n -- "$manifest_temporary" "${output}.inputs.sha256"
[[ ! -e $manifest_temporary ]] || {
    printf 'recovery UKI manifest appeared during build\n' >&2
    exit 1
}
sync -f "$output" "${output}.inputs.sha256"
rm -rf -- "$private_dir"
trap - EXIT
printf 'PBNS RECOVERY UKI BUILD PASS output=%s\n' "$output"
