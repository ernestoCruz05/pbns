#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/.." && pwd -P)
python3 -m unittest "$pbns_root/tools/tests/test_recovery_policy.py" -v
if [[ $# -eq 0 ]]; then
    exit 0
fi
if [[ $# -ne 1 ]]; then
    printf 'usage: %s [PBNSRecovery.efi]\n' "$0" >&2
    exit 2
fi
uki=$1
manifest="${uki}.inputs.sha256"
[[ -f $uki && -f $manifest ]] || {
    printf 'UKI or input manifest is absent\n' >&2
    exit 1
}
sbverify --list "$uki"
for label in kernel initramfs cmdline os-release stub signed-output; do
    grep -Eq "^[0-9a-f]{64}  ${label}$" "$manifest"
done
printf '%s\n' 'PBNS RECOVERY IMAGE POLICY PASS'
