#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
    printf 'usage: %s DISPOSABLE_STATE_DIR\n' "$0" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
state_root="$pbns_root/integration/state/"
state_dir=$1
if [[ ! -d $state_dir || -L $state_dir ]]; then
    printf 'state must be an existing non-symlink directory\n' >&2
    exit 1
fi
state_dir=$(cd -- "$state_dir" && pwd -P)
if [[ $state_dir != "$state_root"* || $(stat -c %a "$state_dir") != 700 ||
      $(stat -c %u "$state_dir") != $EUID ]]; then
    printf 'state must be an owned mode-0700 directory below integration/state\n' >&2
    exit 1
fi

work=
diagnostic="$state_dir/secureboot-enrollment-failed.log"
published_vars=
published_decoded=
record_diagnostic() {
    if [[ -z $diagnostic || -e $diagnostic || -L $diagnostic ]]; then
        return
    fi
    if (set -C; : >"$diagnostic") 2>/dev/null && [[ -f $diagnostic && ! -L $diagnostic ]]; then
        chmod 0600 -- "$diagnostic" 2>/dev/null || true
        printf '%s\n' 'PBNS_SECUREBOOT_ENROLLMENT_FAILED' >"$diagnostic" 2>/dev/null || true
    fi
}
cleanup() {
    status=$?
    trap - EXIT INT TERM
    if (( status != 0 )); then
        record_diagnostic
        [[ -z $published_vars ]] || rm -f -- "$published_vars"
        [[ -z $published_decoded ]] || rm -f -- "$published_decoded"
    fi
    [[ -z $work ]] || rm -rf -- "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() {
    printf '%s\n' 'PBNS secure boot enrollment failed; inspect private state diagnostic' >&2
    exit 1
}

command -v virt-fw-vars >/dev/null || fail
command -v openssl >/dev/null || fail
command -v python3 >/dev/null || fail

vars_template=${PBNS_OVMF_SECUREBOOT_VARS:-/usr/share/edk2/OvmfX64/OVMF_VARS.fd}
uki_test_cert="$pbns_root/tests/fixtures/keys/uki-secureboot-test-cert.pem"
vars_copy="$state_dir/OVMF_VARS.secboot.fd"
decoded="$state_dir/OVMF_VARS.secboot.txt"
for input in "$vars_template" "$uki_test_cert"; do
    [[ -f $input && ! -L $input && -r $input ]] || fail
done
if [[ -e $vars_copy || -L $vars_copy || -e $decoded || -L $decoded ||
      -e $diagnostic || -L $diagnostic ]]; then
    fail
fi

work=$(mktemp -d "$state_dir/.secureboot-enrollment.XXXXXX") || fail
chmod 0700 "$work" || fail
work_vars="$work/OVMF_VARS.secboot.fd"
work_decoded="$work/OVMF_VARS.secboot.txt"
virt-fw-vars --input "$vars_template" --output "$work_vars" \
    --enroll-cert "$uki_test_cert" --microsoft-kek none --no-microsoft \
    --add-db a0baa8a3-041d-48a8-bc87-c36d121b5e3d "$uki_test_cert" \
    --secure-boot || fail
chmod 0600 "$work_vars" || fail
python3 "$script_dir/verify-secureboot-store.py" \
    --vars "$work_vars" --fixture-cert "$uki_test_cert" \
    --decoded "$work_decoded" --scratch-parent "$work" || fail
chmod 0600 "$work_decoded" || fail
ln "$work_vars" "$vars_copy" || fail
published_vars=$vars_copy
ln "$work_decoded" "$decoded" || fail
published_decoded=$decoded
printf '%s\n' 'PBNS SECUREBOOT VARIABLE ENROLLMENT PASS'
