#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
    printf 'usage: %s STATE_DIR\n' "$0" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
state_root="$pbns_root/integration/state/"
state_arg=$1
if [[ ! -e $state_arg && ! -L $state_arg ]]; then
    printf 'swtpm state absent: %s\n' "$state_arg"
    exit 0
fi
if [[ ! -d $state_arg || -L $state_arg ]]; then
    printf 'swtpm state must be a non-symlink directory\n' >&2
    exit 1
fi
state_dir=$(cd -- "$state_arg" && pwd -P)
if [[ $state_dir != "$state_root"* || $(stat -c %u "$state_dir") -ne $(id -u) ||
      $(stat -c %a "$state_dir") != 700 || ! -d $state_dir/tpm || -L $state_dir/tpm ||
      $(stat -c %u "$state_dir/tpm") -ne $(id -u) || $(stat -c %a "$state_dir/tpm") != 700 ]]; then
    printf 'invalid managed TPM state directory\n' >&2
    exit 1
fi
managed="$state_dir/managed"
if [[ ! -f $managed || -L $managed || $(stat -c %u "$managed") -ne $(id -u) ||
      $(stat -c %a "$managed") != 600 || $(<"$managed") != PBNS_SWTPM_STATE_V1 ]]; then
    printf 'refusing unmanaged swtpm state\n' >&2
    exit 1
fi
if [[ -e $state_dir/paused || -L $state_dir/paused ]]; then
    if [[ ! -f $state_dir/paused || -L $state_dir/paused ||
          $(stat -c %u "$state_dir/paused") -ne $(id -u) || $(stat -c %a "$state_dir/paused") != 600 ]]; then
        printf 'invalid paused swtpm state\n' >&2
        exit 1
    fi
    for metadata in swtpm.pid process.identity owner.pid runtime.path socket.path pause.intent; do
        if [[ -e $state_dir/$metadata || -L $state_dir/$metadata ]]; then
            printf 'paused state contains active metadata\n' >&2
            exit 1
        fi
    done
else
    python3 "$script_dir/quiesce-swtpm-runtime.py" --pause "$state_dir"
fi
rm -rf -- "$state_dir"
printf '%s\n' 'SWTPM STOP PASS'
