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
if [[ ! -d $state_arg || -L $state_arg ]]; then
    printf 'swtpm state must be a non-symlink directory\n' >&2
    exit 1
fi
state_dir=$(cd -- "$state_arg" && pwd -P)
if [[ $state_dir != "$state_root"* || $(stat -c %u "$state_dir") -ne $(id -u) ||
      $(stat -c %a "$state_dir") != 700 || ! -d $state_dir/tpm || -L $state_dir/tpm ||
      $(stat -c %u "$state_dir/tpm") -ne $(id -u) || $(stat -c %a "$state_dir/tpm") != 700 ]]; then
    printf 'invalid retained TPM state directory\n' >&2
    exit 1
fi
managed="$state_dir/managed"
if [[ ! -f $managed || -L $managed || $(stat -c %u "$managed") -ne $(id -u) ||
      $(stat -c %a "$managed") != 600 || $(<"$managed") != PBNS_SWTPM_STATE_V1 ||
      -e $state_dir/paused || -L $state_dir/paused ]]; then
    printf 'invalid active PBNS swtpm state\n' >&2
    exit 1
fi

# quiesce-swtpm-runtime.py publishes a durable process.identity pause intent first.
python3 "$script_dir/quiesce-swtpm-runtime.py" --pause "$state_dir"
printf '%s\n' 'SWTPM PAUSE PASS'
