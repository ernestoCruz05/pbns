#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $# -eq 1 ]] || { printf 'usage: %s STATE_DIR\n' "$0" >&2; exit 2; }
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
state_root="$pbns_root/integration/state/"
state_arg=$1
if [[ $state_arg != /* || -L $state_arg || (-e $state_arg && ! -d $state_arg) ]]; then
    printf 'state path must be an absolute non-symlink directory\n' >&2; exit 1
fi
state_parent=$(cd -- "$(dirname -- "$state_arg")" && pwd -P)
state_dir="$state_parent/$(basename -- "$state_arg")"
if [[ $state_dir != "$state_root"* ]] || { [[ -d $state_dir ]] && { [[ $(stat -c %u "$state_dir") -ne $(id -u) ]] || find "$state_dir" -mindepth 1 -print -quit | grep -q .; }; }; then
    printf 'refusing nonempty state, unowned, or out-of-tree state\n' >&2; exit 1
fi
mkdir -p -- "$state_dir/tpm"
chmod 0700 "$state_dir" "$state_dir/tpm"
printf 'PBNS_SWTPM_STATE_V1\n' >"$state_dir/managed"; chmod 0600 "$state_dir/managed"
swtpm_executable=$(readlink -f "$(command -v swtpm)"); [[ ${swtpm_executable##*/} == swtpm ]]
runtime_dir=$(mktemp -d "${TMPDIR:-/tmp}/pbns-swtpm.XXXXXX"); chmod 0700 "$runtime_dir"
socket_path="$runtime_dir/server.sock"; control_path="$socket_path.ctrl"
printf '%s\n' "$$" >"$state_dir/owner.pid"
printf '%s\n' "$runtime_dir" >"$state_dir/runtime.path"
printf '%s\n' "$socket_path" >"$state_dir/socket.path"
: >"$state_dir/swtpm.log"
chmod 0600 "$state_dir/owner.pid" "$state_dir/runtime.path" "$state_dir/socket.path" "$state_dir/swtpm.log"
started=0
launched_pid=
cleanup() {
    status=$?
    terminated=0
    if [[ $status -ne 0 && $started -eq 1 ]]; then
        if [[ -f $state_dir/process.identity ]]; then
            python3 "$script_dir/quiesce-swtpm-runtime.py" --terminate "$state_dir" >/dev/null 2>&1 && terminated=1
        elif [[ -n $launched_pid ]]; then
            python3 "$script_dir/quiesce-swtpm-runtime.py" --terminate-unrecorded "$launched_pid" "$swtpm_executable" "$state_dir" >/dev/null 2>&1 && terminated=1
        fi
    fi
    if [[ $status -eq 0 || $started -eq 0 || $terminated -eq 1 ]]; then
        rm -f -- "$runtime_dir/server.sock" "$runtime_dir/server.sock.ctrl"
        rmdir -- "$runtime_dir" 2>/dev/null || true
        [[ $status -eq 0 ]] || rm -rf -- "$state_dir"
    fi
    exit "$status"
}
trap cleanup EXIT
command -v tpm2_getcap >/dev/null
"$swtpm_executable" socket --tpm2 --tpmstate "dir=$state_dir/tpm,mode=0600" \
    --ctrl "type=unixio,path=$control_path,mode=0600" --server "type=unixio,path=$socket_path,mode=0600" \
    --flags startup-clear --pid "file=$state_dir/swtpm.pid" --log "file=$state_dir/swtpm.log,level=2" --daemon
started=1
for _ in $(seq 1 100); do
    if [[ -s $state_dir/swtpm.pid && -S $socket_path && -S $control_path ]]; then
        pid=$(<"$state_dir/swtpm.pid")
        launched_pid=$pid
        if [[ $pid =~ ^[0-9]+$ ]] && python3 "$script_dir/quiesce-swtpm-runtime.py" --record "$pid" "$swtpm_executable" "$state_dir"; then
            if TPM2TOOLS_TCTI="swtpm:path=$socket_path" tpm2_getcap properties-fixed >"$state_dir/readiness.log" 2>&1; then
                chmod 0600 "$state_dir/swtpm.pid" "$state_dir/readiness.log" "$state_dir/process.identity"
                printf 'SWTPM READY socket=%s\n' "$socket_path"; trap - EXIT; exit 0
            fi
        fi
    fi
    sleep 0.05
done
printf 'swtpm readiness timeout\n' >&2; exit 1
