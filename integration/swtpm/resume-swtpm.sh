#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $# -eq 1 ]] || { printf 'usage: %s STATE_DIR\n' "$0" >&2; exit 2; }
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P); pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
state_root="$pbns_root/integration/state/"; state_arg=$1
if [[ ! -d $state_arg || -L $state_arg ]]; then printf 'swtpm state must be a non-symlink directory\n' >&2; exit 1; fi
state_dir=$(cd -- "$state_arg" && pwd -P)
if [[ $state_dir != "$state_root"* || $(stat -c %u "$state_dir") -ne $(id -u) || $(stat -c %a "$state_dir") != 700 || ! -d $state_dir/tpm || -L $state_dir/tpm || $(stat -c %u "$state_dir/tpm") -ne $(id -u) || $(stat -c %a "$state_dir/tpm") != 700 ]]; then printf 'invalid retained TPM state directory\n' >&2; exit 1; fi
managed="$state_dir/managed"; paused="$state_dir/paused"
if [[ ! -f $managed || -L $managed || $(stat -c %u "$managed") -ne $(id -u) || $(stat -c %a "$managed") != 600 || $(<"$managed") != PBNS_SWTPM_STATE_V1 || ! -f $paused || -L $paused || $(stat -c %u "$paused") -ne $(id -u) || $(stat -c %a "$paused") != 600 || $(<"$paused") != PBNS_SWTPM_PAUSED_V2 ]]; then printf 'invalid managed paused swtpm state\n' >&2; exit 1; fi
for metadata in swtpm.pid process.identity owner.pid runtime.path socket.path pause.intent; do [[ ! -e $state_dir/$metadata && ! -L $state_dir/$metadata ]] || { printf 'paused state contains runtime metadata\n' >&2; exit 1; }; done
swtpm_executable=$(readlink -f "$(command -v swtpm)"); [[ ${swtpm_executable##*/} == swtpm ]]; command -v tpm2_getcap >/dev/null
runtime_dir=$(mktemp -d "${TMPDIR:-/tmp}/pbns-swtpm.XXXXXX"); chmod 0700 "$runtime_dir"; socket_path="$runtime_dir/server.sock"; control_path="$socket_path.ctrl"
printf '%s\n' "$PPID" >"$state_dir/owner.pid"; printf '%s\n' "$runtime_dir" >"$state_dir/runtime.path"; printf '%s\n' "$socket_path" >"$state_dir/socket.path"; : >>"$state_dir/swtpm.log"; chmod 0600 "$state_dir/owner.pid" "$state_dir/runtime.path" "$state_dir/socket.path" "$state_dir/swtpm.log"
started=0; launched_pid=
cleanup() { status=$?; terminated=0; if [[ $status -ne 0 && $started -eq 1 ]]; then if [[ -f $state_dir/process.identity ]]; then python3 "$script_dir/quiesce-swtpm-runtime.py" --terminate "$state_dir" >/dev/null 2>&1 && terminated=1; elif [[ -n $launched_pid ]]; then python3 "$script_dir/quiesce-swtpm-runtime.py" --terminate-unrecorded "$launched_pid" "$swtpm_executable" "$state_dir" >/dev/null 2>&1 && terminated=1; fi; fi; if [[ $status -eq 0 || $started -eq 0 || $terminated -eq 1 ]]; then rm -f -- "$runtime_dir/server.sock" "$runtime_dir/server.sock.ctrl"; rmdir -- "$runtime_dir" 2>/dev/null || true; if [[ $status -ne 0 ]]; then rm -f -- "$state_dir/swtpm.pid" "$state_dir/process.identity" "$state_dir/owner.pid" "$state_dir/runtime.path" "$state_dir/socket.path"; fi; fi; exit "$status"; }
trap cleanup EXIT
"$swtpm_executable" socket --tpm2 --tpmstate "dir=$state_dir/tpm,mode=0600" --ctrl "type=unixio,path=$control_path,mode=0600" --server "type=unixio,path=$socket_path,mode=0600" --flags startup-clear --pid "file=$state_dir/swtpm.pid" --log "file=$state_dir/swtpm.log,level=2" --daemon
started=1
for _ in $(seq 1 100); do
 if [[ -s $state_dir/swtpm.pid && -S $socket_path && -S $control_path ]]; then pid=$(<"$state_dir/swtpm.pid"); launched_pid=$pid; if [[ $pid =~ ^[0-9]+$ ]] && python3 "$script_dir/quiesce-swtpm-runtime.py" --record "$pid" "$swtpm_executable" "$state_dir" && TPM2TOOLS_TCTI="swtpm:path=$socket_path" tpm2_getcap properties-fixed >"$state_dir/readiness.log" 2>&1; then chmod 0600 "$state_dir/swtpm.pid" "$state_dir/process.identity" "$state_dir/readiness.log"; rm -f -- "$paused"; printf 'SWTPM RESUME PASS socket=%s\n' "$socket_path"; trap - EXIT; exit 0; fi; fi; sleep 0.05
done
printf 'swtpm readiness timeout\n' >&2; exit 1
