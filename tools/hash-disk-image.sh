#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
    printf 'usage: %s DISPOSABLE_STATE_IMAGE\n' "$0" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/.." && pwd -P)
state_root="$pbns_root/integration/state/"
image=$1
if [[ ! -f $image || -L $image ]]; then
    printf 'disk image must be a regular non-symlink file\n' >&2
    exit 1
fi
image=$(realpath -- "$image")
if [[ $image != "$state_root"* ]]; then
    printf 'disk image must be below %s\n' "$state_root" >&2
    exit 1
fi
if [[ $(stat -c %u "$image") -ne $(id -u) || $(stat -c %a "$image") != 600 ]]; then
    printf 'disk image must be caller-owned with mode 0600\n' >&2
    exit 1
fi
for tool in flock sha256sum stat; do
    command -v "$tool" >/dev/null
done
before=$(stat -c '%d:%i:%s:%Y' "$image")
exec {image_fd}<"$image"
flock -s "$image_fd"
digest=$(sha256sum "/proc/self/fd/$image_fd" | awk '{ print $1 }')
size=$(stat -c %s "/proc/self/fd/$image_fd")
after=$(stat -c '%d:%i:%s:%Y' "$image")
[[ $before == "$after" ]] || {
    printf 'disk image changed while hashing\n' >&2
    exit 1
}
printf '%s  %s  %s\n' "$digest" "$size" "$(basename -- "$image")"
