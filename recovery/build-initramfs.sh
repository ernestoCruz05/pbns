#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    printf 'usage: %s --kernel-version VERSION --kernel-image FILE --output FILE\n' \
        "$0" >&2
    exit 2
}

kernel_version=
kernel_image=
output=
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel-version) [[ $# -ge 2 ]] || usage; kernel_version=$2; shift 2 ;;
        --kernel-image) [[ $# -ge 2 ]] || usage; kernel_image=$2; shift 2 ;;
        --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
        *) usage ;;
    esac
done
[[ -n $kernel_version && -n $kernel_image && -n $output ]] || usage
[[ -f $kernel_image && -r $kernel_image ]] || {
    printf 'kernel image is not a readable regular file\n' >&2
    exit 1
}
[[ ! -e $output && ! -e ${output}.inputs.sha256 ]] || {
    printf 'refusing to replace recovery initramfs output\n' >&2
    exit 1
}
command -v dracut >/dev/null || {
    printf 'dracut is required\n' >&2
    exit 1
}
command -v sha256sum >/dev/null

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
module_dir="$script_dir/dracut/95pbns-recovery"
output_dir=$(dirname -- "$output")
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd -P)
output="$output_dir/$(basename -- "$output")"
temporary=$(mktemp "$output_dir/.pbns-recovery-initramfs.XXXXXX")
manifest_temporary=$(mktemp "$output_dir/.pbns-recovery-initramfs-manifest.XXXXXX")
cleanup() {
    rm -f -- "$temporary" "$manifest_temporary"
}
trap cleanup EXIT

omit_modules='fstab-sys resume network network-manager ifcfg iscsi nfs cifs nbd '
omit_modules+='lvm mdraid dmraid crypt'
dracut --force --reproducible --no-hostonly --no-hostonly-cmdline \
    --kver "$kernel_version" --omit "$omit_modules" \
    --include "$module_dir/pbns-recovery-init.sh" \
        /usr/lib/dracut/hooks/cmdline/00-pbns-recovery.sh \
    --include "$module_dir/pbns-write-enable" /usr/bin/pbns-write-enable \
    --include "$module_dir/99-pbns-block-readonly.rules" \
        /etc/udev/rules.d/99-pbns-block-readonly.rules \
    --install 'bash mount mkdir chmod sleep awk lsblk readlink tr blockdev udevadm' \
    "$temporary"

{
    sha256sum "$kernel_image" | awk '{ print $1 "  kernel-image" }'
    for input in module-setup.sh pbns-recovery-init.sh pbns-write-enable \
                 99-pbns-block-readonly.rules; do
        sha256sum "$module_dir/$input" | awk -v name="$input" \
            '{ print $1 "  dracut/95pbns-recovery/" name }'
    done
    sha256sum "$temporary" | awk '{ print $1 "  initramfs" }'
} >"$manifest_temporary"
chmod 0644 "$temporary" "$manifest_temporary"
mv -n -- "$temporary" "$output"
[[ ! -e $temporary ]] || {
    printf 'recovery initramfs output appeared during build\n' >&2
    exit 1
}
mv -n -- "$manifest_temporary" "${output}.inputs.sha256"
[[ ! -e $manifest_temporary ]] || {
    printf 'recovery initramfs manifest appeared during build\n' >&2
    exit 1
}
sync -f "$output" "${output}.inputs.sha256"
trap - EXIT
printf 'PBNS RECOVERY INITRAMFS BUILD PASS output=%s\n' "$output"
