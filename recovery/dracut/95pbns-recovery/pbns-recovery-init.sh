#!/bin/sh
set -eu

is_mounted() {
    [ -r /proc/mounts ] || return 1
    awk -v target="$1" '$2 == target { found = 1 } END { exit !found }' /proc/mounts
}

mkdir -p /proc /sys /dev /run
is_mounted /proc || mount -t proc proc /proc
is_mounted /sys || mount -t sysfs sysfs /sys
is_mounted /dev || mount -t devtmpfs devtmpfs /dev
is_mounted /run || mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mkdir -p /run/pbns
chmod 0700 /run/pbns
: >/run/pbns/write-enable.log
chmod 0600 /run/pbns/write-enable.log

/usr/lib/systemd/systemd-udevd --daemon
udevadm trigger --type=devices --action=add
udevadm settle --timeout=10

for sys_device in /sys/class/block/*; do
    [ -e "$sys_device" ] || continue
    name=${sys_device##*/}
    device=/dev/$name
    [ -b "$device" ] || continue
    if ! blockdev --setro "$device"; then
        if ! blockdev --getsize64 "$device" >/dev/null 2>&1; then
            printf 'PBNS RECOVERY UNAVAILABLE-MEDIA SKIP path=%s\n' "$device" \
                >/dev/console
            continue
        fi
        printf 'PBNS RECOVERY READ-ONLY FAIL path=%s\n' "$device" >/dev/console
        while :; do
            sleep 3600
        done
    fi
done

exec </dev/console >/dev/console 2>&1
while :; do
    printf '%s\n' 'PBNS RECOVERY READ-ONLY MODE'
    printf '%s\n' 'Persistent filesystems are not mounted.'
    printf '%s\n' 'Networking is disabled.'
    printf '%s\n' 'Commands: list, enable'
    printf '> '
    if ! IFS= read -r action; then
        sleep 1
        continue
    fi
    case "$action" in
        list)
            lsblk -dn -o NAME,MODEL,SIZE,RO,TYPE
            ;;
        enable)
            printf 'Canonical device path: '
            if IFS= read -r requested_device; then
                /usr/bin/pbns-write-enable "$requested_device" || true
            fi
            ;;
        *)
            printf '%s\n' 'Unknown command; no state changed.'
            ;;
    esac
done
