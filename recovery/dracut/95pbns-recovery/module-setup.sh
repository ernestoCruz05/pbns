#!/bin/bash

check() {
    return 0
}

depends() {
    echo base udev-rules
    return 0
}

install() {
    inst_multiple /bin/sh /bin/bash /bin/mount /bin/mkdir /bin/chmod /bin/sleep /usr/bin/awk \
        /usr/bin/lsblk /usr/bin/readlink /usr/bin/tr /usr/bin/blockdev \
        /usr/bin/udevadm /usr/lib/systemd/systemd-udevd
    inst_script "$moddir/pbns-recovery-init.sh" \
        /usr/lib/dracut/hooks/cmdline/00-pbns-recovery.sh
    inst_script "$moddir/pbns-write-enable" /usr/bin/pbns-write-enable
    inst_rules "$moddir/99-pbns-block-readonly.rules"
}
