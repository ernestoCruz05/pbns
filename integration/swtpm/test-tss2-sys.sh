#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
    printf 'usage: %s STATE_DIR\n' "$0" >&2
    exit 2
fi
state_dir=$(cd -- "$1" && pwd -P)
socket_file="$state_dir/socket.path"
pid_file="$state_dir/swtpm.pid"
if [[ ! -s $socket_file || ! -s $pid_file ]]; then
    printf 'swtpm is not ready\n' >&2
    exit 1
fi
socket_path=$(<"$socket_file")
if [[ ! -S $socket_path ]]; then
    printf 'swtpm is not ready\n' >&2
    exit 1
fi
export TPM2TOOLS_TCTI="swtpm:path=$socket_path"
work_dir="$state_dir/oracle"
if [[ -e $work_dir ]]; then
    printf 'oracle workspace already exists\n' >&2
    exit 1
fi
mkdir -m 0700 "$work_dir"
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT
cd -- "$work_dir"

for tool in tpm2_getcap tpm2_createprimary tpm2_create tpm2_load \
            tpm2_readpublic tpm2_sign tpm2_verifysignature tpm2_createek \
            tpm2_createak tpm2_getrandom tpm2_nvdefine tpm2_nvwrite \
            tpm2_nvread tpm2_nvundefine tpm2_flushcontext \
            tpm2_startauthsession tpm2_policynvwritten tpm2_policynv \
            tpm2_policycphash tpm2_loadexternal tpm2_policyauthorize; do
    command -v "$tool" >/dev/null
done

tpm2_getcap properties-fixed >properties.txt
tpm2_getcap algorithms >algorithms.txt
tpm2_createprimary -C o -G ecc -g sha256 -c primary.ctx >/dev/null
tpm2_create -C 0x80000000 -G ecc -g sha256 -u child.pub -r child.priv \
    >/dev/null
tpm2_load -C 0x80000000 -u child.pub -r child.priv -c child.ctx >/dev/null
tpm2_readpublic -c 0x80000001 -f pem -o child.pem >/dev/null
printf '%s' 'PBNS pinned TSS2 SYS oracle' >message.bin
tpm2_sign -c 0x80000001 -g sha256 -o signature.bin message.bin
tpm2_verifysignature -c 0x80000001 -g sha256 -m message.bin \
    -s signature.bin >/dev/null
tpm2_flushcontext 0x80000001
tpm2_flushcontext 0x80000000

tpm2_createek -G ecc -c ek.ctx -u ek.pub >/dev/null
tpm2_createak -C 0x80000000 -G ecc -g sha256 -s ecdsa -c ak.ctx -u ak.pub \
    -n ak.name >/dev/null
tpm2_flushcontext 0x80000001
tpm2_flushcontext 0x80000000

tpm2_getrandom 32 -o random.bin
[[ $(stat -c %s random.bin) -eq 32 ]]

nv_index=0x01501000
printf '\x00\x00\x00\x00\x00\x00\x00\x01' >nv.in
tpm2_nvdefine "$nv_index" -C o -s 8 -a 'ownerread|ownerwrite' >/dev/null
tpm2_nvwrite "$nv_index" -C o -i nv.in >/dev/null
tpm2_nvread "$nv_index" -C o -s 8 -o nv.out >/dev/null
cmp nv.in nv.out
tpm2_nvundefine "$nv_index" -C o >/dev/null

printf '%s\n' 'SWTPM TSS2 SYS PASS'
