#!/usr/bin/env bash
set -euo pipefail
umask 077

selected_case=
if [[ $# -eq 2 && $1 == --case && $2 == signed-trusted ]]; then
    selected_case=$2
elif [[ $# -ne 0 ]]; then
    printf 'usage: %s [--case signed-trusted]\n' "$0" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
state_root="$pbns_root/integration/state/"
state_dir=${PBNS_RECOVERY_QEMU_STATE:-}
if [[ ! -d $state_dir || -L $state_dir ]]; then
    printf 'PBNS_RECOVERY_QEMU_STATE must be a private disposable state directory\n' >&2
    exit 2
fi
state_dir=$(cd -- "$state_dir" && pwd -P)
if [[ $state_dir != "$state_root"* || $(stat -c %a "$state_dir") != 700 ||
      $(stat -c %u "$state_dir") != $EUID ]]; then
    printf 'QEMU recovery state must be an owned mode-0700 directory below integration/state\n' >&2
    exit 1
fi

preflight_dir=
case_tmp=
case_root=
case_swtpm_running=0
gateway_pid=
gateway_expected_executable=
gateway_executable=
gateway_start=
gateway_ready=0
gateway_command=()
driver_pid=
driver_executable=
driver_start=
private_dir=
blocker="$state_dir/recovery-matrix-blocked.log"
serial_failure="$state_dir/recovery-secureboot-preflight-failed.log"
serial_success="$state_dir/recovery-secureboot-preflight.log"
output_limit_kib=65536
# recovery-live-driver.py bounds its cooperative QEMU cleanup at 10.2 seconds.
# Leave margin before the identity-verified helper is allowed to SIGKILL it.
driver_term_timeout=12
child_stopped() {
    local pid=$1
    local encoded remainder state
    if [[ ! -r /proc/$pid/stat ]]; then
        return 0
    fi
    encoded=$(<"/proc/$pid/stat")
    remainder=${encoded##*) }
    state=${remainder%% *}
    [[ $state == Z ]]
}
process_start_time() {
    python3 - "$1" <<'PY'
import pathlib
import sys
encoded = pathlib.Path(f"/proc/{int(sys.argv[1])}/stat").read_bytes()
print(encoded.rsplit(b") ", 1)[1].split()[19].decode("ascii"))
PY
}
terminate_gateway() {
    local pid=${gateway_pid:-}
    [[ -n $pid ]] || return 0
    if ! child_stopped "$pid"; then
        if [[ -n $gateway_executable && -n $gateway_start ]]; then
            if (( ${#gateway_command[@]} > 0 )); then
                verify_gateway_command_identity || return 1
            fi
            python3 "$script_dir/terminate-child-process.py" \
                "$pid" "$gateway_executable" "$gateway_start" || return 1
        else
            # Before readiness proves the executable/start identity, this is the
            # still-unreaped direct child started by this shell.  Never derive
            # cleanup identity from a potentially unrelated /proc entry.
            kill -TERM -- "$pid" 2>/dev/null || true
        fi
    fi
    wait "$pid" 2>/dev/null || true
    gateway_pid=
    gateway_expected_executable=
    gateway_executable=
    gateway_start=
    gateway_ready=0
    gateway_command=()
}
record_blocker() {
    if [[ -z $blocker || -e $blocker || -L $blocker ]]; then
        return
    fi
    if (set -C; : >"$blocker") 2>/dev/null && [[ -f $blocker && ! -L $blocker ]]; then
        chmod 0600 -- "$blocker" 2>/dev/null || true
        printf '%s\n' 'PBNS_RECOVERY_MATRIX_BLOCKED' >"$blocker" 2>/dev/null || true
    fi
}
terminate_driver() {
    local pid=${driver_pid:-}
    [[ -n $pid ]] || return 0
    if ! child_stopped "$pid"; then
        [[ -n ${driver_executable:-} && -n ${driver_start:-} ]] || return 1
        python3 "$script_dir/terminate-child-process.py" \
            "$pid" "$driver_executable" "$driver_start" \
            --term-timeout "$driver_term_timeout" || return 1
    fi
    wait "$pid" 2>/dev/null || true
    driver_pid=
    driver_executable=
    driver_start=
}
cleanup() {
    status=$?
    trap - EXIT INT TERM
    # Stop the verified gateway first so its connection closure can let the
    # driver finish naturally; terminate_driver retains its exact identity as a
    # bounded fallback.
    if ! terminate_gateway >/dev/null 2>&1; then
        status=1
    fi
    if ! terminate_driver >/dev/null 2>&1; then
        status=1
    fi
    if [[ $case_swtpm_running -eq 1 && -n $case_root &&
          -d $case_root/swtpm-state ]]; then
        "$pbns_root/integration/swtpm/stop-swtpm.sh" \
            "$case_root/swtpm-state" >/dev/null 2>&1 || true
    fi
    [[ -z $private_dir ]] || rm -rf -- "$private_dir"
    [[ -z $case_tmp ]] || rm -rf -- "$case_tmp"
    if (( status != 0 )); then
        record_blocker
    fi
    [[ -z $preflight_dir ]] || rm -rf -- "$preflight_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() {
    printf '%s\n' 'PBNS_RECOVERY_MATRIX_BLOCKED' >&2
    exit 1
}

for tool in go qemu-system-x86_64 sbsign sbverify sbattach sha256sum timeout truncate \
            virt-fw-vars openssl python3 swtpm tpm2_getcap; do
    command -v "$tool" >/dev/null || fail
done

code=${PBNS_OVMF_SECUREBOOT_CODE:-/usr/share/edk2/OvmfX64/OVMF_CODE.secboot.fd}
vars_source="$state_dir/OVMF_VARS.secboot.fd"
shell=${PBNS_OVMF_SHELL:-/usr/share/edk2/OvmfX64/Shell.efi}
uki_test_cert="$pbns_root/tests/fixtures/keys/uki-secureboot-test-cert.pem"
uki_test_key="$pbns_root/tests/fixtures/keys/uki-secureboot-test-key.pem"
recovery_app=${PBNS_RECOVERY_APP:-$pbns_root/.deps/edk2/Build/PbnsPkg/DEBUG_GCC/X64/PBNSRecovery.efi}
live_result="$pbns_root/eval/results/recovery-live-qemu.json"
for artifact in "$code" "$vars_source" "$shell" "$uki_test_cert" "$uki_test_key"; do
    [[ -f $artifact && ! -L $artifact ]] || fail
done
[[ $(stat -c %a "$vars_source") == 600 ]] || fail
if [[ -e $blocker || -L $blocker || -e $serial_failure || -L $serial_failure ||
      -e $serial_success || -L $serial_success ]]; then
    fail
fi

preflight_dir=$(mktemp -d "$state_dir/.recovery-preflight.XXXXXX") || fail
chmod 0700 "$preflight_dir" || fail
preflight_log="$preflight_dir/serial.log"
preflight_vars="$preflight_dir/OVMF_VARS.fd"
preflight_code="$preflight_dir/OVMF_CODE.fd"
preflight_esp="$preflight_dir/esp"
preflight_private="$preflight_dir/private"
mkdir -m 0700 -p "$preflight_esp/EFI/BOOT" "$preflight_private" || fail
install -m 0600 "$code" "$preflight_code" || fail
install -m 0600 "$vars_source" "$preflight_vars" || fail
install -m 0600 "$uki_test_key" "$preflight_private/uki-test.key" || fail
python3 "$script_dir/verify-secureboot-store.py" \
    --vars "$preflight_vars" --fixture-cert "$uki_test_cert" \
    --decoded "$preflight_dir/OVMF_VARS.verified.txt" --scratch-parent "$preflight_dir" || fail
sbsign --key "$preflight_private/uki-test.key" --cert "$uki_test_cert" \
    --output "$preflight_esp/EFI/BOOT/BOOTX64.EFI" "$shell" >/dev/null || fail
chmod 0644 "$preflight_esp/EFI/BOOT/BOOTX64.EFI" || fail
printf '%s\r\n' \
    'echo -off' \
    'echo PBNS-SB-BEGIN-SecureBoot' \
    'dmpstore -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C SecureBoot' \
    'echo PBNS-SB-END-SecureBoot' \
    'echo PBNS-SB-BEGIN-SetupMode' \
    'dmpstore -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C SetupMode' \
    'echo PBNS-SB-END-SetupMode' \
    'reset -c' >"$preflight_esp/startup.nsh" || fail

set +e
(
    ulimit -f "$output_limit_kib"
    exec timeout --signal=TERM --kill-after=5s 45s qemu-system-x86_64 \
        -machine q35,accel=tcg -cpu max -m 512M \
        -drive "if=pflash,format=raw,readonly=on,file=$preflight_code" \
        -drive "if=pflash,format=raw,file=$preflight_vars" \
        -drive "format=raw,file=fat:rw:$preflight_esp" \
        -nic none -display none -serial stdio -monitor none -no-reboot
) >"$preflight_log" 2>&1
preflight_status=$?
set -e
serial_safe() {
    ! grep -Eiq \
        'private[[:space:]_-]*key|identity[[:space:]_-]*(material|key|cose)|tpm[[:space:]_-]*(blob|auth|authorization|session|nonce)|auth[[:space:]_-]*value|session[[:space:]_-]*nonce|token|nonce|decrypted[[:space:]_-]*transcript|policy[[:space:]_-]*(authorization|internal)|artifact[[:space:]_-]*bytes|transient[[:space:]_-]*crypto' \
        "$preflight_log"
}
if [[ $preflight_status != 0 && $preflight_status != 124 ]] || ! serial_safe ||
   ! python3 "$script_dir/verify-secureboot-preflight.py" --serial "$preflight_log" >/dev/null; then
    if serial_safe && [[ ! -e $serial_failure && ! -L $serial_failure ]]; then
        install -m 0600 "$preflight_log" "$serial_failure" || true
    fi
    fail
fi
install -m 0600 "$preflight_log" "$serial_success" || fail
python3 "$script_dir/verify-secureboot-preflight.py" --serial "$serial_success" >/dev/null || fail
printf '%s\n' 'PBNS SECUREBOOT PREFLIGHT PASS SecureBoot=1 SetupMode=0'

base="$state_dir/recovery-base"
remaining_cases=(
    unsigned-untrusted truncated gateway-interruption forged-manifest
    forged-digest forged-chunk downgrade normal-launcher pico-absent
)
if [[ ! -d $base || -L $base ]]; then
    printf '%s\n' '[NOT-RUN] signed-trusted'
    for name in "${remaining_cases[@]}"; do
        printf '[NOT-RUN] %s\n' "$name"
    done
    printf '%s\n' 'RECOVERY MATRIX BLOCKED'
    exit 1
fi
if [[ -e $live_result || -L $live_result || -z ${PBNS_GATEWAY_SERVER_NAME:-} ]]; then
    fail
fi

cases="$state_dir/cases"
case_root="$state_dir/cases/signed-trusted"
case_tmp="$state_dir/cases/.signed-trusted.tmp.$$"
if [[ -e $case_root || -L $case_root || -e $case_tmp || -L $case_tmp ]]; then
    fail
fi
if [[ ! -e $cases ]]; then
    mkdir -m 0700 "$cases" || fail
fi
if [[ ! -d $cases || -L $cases || $(stat -c %a "$cases") != 700 ||
      $(stat -c %u "$cases") != $EUID ]]; then
    fail
fi
clone_coupled_base() {
    local case_name=$1
    case_root="$cases/$case_name"
    case_tmp="$cases/.$case_name.tmp.$$"
    if [[ -e $case_root || -L $case_root || -e $case_tmp || -L $case_tmp ]]; then
        fail
    fi
    python3 - "$base" "$case_tmp" <<'PY'
import hashlib
import os
import pathlib
import shutil
import stat
import sys
source = pathlib.Path(sys.argv[1]).resolve(strict=True)
destination = pathlib.Path(sys.argv[2])
if destination.exists() or destination.is_symlink():
    raise SystemExit("signed case destination already exists")
def inventory(root: pathlib.Path):
    result = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit("coupled base contains a symlink")
        if stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise SystemExit("coupled base directory mode mismatch")
            result[relative] = ("d", 0, "")
        elif stat.S_ISREG(info.st_mode):
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise SystemExit("coupled base file mode mismatch")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result[relative] = ("f", info.st_size, digest)
        else:
            raise SystemExit("coupled base contains a special file")
    return result
expected = inventory(source)
shutil.copytree(source, destination, symlinks=False)
os.chmod(destination, 0o700)
if inventory(destination) != expected:
    raise SystemExit("coupled case clone mismatch")
for path in sorted(destination.rglob("*"), reverse=True):
    if path.is_file():
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
for path in sorted((item for item in destination.rglob("*") if item.is_dir()), reverse=True):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
    mv -T -- "$case_tmp" "$case_root" || fail
    case_tmp=
    sync -f "$cases" || fail
}
clone_coupled_base "signed-trusted"

case_code="$case_root/OVMF_CODE.fd"
case_vars="$case_root/OVMF_VARS.fd"
case_esp="$case_root/esp-template"
case_swtpm="$case_root/swtpm-state"
case_database="$case_root/gateway.db"
disk="$case_root/disk.raw"
serial="$case_root/serial.log"
nv_before="$case_root/nv-before.bin"
nv_after="$case_root/nv-after.bin"
nv_before_runtime="$case_swtpm/nv-before.bin"
nv_after_runtime="$case_swtpm/nv-after.bin"
disk_before="$case_root/disk-before.sha256"
disk_after="$case_root/disk-after.sha256"
private_dir="$case_root/private"
repository="$case_root/repository"
gateway_log="$case_root/gateway.log"
mkdir -m 0700 "$private_dir" "$case_root/artifact-input"
python3 "$script_dir/verify-secureboot-store.py" \
    --vars "$case_vars" --fixture-cert "$uki_test_cert" \
    --decoded "$case_root/secureboot-store.txt" --scratch-parent "$case_root" || fail
signed_secureboot_log="$case_root/signed-secureboot-runtime.log"
signed_preflight_dir="$case_root/.signed-secureboot-preflight"
mkdir -m 0700 "$signed_preflight_dir" "$signed_preflight_dir/EFI" \
    "$signed_preflight_dir/EFI/BOOT"
install -m 0600 "$case_esp/EFI/BOOT/BOOTX64.EFI" \
    "$signed_preflight_dir/EFI/BOOT/BOOTX64.EFI"
printf '%s\r\n' \
    'echo -off' \
    'echo PBNS-SB-BEGIN-SecureBoot' \
    'dmpstore -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C SecureBoot' \
    'echo PBNS-SB-END-SecureBoot' \
    'echo PBNS-SB-BEGIN-SetupMode' \
    'dmpstore -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C SetupMode' \
    'echo PBNS-SB-END-SetupMode' \
    'reset -c' >"$signed_preflight_dir/startup.nsh"
chmod 0600 "$signed_preflight_dir/startup.nsh"
python3 "$script_dir/secureboot-runtime-driver.py" \
    --case-root "$case_root" --code "$case_code" --variables "$case_vars" \
    --esp "$signed_preflight_dir" --log "$signed_secureboot_log" || fail
chmod 0600 "$case_vars"
rm -rf -- "$signed_preflight_dir"
printf '%s\r\n' '@echo -off' 'fs0:\EFI\PBNS\PBNSRecovery.efi' \
    >"$case_esp/startup.nsh"
chmod 0600 "$case_esp/startup.nsh"
truncate -s 67108864 "$disk"
chmod 0600 "$disk"
hash_disk() {
    image=$1
    output=$2
    digest=$(sha256sum "$image" | awk '{print $1}')
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || fail
    (set -o noclobber; printf '%s\n' "$digest" >"$output") || fail
    chmod 0600 "$output"
}
hash_disk "$disk" "$disk_before"
publish_nv_evidence() {
    source=$1
    destination=$2
    if [[ ! -f $source || -L $source || $(stat -c %u "$source") -ne $EUID ||
          $(stat -c %a "$source") != 600 || $(stat -c %s "$source") -ne 8 ||
          $(dirname -- "$destination") != "$case_root" || -e $destination ||
          -L $destination ]]; then
        fail
    fi
    (set -o noclobber; cat -- "$source" >"$destination") || fail
    chmod 0600 "$destination" || fail
    [[ $(stat -c %s "$destination") -eq 8 ]] || fail
    sync -f "$destination" || fail
    sync -f "$case_root" || fail
}

expected_uki_sha256=d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3
expected_uki_size=26553920
signed_uki="$pbns_root/integration/state/task14c-signed-final-20260810T022831Z.DBx3aC/cases/signed-trusted/repository/artifacts/$expected_uki_sha256"
# This repository object is immutable input. Verify it completely before making
# the mode-0600 disposable copy used by the signed recovery case.
if ! [[ -f $signed_uki && ! -L $signed_uki ]] ||
   [[ $(stat -c %u "$signed_uki") -ne $EUID ]] ||
   [[ $(stat -c %a "$signed_uki") != 444 ]] ||
   [[ $(basename -- "$signed_uki") != $expected_uki_sha256 ]] ||
   [[ $(stat -c %s "$signed_uki") -ne $expected_uki_size ]] ||
   [[ $(sha256sum "$signed_uki" | awk '{print $1}') != $expected_uki_sha256 ]]; then
    fail
fi
sbverify --cert "$uki_test_cert" "$signed_uki" >/dev/null 2>&1 || fail
artifact_input="$case_root/artifact-input/PBNSRecovery.efi"
install -m 0600 "$signed_uki" "$artifact_input"
artifact_size=$(stat -c %s "$artifact_input")
[[ $artifact_size -eq $expected_uki_size ]] || fail

install -m 0600 "$pbns_root/tests/fixtures/keys/tls-gateway-test-key.pem" \
    "$private_dir/tls-key.pem"
install -m 0600 "$pbns_root/tests/fixtures/keys/service-signing-test-private.pem" \
    "$private_dir/time-source.pem"
openssl ec -in "$private_dir/time-source.pem" \
    -out "$private_dir/time-signing.pem" >/dev/null 2>&1
install -m 0600 "$pbns_root/tests/fixtures/keys/recovery-manifest-test-private.pem" \
    "$private_dir/manifest-source.pem"
openssl ec -in "$private_dir/manifest-source.pem" \
    -out "$private_dir/manifest-signing.pem" >/dev/null 2>&1
install -m 0600 "$pbns_root/tests/fixtures/keys/recovery-policy-test-public.pem" \
    "$private_dir/policy-public.pem"
install -m 0600 "$uki_test_cert" "$private_dir/secureboot-public.pem"
chmod 0600 "$private_dir/time-signing.pem" "$private_dir/manifest-signing.pem"

python3 - "$PBNS_GATEWAY_SERVER_NAME" "$private_dir/server.ext" <<'PY'
import ipaddress
import json
import pathlib
import re
import socket
import subprocess
import sys
name = sys.argv[1]
try:
    address = ipaddress.ip_address(name)
except ValueError:
    label = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    if not name or len(name) > 253 or any(
        label.fullmatch(item) is None for item in name.split(".")
    ):
        raise SystemExit("invalid recovery gateway name")
    san = f"DNS:{name}"
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    }
else:
    san = f"IP:{address.compressed}"
    addresses = {address.compressed}
local = {
    info["local"]
    for interface in json.loads(
        subprocess.check_output(["ip", "-j", "-4", "address"], text=True)
    )
    for info in interface.get("addr_info", [])
}
if not addresses or addresses.isdisjoint(local):
    raise SystemExit("recovery gateway SAN is not assigned locally")
pathlib.Path(sys.argv[2]).write_text(
    "basicConstraints=critical,CA:FALSE\n"
    "keyUsage=critical,digitalSignature\n"
    "extendedKeyUsage=serverAuth\n"
    f"subjectAltName={san}\n",
    encoding="ascii",
)
PY
chmod 0600 "$private_dir/server.ext"
openssl req -new -key "$private_dir/tls-key.pem" -subj '/CN=pbns-gateway.test' \
    -out "$private_dir/gateway.csr" >/dev/null 2>&1
openssl x509 -req -in "$private_dir/gateway.csr" \
    -signkey "$private_dir/tls-key.pem" -sha256 -days 3650 \
    -set_serial 0x50424e5302 -extfile "$private_dir/server.ext" \
    -out "$private_dir/tls-cert.pem" >/dev/null 2>&1
chmod 0600 "$private_dir/gateway.csr" "$private_dir/tls-cert.pem"
python3 "$pbns_root/integration/tls/verify-spki.py" \
    "$private_dir/tls-cert.pem" \
    "$pbns_root/tests/fixtures/keys/tls-gateway-test-spki.sha256" >/dev/null || fail
if [[ $PBNS_GATEWAY_SERVER_NAME =~ ^[0-9a-fA-F:.]+$ ]]; then
    openssl x509 -in "$private_dir/tls-cert.pem" -noout \
        -checkip "$PBNS_GATEWAY_SERVER_NAME" >/dev/null || fail
else
    openssl x509 -in "$private_dir/tls-cert.pem" -noout \
        -checkhost "$PBNS_GATEWAY_SERVER_NAME" >/dev/null || fail
fi
(
    cd -- "$pbns_root/gateway"
    go build -trimpath -o "$private_dir/pbns-gateway" ./cmd/pbns-gateway
    go build -trimpath -o "$private_dir/pbnsctl" ./cmd/pbnsctl
) || fail
chmod 0700 "$private_dir/pbns-gateway" "$private_dir/pbnsctl"
host_output=$("$private_dir/pbnsctl" --db "$case_database" hosts list) || fail
if ! grep -Fqx 'hosts=1' <<<"$host_output"; then
    host_output=
    unset host_output
    fail
fi
host_output=
unset host_output

read -r not_before not_after < <(python3 - <<'PY'
import datetime
now = datetime.datetime.now(datetime.UTC)
print(
    (now - datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
)
PY
)
"$private_dir/pbnsctl" recovery publish \
    --artifact "$artifact_input" \
    --repository "$repository" \
    --request-id 00112233445566778899aabbccddeeff \
    --host-binding 102132435465768798a9bacbdcedfe0f00112233445566778899aabbccddeeff \
    --nonce ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 \
    --not-before "$not_before" --not-after "$not_after" \
    --version 7 --minimum-version 6 \
    --policy-authorization "$case_swtpm/recovery-policy/target-7.cbor" \
    --policy-key-id recovery-policy-key-1 \
    --manifest-private-key "$private_dir/manifest-signing.pem" \
    --manifest-key-id recovery-manifest-key-1 \
    --secureboot-public-key "$private_dir/secureboot-public.pem" \
    --output "$private_dir/offline-manifest.cbor" \
    >"$private_dir/publication.json" || fail
chmod 0600 "$private_dir/offline-manifest.cbor" "$private_dir/publication.json"
read -r artifact_digest published_size < <(python3 - \
    "$private_dir/publication.json" "$case_root/artifact-publication.json" <<'PY'
import json
import os
import pathlib
import re
import sys
source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
value = json.loads(source.read_text(encoding="utf-8"))
digest = value.get("artifact_sha256")
size = value.get("artifact_size")
version = value.get("version")
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit("publication digest is invalid")
if not isinstance(size, int) or size <= 0 or version != 7:
    raise SystemExit("publication metadata is invalid")
encoded = json.dumps(
    {"artifact_sha256": digest, "artifact_size": size, "version": version},
    sort_keys=True,
).encode("ascii") + b"\n"
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, encoded)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
print(digest, size)
PY
) || fail
if [[ $artifact_digest != $expected_uki_sha256 ||
      $published_size -ne $artifact_size ]]; then
    fail
fi

(set -o noclobber; : >"$gateway_log") || fail
chmod 0600 "$gateway_log"
gateway_expected_executable=$(readlink -f "$private_dir/pbns-gateway") || fail
(
    ulimit -f "$output_limit_kib"
    exec "$private_dir/pbns-gateway" \
        --listen 0.0.0.0:8443 \
        --tls-cert "$private_dir/tls-cert.pem" \
        --tls-key "$private_dir/tls-key.pem" \
        --handshake-timeout 15s --read-timeout 60s --write-timeout 60s \
        --enrollment-store "$case_database" \
        --time-signing-key "$private_dir/time-signing.pem" \
        --time-signing-kid time-key-1 \
        --time-uncertainty 250ms --time-quality qemu-gateway-synchronized \
        --recovery-repository "$repository" \
        --recovery-artifact-sha256 "$artifact_digest" \
        --recovery-target-version 7 \
        --recovery-minimum-version 6 \
        --recovery-policy-authorization "$case_swtpm/recovery-policy/target-7.cbor" \
        --recovery-policy-public-key "$private_dir/policy-public.pem" \
        --recovery-policy-kid recovery-policy-key-1 \
        --recovery-manifest-signing-key "$private_dir/manifest-signing.pem" \
        --recovery-manifest-signing-kid recovery-manifest-key-1 \
        --recovery-secureboot-public-key "$private_dir/secureboot-public.pem" \
        --recovery-validity-lead 2m \
        --recovery-validity-trailing 2m \
        --recovery-transfer-timeout 45m
) >>"$gateway_log" 2>&1 &
gateway_pid=$!
gateway_ready=0
for _ in $(seq 1 20); do
    child_stopped "$gateway_pid" && fail
    if [[ $(readlink -f "/proc/$gateway_pid/exe" 2>/dev/null) == \
          "$gateway_expected_executable" ]]; then
        candidate_gateway_start=$(process_start_time "$gateway_pid") || continue
        if [[ $(readlink -f "/proc/$gateway_pid/exe" 2>/dev/null) == \
              "$gateway_expected_executable" && -n $candidate_gateway_start ]]; then
            gateway_executable=$gateway_expected_executable
            gateway_start=$candidate_gateway_start
            gateway_ready=1
            break
        fi
    fi
    sleep 0.05
done
[[ $gateway_ready -eq 1 && -n $gateway_executable && -n $gateway_start ]] || fail
[[ $(readlink -f "/proc/$gateway_pid/exe" 2>/dev/null) == "$gateway_executable" ]] || fail
printf '%s\n' \
    'production-gateway=true' \
    'recovery-target-version=7' \
    'recovery-minimum-version=6' \
    'evaluation-events=absent' >"$case_root/production-gateway-profile.txt"
chmod 0600 "$case_root/production-gateway-profile.txt"

case_swtpm_running=1
"$pbns_root/integration/swtpm/resume-swtpm.sh" "$case_swtpm" >/dev/null || fail
"$pbns_root/integration/swtpm/run-recovery-policy-live.sh" read \
    "$case_swtpm" "$nv_before_runtime" >/dev/null || fail
python3 "$script_dir/recovery-live-driver.py" \
    --case-root "$case_root" --case signed-trusted --phase recovery \
    --code "$case_code" --variables "$case_vars" --esp "$case_esp" \
    --swtpm-state "$case_swtpm" --disk "$disk" --log "$serial" \
    --pico present || fail
"$pbns_root/integration/swtpm/pause-swtpm.sh" "$case_swtpm" >/dev/null || fail
case_swtpm_running=0
case_swtpm_running=1
"$pbns_root/integration/swtpm/resume-swtpm.sh" "$case_swtpm" >/dev/null || fail
"$pbns_root/integration/swtpm/run-recovery-policy-live.sh" read \
    "$case_swtpm" "$nv_after_runtime" >/dev/null || fail
publish_nv_evidence "$nv_before_runtime" "$nv_before"
publish_nv_evidence "$nv_after_runtime" "$nv_after"
hash_disk "$disk" "$disk_after"
python3 "$script_dir/verify-secureboot-preflight.py" \
    --serial "$signed_secureboot_log" >/dev/null || fail
stream_duration_ms=$(python3 "$script_dir/verify-recovery-observability.py" \
    --serial "$serial" --nv-before "$nv_before" --nv-after "$nv_after" \
    --disk-before "$disk_before" --disk-after "$disk_after" \
    --case-root "$case_root" --expected-size "$artifact_size" \
    --current-version 5 --target-version 7 --print-stream-duration
) || fail
[[ $stream_duration_ms =~ ^(0|[1-9][0-9]*)$ ]] || fail
[[ $stream_duration_ms -le 60000 ]] || fail

terminate_gateway || fail
if grep -Eiq \
    'private[[:space:]_-]*key|identity[[:space:]_-]*(material|key|cose)|tpm[[:space:]_-]*(blob|auth|authorization|session|nonce)|auth[[:space:]_-]*value|session[[:space:]_-]*nonce|token|nonce|decrypted[[:space:]_-]*transcript|policy[[:space:]_-]*(authorization|internal)|artifact[[:space:]_-]*bytes|transient[[:space:]_-]*crypto' \
    "$gateway_log"; then
    printf '%s\n' 'PBNS GATEWAY LOG REJECT' >"$gateway_log"
    chmod 0600 "$gateway_log"
    sync -f "$gateway_log"
    fail
fi
"$pbns_root/integration/swtpm/stop-swtpm.sh" "$case_swtpm" >/dev/null || fail
case_swtpm_running=0
rm -rf -- "$private_dir"
private_dir=
python3 - "$case_root/tls-profile.json" "$stream_duration_ms" <<'PY' || fail
import json
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
duration_ms = int(sys.argv[2])
if path.name != "tls-profile.json" or path.parent.name != "signed-trusted" or not 0 <= duration_ms <= 60000:
    raise SystemExit(1)
value = {
    "alpn": "pbns/1",
    "cipher_suite": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "duration_ms": duration_ms,
    "pinned_spki_sha256": "a0d21923ddfccba12d0a7bbd7408650cb8c54f1be537fe3a7e69adb1376da106",
    "server_san": "192.168.1.180",
    "tls_version": "TLS 1.2",
}
encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, encoded)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
printf '%s\n' '[PASS] signed-trusted'
if [[ $selected_case == signed-trusted ]]; then
    printf '%s\n' 'RECOVERY MATRIX PASS'
    exit 0
fi

# Each production negative begins from the stopped coupled base; no state from the
# successful pass is reused.  PBNS_ERR_REPLAY is emitted by firmware as status=-15.
run_production_failure_case() {
    local case_name=$1 target_version=$2 minimum_version=$3 policy_name=$4 mutation=$5
    local manifest_signing artifact_digest published_size signed_hash unsigned_hash
    clone_coupled_base "$case_name"
    case_code="$case_root/OVMF_CODE.fd"
    case_vars="$case_root/OVMF_VARS.fd"
    case_esp="$case_root/esp-template"
    case_swtpm="$case_root/swtpm-state"
    case_database="$case_root/gateway.db"
    disk="$case_root/disk.raw"
    serial="$case_root/serial.log"
    nv_before="$case_root/nv-before.bin"
    nv_after="$case_root/nv-after.bin"
    nv_before_runtime="$case_swtpm/nv-before.bin"
    nv_after_runtime="$case_swtpm/nv-after.bin"
    disk_before="$case_root/disk-before.sha256"
    disk_after="$case_root/disk-after.sha256"
    private_dir="$case_root/private"
    repository="$case_root/repository"
    gateway_log="$case_root/gateway.log"
    artifact_input="$case_root/artifact.efi"
    mkdir -m 0700 "$private_dir"
    python3 "$script_dir/verify-secureboot-store.py" \
        --vars "$case_vars" --fixture-cert "$uki_test_cert" \
        --decoded "$case_root/secureboot-store.txt" --scratch-parent "$case_root" || fail
    printf '%s\r\n' '@echo -off' 'fs0:\EFI\PBNS\PBNSRecovery.efi' >"$case_esp/startup.nsh"
    chmod 0600 "$case_esp/startup.nsh"
    truncate -s 67108864 "$disk"
    chmod 0600 "$disk"
    hash_disk "$disk" "$disk_before"
    install -m 0600 "$signed_uki" "$artifact_input"
    signed_hash=$(sha256sum "$artifact_input" | awk '{print $1}')
    case $mutation in
        unsigned)
            sbattach --remove "$artifact_input" >/dev/null 2>&1 || fail
            signature_report=$(sbverify --list "$artifact_input" 2>&1 || true)
            [[ $signature_report == *"No signature table present"* ]] || fail
            python3 - "$artifact_input" <<'PY' || fail
import pathlib
import sys
value = pathlib.Path(sys.argv[1]).read_bytes()
if len(value) == 0 or value[:2] != b"MZ":
    raise SystemExit(1)
PY
            ;;
        truncated)
            unsigned_probe="$private_dir/unsigned-reference.efi"
            install -m 0600 "$signed_uki" "$unsigned_probe"
            sbattach --remove "$unsigned_probe" >/dev/null 2>&1 || fail
            unsigned_hash=$(sha256sum "$unsigned_probe" | awk '{print $1}')
            rm -f -- "$unsigned_probe"
            artifact_size=$(stat -c %s "$artifact_input")
            [[ $artifact_size -gt 1 ]] || fail
            truncate -s $((artifact_size / 2)) "$artifact_input"
            ;;
        forged-manifest|downgrade) ;;
        *) fail ;;
    esac
    artifact_size=$(stat -c %s "$artifact_input")
    [[ $artifact_size -gt 0 ]] || fail
    artifact_digest=$(sha256sum "$artifact_input" | awk '{print $1}')
    [[ $artifact_digest =~ ^[0-9a-f]{64}$ && $artifact_digest != "$signed_hash" ]] ||
        [[ $mutation == forged-manifest || $mutation == downgrade ]] || fail
    if [[ $mutation == truncated && $artifact_digest == "$unsigned_hash" ]]; then
        fail
    fi

    install -m 0600 "$pbns_root/tests/fixtures/keys/tls-gateway-test-key.pem" "$private_dir/tls-key.pem"
    install -m 0600 "$pbns_root/tests/fixtures/keys/service-signing-test-private.pem" "$private_dir/time-source.pem"
    openssl ec -in "$private_dir/time-source.pem" -out "$private_dir/time-signing.pem" >/dev/null 2>&1 || fail
    install -m 0600 "$pbns_root/tests/fixtures/keys/recovery-policy-test-public.pem" "$private_dir/policy-public.pem"
    install -m 0600 "$uki_test_cert" "$private_dir/secureboot-public.pem"
    if [[ $mutation == forged-manifest ]]; then
        openssl ecparam -name prime256v1 -genkey -noout -out "$private_dir/forged-manifest-signing.pem" >/dev/null 2>&1 || fail
        manifest_signing="$private_dir/forged-manifest-signing.pem"
    else
        install -m 0600 "$pbns_root/tests/fixtures/keys/recovery-manifest-test-private.pem" "$private_dir/manifest-source.pem"
        openssl ec -in "$private_dir/manifest-source.pem" -out "$private_dir/manifest-signing.pem" >/dev/null 2>&1 || fail
        manifest_signing="$private_dir/manifest-signing.pem"
    fi
    chmod 0600 "$private_dir/time-signing.pem" "$manifest_signing"
    python3 - "$PBNS_GATEWAY_SERVER_NAME" "$private_dir/server.ext" <<'PY' || fail
import ipaddress
import pathlib
import sys
name = sys.argv[1]
try:
    san = f"IP:{ipaddress.ip_address(name).compressed}"
except ValueError:
    if not name or any(not item for item in name.split(".")):
        raise SystemExit(1)
    san = f"DNS:{name}"
pathlib.Path(sys.argv[2]).write_text(
    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
    "extendedKeyUsage=serverAuth\nsubjectAltName=" + san + "\n", encoding="ascii")
PY
    chmod 0600 "$private_dir/server.ext"
    openssl req -new -key "$private_dir/tls-key.pem" -subj '/CN=pbns-gateway.test' -out "$private_dir/gateway.csr" >/dev/null 2>&1 || fail
    openssl x509 -req -in "$private_dir/gateway.csr" -signkey "$private_dir/tls-key.pem" -sha256 -days 3650 -set_serial 0x50424e5302 -extfile "$private_dir/server.ext" -out "$private_dir/tls-cert.pem" >/dev/null 2>&1 || fail
    chmod 0600 "$private_dir/gateway.csr" "$private_dir/tls-cert.pem"
    python3 "$pbns_root/integration/tls/verify-spki.py" "$private_dir/tls-cert.pem" "$pbns_root/tests/fixtures/keys/tls-gateway-test-spki.sha256" >/dev/null || fail
    (
        cd -- "$pbns_root/gateway"
        go build -trimpath -o "$private_dir/pbns-gateway" ./cmd/pbns-gateway
        go build -trimpath -o "$private_dir/pbnsctl" ./cmd/pbnsctl
    ) || fail
    chmod 0700 "$private_dir/pbns-gateway" "$private_dir/pbnsctl"
    "$private_dir/pbnsctl" --db "$case_database" hosts list | grep -Fqx 'hosts=1' || fail
    read -r not_before not_after < <(python3 - <<'PY'
import datetime
now = datetime.datetime.now(datetime.UTC)
print((now - datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
      (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)
    "$private_dir/pbnsctl" recovery publish \
        --artifact "$artifact_input" --repository "$repository" \
        --request-id 00112233445566778899aabbccddeeff \
        --host-binding 102132435465768798a9bacbdcedfe0f00112233445566778899aabbccddeeff \
        --nonce ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 \
        --not-before "$not_before" --not-after "$not_after" \
        --version "$target_version" --minimum-version "$minimum_version" \
        --policy-authorization "$case_swtpm/recovery-policy/$policy_name" \
        --policy-key-id recovery-policy-key-1 --manifest-private-key "$manifest_signing" \
        --manifest-key-id recovery-manifest-key-1 --secureboot-public-key "$private_dir/secureboot-public.pem" \
        --output "$private_dir/offline-manifest.cbor" >"$private_dir/publication.json" || fail
    chmod 0600 "$private_dir/offline-manifest.cbor" "$private_dir/publication.json"
    python3 - "$private_dir/publication.json" "$case_root/artifact-publication.json" "$target_version" "$artifact_digest" "$artifact_size" <<'PY' || fail
import json
import os
import pathlib
import sys
source, output, version, digest, size = map(pathlib.Path, sys.argv[1:])
value = json.loads(source.read_text(encoding="utf-8"))
if value.get("artifact_sha256") != str(digest) or value.get("artifact_size") != int(str(size)) or value.get("version") != int(str(version)):
    raise SystemExit(1)
encoded = json.dumps({"artifact_sha256": str(digest), "artifact_size": int(str(size)), "version": int(str(version))}, sort_keys=True).encode("ascii") + b"\n"
fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, encoded)
    os.fsync(fd)
finally:
    os.close(fd)
PY
    (set -o noclobber; : >"$gateway_log") || fail
    chmod 0600 "$gateway_log"
    gateway_expected_executable=$(readlink -f "$private_dir/pbns-gateway") || fail
    (
        ulimit -f "$output_limit_kib"
        exec "$private_dir/pbns-gateway" --listen 0.0.0.0:8443 \
            --tls-cert "$private_dir/tls-cert.pem" --tls-key "$private_dir/tls-key.pem" \
            --handshake-timeout 15s --read-timeout 60s --write-timeout 60s \
            --enrollment-store "$case_database" --time-signing-key "$private_dir/time-signing.pem" \
            --time-signing-kid time-key-1 --time-uncertainty 250ms --time-quality qemu-gateway-synchronized \
            --recovery-repository "$repository" --recovery-artifact-sha256 "$artifact_digest" \
            --recovery-target-version "$target_version" --recovery-minimum-version "$minimum_version" \
            --recovery-policy-authorization "$case_swtpm/recovery-policy/$policy_name" \
            --recovery-policy-public-key "$private_dir/policy-public.pem" --recovery-policy-kid recovery-policy-key-1 \
            --recovery-manifest-signing-key "$manifest_signing" --recovery-manifest-signing-kid recovery-manifest-key-1 \
            --recovery-secureboot-public-key "$private_dir/secureboot-public.pem" \
            --recovery-validity-lead 2m --recovery-validity-trailing 2m --recovery-transfer-timeout 45m
    ) >>"$gateway_log" 2>&1 &
    gateway_pid=$!
    gateway_ready=0
    for _ in $(seq 1 20); do
        child_stopped "$gateway_pid" && fail
        if [[ $(readlink -f "/proc/$gateway_pid/exe" 2>/dev/null) == "$gateway_expected_executable" ]]; then
            candidate_gateway_start=$(process_start_time "$gateway_pid") || continue
            if [[ $(readlink -f "/proc/$gateway_pid/exe" 2>/dev/null) == "$gateway_expected_executable" && -n $candidate_gateway_start ]]; then
                gateway_executable=$gateway_expected_executable
                gateway_start=$candidate_gateway_start
                gateway_ready=1
                break
            fi
        fi
        sleep 0.05
    done
    [[ $gateway_ready -eq 1 && -n $gateway_executable && -n $gateway_start ]] || fail
    [[ $(readlink -f "/proc/$gateway_pid/exe" 2>/dev/null) == "$gateway_executable" ]] || fail
    case_swtpm_running=1
    "$pbns_root/integration/swtpm/resume-swtpm.sh" "$case_swtpm" >/dev/null || fail
    "$pbns_root/integration/swtpm/run-recovery-policy-live.sh" read "$case_swtpm" "$nv_before_runtime" >/dev/null || fail
    python3 "$script_dir/recovery-live-driver.py" \
        --case-root "$case_root" --case "$case_name" --phase recovery \
        --code "$case_code" --variables "$case_vars" --esp "$case_esp" --swtpm-state "$case_swtpm" \
        --disk "$disk" --log "$serial" --pico present || fail
    "$pbns_root/integration/swtpm/pause-swtpm.sh" "$case_swtpm" >/dev/null || fail
    case_swtpm_running=0
    case_swtpm_running=1
    "$pbns_root/integration/swtpm/resume-swtpm.sh" "$case_swtpm" >/dev/null || fail
    "$pbns_root/integration/swtpm/run-recovery-policy-live.sh" read "$case_swtpm" "$nv_after_runtime" >/dev/null || fail
    publish_nv_evidence "$nv_before_runtime" "$nv_before"
    publish_nv_evidence "$nv_after_runtime" "$nv_after"
    hash_disk "$disk" "$disk_after"
    python3 "$script_dir/verify-recovery-observability.py" \
        --case "$case_name" --serial "$serial" --nv-before "$nv_before" --nv-after "$nv_after" \
        --disk-before "$disk_before" --disk-after "$disk_after" --case-root "$case_root" \
        --expected-size "$artifact_size" --current-version 5 --target-version "$target_version" >/dev/null || fail
    terminate_gateway || fail
    "$pbns_root/integration/swtpm/stop-swtpm.sh" "$case_swtpm" >/dev/null || fail
    case_swtpm_running=0
    rm -rf -- "$private_dir"
    private_dir=
    python3 "$script_dir/recovery-matrix-evidence.py" case --case "$case_name" --case-root "$case_root" \
        --serial "$serial" --nv-before "$nv_before" --nv-after "$nv_after" \
        --disk-before "$disk_before" --disk-after "$disk_after" \
        --artifact-metadata "$case_root/artifact-publication.json" --artifact "$artifact_input" >/dev/null || fail
    printf '[PASS] %s\n' "$case_name"
}

run_production_failure_case unsigned-untrusted 7 6 target-7.cbor unsigned
run_production_failure_case truncated 7 6 target-7.cbor truncated
run_production_failure_case forged-manifest 7 6 target-7.cbor forged-manifest
run_production_failure_case downgrade 5 5 downgrade-5.cbor downgrade
# Evaluation faults are deliberately isolated from the production gateway.  Each
# invocation has one closed evaluation prefix and then the complete unmodified
# production gateway suffix after its sole -- separator.
verify_gateway_command_identity() {
    [[ -n ${gateway_pid:-} && -n ${gateway_executable:-} && -n ${gateway_start:-} ]] || return 1
    python3 - "$gateway_pid" "$gateway_executable" "$gateway_start" "${gateway_command[@]}" <<'PY'
import pathlib
import sys
pid, executable, start, *command = sys.argv[1:]
try:
    if pathlib.Path(f"/proc/{pid}/exe").resolve(strict=True) != pathlib.Path(executable).resolve(strict=True):
        raise ValueError
    encoded = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
    actual_start = encoded.rsplit(b") ", 1)[1].split()[19].decode("ascii")
    argv = [value.decode("utf-8") for value in pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]]
    if actual_start != start or argv != command:
        raise ValueError
except (OSError, UnicodeDecodeError, IndexError, ValueError):
    raise SystemExit(1)
PY
}

start_evaluation_gateway() {
    local case_name=$1 fault=$2 events=$3
    [[ -n ${case_root:-} && -n ${private_dir:-} && -n ${gateway_log:-} ]] || fail
    [[ ! -e $events && ! -L $events && -x $private_dir/pbns-recovery-eval-gateway ]] || fail
    gateway_expected_executable=$(readlink -f "$private_dir/pbns-recovery-eval-gateway") || fail
    gateway_command=(
        "$gateway_expected_executable" --case "$case_name" --fault "$fault" --events "$events" --
        "${gateway_suffix[@]}"
    )
    (
        ulimit -f "$output_limit_kib"
        exec "${gateway_command[@]}"
    ) >>"$gateway_log" 2>&1 &
    gateway_pid=$!
    gateway_ready=0
    for _ in $(seq 1 40); do
        child_stopped "$gateway_pid" && fail
        if [[ $(readlink -f "/proc/$gateway_pid/exe" 2>/dev/null) == "$gateway_expected_executable" ]]; then
            candidate_gateway_start=$(process_start_time "$gateway_pid") || continue
            gateway_executable=$gateway_expected_executable
            gateway_start=$candidate_gateway_start
            if verify_gateway_command_identity; then
                gateway_ready=$((1))
                break
            fi
        fi
        sleep 0.05
    done
    [[ $gateway_ready -eq 1 ]] || fail
}

# A successful Sink.Record fsyncs one JSON line before this predicate can become
# true.  The stable double read plus a local fsync makes the termination boundary
# explicit; no protocol ERROR is accepted as an interruption substitute.
wait_evaluation_barrier() {
    local events=$1 case_name=$2 fault=$3 final_sequence=$4 final_outcome=$5
    python3 - "$events" "$case_name" "$fault" "$final_sequence" "$final_outcome" <<'PY'
import json
import os
import pathlib
import stat
import sys
import time
path = pathlib.Path(sys.argv[1])
case, fault, last, outcome = sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
deadline = time.monotonic() + 90
expected = [
    {"schema":"pbns-recovery-evaluation-v1", "case":case, "connection":1,
     "operation":"manifest", "frame":"RESPONSE", "sequence":0, "next":0,
     "window":0, "fault":fault, "outcome":"sent"},
]
for sequence in range(last + 1):
    expected.append({"schema":"pbns-recovery-evaluation-v1", "case":case, "connection":2,
                     "operation":"artifact", "frame":"DATA", "sequence":sequence,
                     "next":0, "window":0, "fault":fault,
                     "outcome":outcome if sequence == last else "sent"})
while time.monotonic() < deadline:
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or
                not 0 < info.st_size <= 1024 * 1024):
            raise ValueError
        first = path.read_bytes()
        middle = path.stat()
        second = path.read_bytes()
        after = path.stat()
        if first != second or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (middle.st_dev, middle.st_ino, middle.st_size, middle.st_mtime_ns, middle.st_ctime_ns) or (middle.st_dev, middle.st_ino, middle.st_size, middle.st_mtime_ns, middle.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError
        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError
                value[key] = item
            return value
        records = [json.loads(line, object_pairs_hook=unique_object) for line in first.decode("utf-8").splitlines()]
        if records == expected:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise SystemExit(0)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        pass
    time.sleep(0.05)
raise SystemExit(1)
PY
}

start_evaluation_driver() {
    local case_name=$1 serial_path=$2
    [[ ! -e $serial_path && ! -L $serial_path ]] || fail
    python3 "$script_dir/recovery-live-driver.py" \
        --case-root "$case_root" --case "$case_name" --phase recovery \
        --code "$case_code" --variables "$case_vars" --esp "$case_esp" \
        --swtpm-state "$case_swtpm" --disk "$disk" --log "$serial_path" \
        --pico present &
    driver_pid=$!
    driver_executable=$(readlink -f "$(command -v python3)") || fail
    for _ in $(seq 1 20); do
        child_stopped "$driver_pid" && fail
        if [[ $(readlink -f "/proc/$driver_pid/exe" 2>/dev/null) == "$driver_executable" ]]; then
            driver_start=$(process_start_time "$driver_pid") || continue
            [[ -n $driver_start ]] && return 0
        fi
        sleep 0.05
    done
    fail
}

wait_evaluation_driver() {
    local pid=$driver_pid
    [[ -n $pid && -n $driver_executable && -n $driver_start ]] || fail
    # A direct child that is already gone or zombie is safe to reap without
    # consulting /proc/exe (which disappears for a reaped process).  A live
    # child must still match the executable and start-time captured at launch.
    if ! child_stopped "$pid"; then
        if ! python3 - "$pid" "$driver_executable" "$driver_start" <<'PY'
import pathlib
import sys
try:
    pid, executable, start = sys.argv[1:]
    if pathlib.Path(f"/proc/{pid}/exe").resolve(strict=True) != pathlib.Path(executable).resolve(strict=True):
        raise ValueError
    encoded = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
    if encoded.rsplit(b") ", 1)[1].split()[19].decode("ascii") != start:
        raise ValueError
except (OSError, IndexError, UnicodeDecodeError, ValueError):
    raise SystemExit(1)
PY
        then
            # It may have exited between child_stopped and the identity read;
            # in that case it remains our direct child and wait is the safe
            # race-free operation.  A still-live unverifiable process fails.
            child_stopped "$pid" || fail
        fi
    fi
    wait "$pid" || fail
    driver_pid=
    driver_executable=
    driver_start=
}

run_evaluation_fault_case() {
    local case_name=$1 fault=$2
    local artifact_digest published_size not_before not_after events events_restart serial_restart
    clone_coupled_base "$case_name"
    case_code="$case_root/OVMF_CODE.fd"
    case_vars="$case_root/OVMF_VARS.fd"
    case_esp="$case_root/esp-template"
    case_swtpm="$case_root/swtpm-state"
    case_database="$case_root/gateway.db"
    disk="$case_root/disk.raw"
    serial="$case_root/serial.log"
    nv_before="$case_root/nv-before.bin"
    nv_after="$case_root/nv-after.bin"
    nv_before_runtime="$case_swtpm/nv-before.bin"
    nv_after_runtime="$case_swtpm/nv-after.bin"
    disk_before="$case_root/disk-before.sha256"
    disk_after="$case_root/disk-after.sha256"
    private_dir="$case_root/private"
    repository="$case_root/repository"
    gateway_log="$case_root/gateway.log"
    artifact_input="$case_root/artifact.efi"
    events="$case_root/events.jsonl"
    events_restart="$case_root/events-restart.jsonl"
    serial_restart="$case_root/serial-restart.log"
    mkdir -m 0700 "$private_dir"
    printf '%s\r\n' '@echo -off' 'fs0:\EFI\PBNS\PBNSRecovery.efi' >"$case_esp/startup.nsh"
    chmod 0600 "$case_esp/startup.nsh"
    truncate -s 67108864 "$disk"
    chmod 0600 "$disk"
    hash_disk "$disk" "$disk_before"
    install -m 0600 "$signed_uki" "$artifact_input"
    artifact_size=$(stat -c %s "$artifact_input")
    [[ $artifact_size -eq 26553920 ]] || fail

    install -m 0600 "$pbns_root/tests/fixtures/keys/tls-gateway-test-key.pem" "$private_dir/tls-key.pem"
    install -m 0600 "$pbns_root/tests/fixtures/keys/service-signing-test-private.pem" "$private_dir/time-source.pem"
    openssl ec -in "$private_dir/time-source.pem" -out "$private_dir/time-signing.pem" >/dev/null 2>&1 || fail
    install -m 0600 "$pbns_root/tests/fixtures/keys/recovery-manifest-test-private.pem" "$private_dir/manifest-source.pem"
    openssl ec -in "$private_dir/manifest-source.pem" -out "$private_dir/manifest-signing.pem" >/dev/null 2>&1 || fail
    install -m 0600 "$pbns_root/tests/fixtures/keys/recovery-policy-test-public.pem" "$private_dir/policy-public.pem"
    install -m 0600 "$uki_test_cert" "$private_dir/secureboot-public.pem"
    chmod 0600 "$private_dir/time-signing.pem" "$private_dir/manifest-signing.pem"
    python3 - "$PBNS_GATEWAY_SERVER_NAME" "$private_dir/server.ext" <<'PY' || fail
import ipaddress
import pathlib
import sys
name = sys.argv[1]
try:
    san = f"IP:{ipaddress.ip_address(name).compressed}"
except ValueError:
    if not name or any(not item for item in name.split(".")):
        raise SystemExit(1)
    san = f"DNS:{name}"
pathlib.Path(sys.argv[2]).write_text(
    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
    "extendedKeyUsage=serverAuth\nsubjectAltName=" + san + "\n", encoding="ascii")
PY
    chmod 0600 "$private_dir/server.ext"
    openssl req -new -key "$private_dir/tls-key.pem" -subj '/CN=pbns-gateway.test' -out "$private_dir/gateway.csr" >/dev/null 2>&1 || fail
    openssl x509 -req -in "$private_dir/gateway.csr" -signkey "$private_dir/tls-key.pem" -sha256 -days 3650 -set_serial 0x50424e5302 -extfile "$private_dir/server.ext" -out "$private_dir/tls-cert.pem" >/dev/null 2>&1 || fail
    chmod 0600 "$private_dir/gateway.csr" "$private_dir/tls-cert.pem"
    python3 "$pbns_root/integration/tls/verify-spki.py" "$private_dir/tls-cert.pem" "$pbns_root/tests/fixtures/keys/tls-gateway-test-spki.sha256" >/dev/null || fail
    (
        cd -- "$pbns_root/gateway"
        go build -trimpath -o "$private_dir/pbns-recovery-eval-gateway" ./cmd/pbns-recovery-eval-gateway
        go build -trimpath -o "$private_dir/pbnsctl" ./cmd/pbnsctl
    ) || fail
    chmod 0700 "$private_dir/pbns-recovery-eval-gateway" "$private_dir/pbnsctl"
    "$private_dir/pbnsctl" --db "$case_database" hosts list | grep -Fqx 'hosts=1' || fail
    read -r not_before not_after < <(python3 - <<'PY'
import datetime
now = datetime.datetime.now(datetime.UTC)
print((now - datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
      (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)
    "$private_dir/pbnsctl" recovery publish \
        --artifact "$artifact_input" --repository "$repository" \
        --request-id 00112233445566778899aabbccddeeff \
        --host-binding 102132435465768798a9bacbdcedfe0f00112233445566778899aabbccddeeff \
        --nonce ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 \
        --not-before "$not_before" --not-after "$not_after" --version 7 --minimum-version 6 \
        --policy-authorization "$case_swtpm/recovery-policy/target-7.cbor" \
        --policy-key-id recovery-policy-key-1 --manifest-private-key "$private_dir/manifest-signing.pem" \
        --manifest-key-id recovery-manifest-key-1 --secureboot-public-key "$private_dir/secureboot-public.pem" \
        --output "$private_dir/offline-manifest.cbor" >"$private_dir/publication.json" || fail
    chmod 0600 "$private_dir/offline-manifest.cbor" "$private_dir/publication.json"
    read -r artifact_digest published_size < <(python3 - "$private_dir/publication.json" "$case_root/artifact-publication.json" <<'PY'
import json
import os
import pathlib
import re
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
digest, size, version = value.get("artifact_sha256"), value.get("artifact_size"), value.get("version")
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None or not isinstance(size, int) or size <= 0 or version != 7:
    raise SystemExit(1)
encoded = json.dumps({"artifact_sha256": digest, "artifact_size": size, "version": version}, sort_keys=True).encode("ascii") + b"\n"
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, encoded)
    os.fsync(fd)
finally:
    os.close(fd)
print(digest, size)
PY
) || fail
    [[ $artifact_digest == "$expected_uki_sha256" && $published_size -eq $artifact_size ]] || fail
    (set -o noclobber; : >"$gateway_log") || fail
    chmod 0600 "$gateway_log"
    gateway_suffix=(
        --listen 0.0.0.0:8443 --tls-cert "$private_dir/tls-cert.pem" --tls-key "$private_dir/tls-key.pem"
        --handshake-timeout 15s --read-timeout 60s --write-timeout 60s
        --enrollment-store "$case_database" --time-signing-key "$private_dir/time-signing.pem"
        --time-signing-kid time-key-1 --time-uncertainty 250ms --time-quality qemu-gateway-synchronized
        --recovery-repository "$repository" --recovery-artifact-sha256 "$artifact_digest"
        --recovery-target-version 7 --recovery-minimum-version 6
        --recovery-policy-authorization "$case_swtpm/recovery-policy/target-7.cbor"
        --recovery-policy-public-key "$private_dir/policy-public.pem" --recovery-policy-kid recovery-policy-key-1
        --recovery-manifest-signing-key "$private_dir/manifest-signing.pem" --recovery-manifest-signing-kid recovery-manifest-key-1
        --recovery-secureboot-public-key "$private_dir/secureboot-public.pem"
        --recovery-validity-lead 2m --recovery-validity-trailing 2m --recovery-transfer-timeout 45m
    )

    case_swtpm_running=1
    "$pbns_root/integration/swtpm/resume-swtpm.sh" "$case_swtpm" >/dev/null || fail
    "$pbns_root/integration/swtpm/run-recovery-policy-live.sh" read "$case_swtpm" "$nv_before_runtime" >/dev/null || fail
    start_evaluation_gateway "$case_name" "$fault" "$events"
    if [[ $case_name == gateway-interruption ]]; then
        start_evaluation_driver "$case_name" "$serial"
        wait_evaluation_barrier "$events" "$case_name" "$fault" 7 interrupt-ready || fail
        # TERM is sent only after the exact, synced DATA0..7 barrier and after
        # exe/start/cmdline identity verification in terminate_gateway.
        terminate_gateway || fail
        wait_evaluation_driver
        start_evaluation_gateway "$case_name" "$fault" "$events_restart"
        start_evaluation_driver "$case_name" "$serial_restart"
        wait_evaluation_barrier "$events_restart" "$case_name" "$fault" 0 sent || fail
        terminate_gateway || fail
        wait_evaluation_driver
    else
        python3 "$script_dir/recovery-live-driver.py" \
            --case-root "$case_root" --case "$case_name" --phase recovery \
            --code "$case_code" --variables "$case_vars" --esp "$case_esp" \
            --swtpm-state "$case_swtpm" --disk "$disk" --log "$serial" --pico present || fail
        terminate_gateway || fail
    fi
    "$pbns_root/integration/swtpm/pause-swtpm.sh" "$case_swtpm" >/dev/null || fail
    case_swtpm_running=0
    case_swtpm_running=1
    "$pbns_root/integration/swtpm/resume-swtpm.sh" "$case_swtpm" >/dev/null || fail
    "$pbns_root/integration/swtpm/run-recovery-policy-live.sh" read "$case_swtpm" "$nv_after_runtime" >/dev/null || fail
    publish_nv_evidence "$nv_before_runtime" "$nv_before"
    publish_nv_evidence "$nv_after_runtime" "$nv_after"
    hash_disk "$disk" "$disk_after"
    "$pbns_root/integration/swtpm/stop-swtpm.sh" "$case_swtpm" >/dev/null || fail
    case_swtpm_running=0
    rm -rf -- "$private_dir"
    private_dir=
    evidence_args=(case --case "$case_name" --case-root "$case_root" --serial "$serial"
        --nv-before "$nv_before" --nv-after "$nv_after" --disk-before "$disk_before" --disk-after "$disk_after"
        --artifact-metadata "$case_root/artifact-publication.json" --artifact "$artifact_input" --events "$events")
    if [[ $case_name == gateway-interruption ]]; then
        evidence_args+=(--events-restart "$events_restart" --serial-restart "$serial_restart")
    fi
    python3 "$script_dir/recovery-matrix-evidence.py" "${evidence_args[@]}" >/dev/null || fail
    printf '[PASS] %s\n' "$case_name"
}

run_evaluation_fault_case forged-digest artifact-digest-mismatch
run_evaluation_fault_case forged-chunk chunk-sequence
run_evaluation_fault_case gateway-interruption interrupt-after-data-7
for name in normal-launcher pico-absent; do
    printf '[NOT-RUN] %s\n' "$name"
done
printf '%s\n' 'RECOVERY MATRIX BLOCKED'
exit 1
