#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
    printf 'usage: %s STATE_DIR\n' "$0" >&2
    exit 2
fi
if [[ -z ${PBNS_EDK2_DIR:-} || -z ${PBNS_GATEWAY_SERVER_NAME:-} ||
      $PBNS_EDK2_DIR != /* ]]; then
    printf 'absolute PBNS_EDK2_DIR and PBNS_GATEWAY_SERVER_NAME are required\n' >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
state_root="$pbns_root/integration/state/"
state_arg=$1
if [[ ! -d $state_arg || -L $state_arg ]]; then
    printf 'state must be a non-symlink directory\n' >&2
    exit 1
fi
state_dir=$(cd -- "$state_arg" && pwd -P)
PBNS_EDK2_DIR=$(cd -- "$PBNS_EDK2_DIR" && pwd -P)
if [[ $state_dir != "$state_root"* || $(stat -c %u "$state_dir") -ne $EUID ||
      $(stat -c %a "$state_dir") != 700 ]]; then
    printf 'state below integration/state/ must be owned and use mode 0700\n' >&2
    exit 1
fi
vars_source="$state_dir/OVMF_VARS.secboot.fd"
base="$state_dir/recovery-base"
if [[ ! -f $vars_source || -L $vars_source ||
      $(stat -c %a "$vars_source") != 600 || -e $base || -L $base ]]; then
    printf 'exact copied Secure Boot variables or fresh recovery-base is absent\n' >&2
    exit 1
fi

for tool in cp find go install ip openssl python3 qemu-system-x86_64 \
            sbsign sbverify sha256sum sync swtpm tpm2_getcap; do
    command -v "$tool" >/dev/null
 done
if ! qemu-system-x86_64 -device help 2>/dev/null | grep -Fq 'name "usb-host"'; then
    printf 'QEMU lacks usb-host support\n' >&2
    exit 1
fi
python3 - "$PBNS_GATEWAY_SERVER_NAME" <<'PY'
import ipaddress
import json
import socket
import subprocess
import sys
name = sys.argv[1]
try:
    address = ipaddress.ip_address(name).compressed
except ValueError:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    }
else:
    addresses = {address}
local = {
    info["local"]
    for interface in json.loads(
        subprocess.check_output(["ip", "-j", "-4", "address"], text=True)
    )
    for info in interface.get("addr_info", [])
}
if not addresses or addresses.isdisjoint(local):
    raise SystemExit("frozen gateway SAN is not assigned locally")
PY
verify_pico() {
    python3 - <<'PY'
import pathlib
matches = []
for device in pathlib.Path("/sys/bus/usb/devices").glob("*"):
    try:
        vendor = (device / "idVendor").read_text().strip().lower()
        product = (device / "idProduct").read_text().strip().lower()
        if (vendor, product) != ("cafe", "4011"):
            continue
        matches.append(
            ((device / "serial").read_text().strip(),
             (device / "product").read_text().strip())
        )
    except OSError:
        continue
if matches != [("E66130100F527A26", "PBNS Proxy v1")]:
    raise SystemExit("exact PBNS proxy identity is not present")
PY
}
verify_pico

release_root="$PBNS_EDK2_DIR/Build/PbnsPkg/RELEASE_GCC/X64"
ovmf_code_source=/usr/share/edk2/OvmfX64/OVMF_CODE.secboot.fd
shell_source=/usr/share/edk2/OvmfX64/Shell.efi
secureboot_cert="$pbns_root/tests/fixtures/keys/uki-secureboot-test-cert.pem"
secureboot_key="$pbns_root/tests/fixtures/keys/uki-secureboot-test-key.pem"
for source in \
    "$release_root/PbnsEnroll.efi" \
    "$release_root/PbnsTimeLive.efi" \
    "$release_root/PBNSRecovery.efi" \
    "$release_root/PBNSLauncher.efi" \
    "$release_root/PbnsBootSetup.efi" \
    "$release_root/ReturnSuccess.efi" \
    "$shell_source" "$ovmf_code_source" "$secureboot_cert" "$secureboot_key"; do
    if [[ ! -f $source || -L $source ]]; then
        printf 'missing signed recovery prerequisite\n' >&2
        exit 1
    fi
done

work_dir=$(mktemp -d "$state_dir/.recovery-live-work.XXXXXX")
chmod 0700 "$work_dir"
private="$work_dir/private"
tls="$work_dir/tls"
esp="$work_dir/esp-template"
swtpm_state="$work_dir/swtpm-state"
database="$work_dir/gateway.db"
gateway_log="$work_dir/gateway.log"
enrollment_log="$work_dir/enrollment.log"
time_log="$work_dir/time.log"
gateway_binary="$work_dir/pbns-gateway"
pbnsctl_binary="$work_dir/pbnsctl"
gateway_pid=
gateway_executable=
gateway_start=
swtpm_running=0
output_limit_kib=65536
base_tmp="$state_dir/.recovery-base.tmp.$$"
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
stop_gateway() {
    local pid=${gateway_pid:-}
    [[ -n $pid ]] || return 0
    if ! child_stopped "$pid"; then
        if [[ -z $gateway_executable || -z $gateway_start ]]; then
            gateway_executable=$(readlink -f "/proc/$pid/exe") || return 1
            gateway_start=$(process_start_time "$pid") || return 1
        fi
        python3 "$script_dir/terminate-child-process.py" \
            "$pid" "$gateway_executable" "$gateway_start" || return 1
    fi
    wait "$pid" 2>/dev/null || true
    gateway_pid=
    gateway_executable=
    gateway_start=
}
cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [[ -n ${token-} ]]; then
        token=$(printf '%043d' 0)
    fi
    if [[ -n ${raw_token_output-} ]]; then
        raw_token_output=$(printf '%043d' 0)
    fi
    unset token raw_token_output host_output || true
    if ! stop_gateway >/dev/null 2>&1; then
        status=1
    fi
    if [[ $swtpm_running -eq 1 && -d $swtpm_state ]]; then
        "$pbns_root/integration/swtpm/stop-swtpm.sh" "$swtpm_state" \
            >/dev/null 2>&1 || true
    fi
    rm -rf -- "$private" "$base_tmp" "$work_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 "$private" "$tls" "$esp" "$esp/EFI" \
    "$esp/EFI/BOOT" "$esp/EFI/PBNS"
install -m 0600 "$ovmf_code_source" "$work_dir/OVMF_CODE.fd"
install -m 0600 "$vars_source" "$work_dir/OVMF_VARS.fd"
install -m 0600 "$secureboot_key" "$private/uki.key"

sign_efi() {
    source=$1
    destination=$2
    temporary="$destination.tmp"
    if [[ -e $destination || -L $destination || -e $temporary || -L $temporary ]]; then
        printf 'signed EFI destination already exists\n' >&2
        exit 1
    fi
    sbsign --key "$private/uki.key" --cert "$secureboot_cert" \
        --output "$temporary" "$source" >/dev/null
    chmod 0600 "$temporary"
    signature_list=$(sbverify --list "$temporary" 2>&1)
    if [[ $(grep -Ec '^signature [0-9]+$' <<<"$signature_list") -ne 1 ]]; then
        printf 'signed EFI prerequisite has an unexpected signature inventory\n' >&2
        exit 1
    fi
    mv -T -- "$temporary" "$destination"
}

sign_efi "$shell_source" "$esp/EFI/BOOT/BOOTX64.EFI"
sign_efi "$release_root/PbnsEnroll.efi" "$esp/EFI/PBNS/PbnsEnroll.efi"
sign_efi "$release_root/PbnsTimeLive.efi" "$esp/EFI/PBNS/PbnsTimeLive.efi"
sign_efi "$release_root/PBNSRecovery.efi" "$esp/EFI/PBNS/PBNSRecovery.efi"
sign_efi "$release_root/PBNSLauncher.efi" "$esp/EFI/PBNS/PBNSLauncher.efi"
sign_efi "$release_root/PbnsBootSetup.efi" "$esp/EFI/PBNS/PbnsBootSetup.efi"
sign_efi "$release_root/ReturnSuccess.efi" "$esp/EFI/PBNS/PBNSNormal.efi"
sign_efi "$shell_source" "$esp/EFI/PBNS/Shell.efi"

install -m 0600 "$pbns_root/tests/fixtures/keys/tls-gateway-test-key.pem" \
    "$private/tls-key.pem"
install -m 0600 \
    "$pbns_root/tests/fixtures/keys/enrollment-recipient-test-private.pem" \
    "$private/enrollment-recipient.pem"
install -m 0600 \
    "$pbns_root/tests/fixtures/keys/enrollment-signing-test-private.pem" \
    "$private/enrollment-signing.pem"
install -m 0600 "$pbns_root/tests/fixtures/keys/service-signing-test-private.pem" \
    "$private/time-signing-source.pem"
openssl ec -in "$private/time-signing-source.pem" \
    -out "$private/time-signing.pem" >/dev/null 2>&1
chmod 0600 "$private/time-signing.pem"
tls_cert="$tls/gateway-reissued-cert.pem"
python3 - "$PBNS_GATEWAY_SERVER_NAME" "$tls/server.ext" <<'PY'
import ipaddress
import pathlib
import re
import sys
name = sys.argv[1]
try:
    address = ipaddress.ip_address(name)
except ValueError:
    label = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    if not name or len(name) > 253 or any(
        label.fullmatch(item) is None for item in name.split(".")
    ):
        raise SystemExit("invalid frozen gateway DNS name")
    san = f"DNS:{name}"
else:
    san = f"IP:{address.compressed}"
pathlib.Path(sys.argv[2]).write_text(
    "basicConstraints=critical,CA:FALSE\n"
    "keyUsage=critical,digitalSignature\n"
    "extendedKeyUsage=serverAuth\n"
    f"subjectAltName={san}\n",
    encoding="ascii",
)
PY
chmod 0600 "$tls/server.ext"
openssl req -new -key "$private/tls-key.pem" -subj '/CN=pbns-gateway.test' \
    -out "$tls/gateway.csr"
openssl x509 -req -in "$tls/gateway.csr" -signkey "$private/tls-key.pem" \
    -sha256 -days 3650 -set_serial 0x50424e5302 -extfile "$tls/server.ext" \
    -out "$tls_cert"
chmod 0600 "$tls_cert" "$tls/gateway.csr"
"$pbns_root/integration/tls/verify-spki.py" "$tls_cert" \
    "$pbns_root/tests/fixtures/keys/tls-gateway-test-spki.sha256" \
    >"$work_dir/tls-spki.log"
if [[ $PBNS_GATEWAY_SERVER_NAME =~ ^[0-9a-fA-F:.]+$ ]]; then
    openssl x509 -in "$tls_cert" -noout \
        -checkip "$PBNS_GATEWAY_SERVER_NAME" >/dev/null
else
    openssl x509 -in "$tls_cert" -noout \
        -checkhost "$PBNS_GATEWAY_SERVER_NAME" >/dev/null
fi
(
    cd -- "$pbns_root/gateway"
    go build -trimpath -o "$gateway_binary" ./cmd/pbns-gateway
    go build -trimpath -o "$pbnsctl_binary" ./cmd/pbnsctl
)
chmod 0700 "$gateway_binary" "$pbnsctl_binary"
(set -o noclobber; : >"$gateway_log")
chmod 0600 "$gateway_log"

start_gateway() {
    if [[ -n $gateway_pid ]]; then
        printf 'gateway is already running\n' >&2
        exit 1
    fi
    (
        ulimit -f "$output_limit_kib"
        exec "$gateway_binary" \
            --listen 0.0.0.0:8443 \
            --tls-cert "$tls_cert" \
            --tls-key "$private/tls-key.pem" \
            --handshake-timeout 15s \
            --read-timeout 60s \
            --write-timeout 60s \
            --enrollment-store "$database" \
            --enrollment-recipient-key "$private/enrollment-recipient.pem" \
            --enrollment-recipient-kid enrollment-recipient-1 \
            --enrollment-signing-key "$private/enrollment-signing.pem" \
            --enrollment-signing-kid enrollment-signer-1 \
            --time-signing-key "$private/time-signing.pem" \
            --time-signing-kid time-key-1 \
            --time-uncertainty 250ms \
            --time-quality qemu-gateway-synchronized
    ) >>"$gateway_log" 2>&1 &
    gateway_pid=$!
    expected_gateway_executable=$(readlink -f "$gateway_binary")
    for _ in $(seq 1 20); do
        if child_stopped "$gateway_pid"; then
            printf 'production gateway failed to start\n' >&2
            exit 1
        fi
        if [[ $(readlink -f "/proc/$gateway_pid/exe") == \
              "$expected_gateway_executable" ]]; then
            gateway_executable=$expected_gateway_executable
            gateway_start=$(process_start_time "$gateway_pid")
            break
        fi
        sleep 0.05
    done
    if [[ -z $gateway_executable || -z $gateway_start ]]; then
        printf 'production gateway identity was not established\n' >&2
        exit 1
    fi
}
write_startup() {
    application=$1
    printf '%s\r\n' '@echo -off' "fs0:\\EFI\\PBNS\\$application" \
        >"$esp/startup.nsh"
    chmod 0600 "$esp/startup.nsh"
}

raw_token_output=$("$pbnsctl_binary" --db "$database" enrollment create --ttl 10m)
if [[ $(grep -c '^enrollment_token=' <<<"$raw_token_output") -ne 1 ]]; then
    raw_token_output=$(printf '%043d' 0)
    unset raw_token_output
    printf 'pbnsctl did not emit one enrollment token\n' >&2
    exit 1
fi
token=${raw_token_output#*enrollment_token=}
token=${token%%$'\n'*}
if [[ ${#token} -ne 43 || ! $token =~ ^[A-Za-z0-9_-]{43}$ ]]; then
    token=$(printf '%043d' 0)
    raw_token_output=$token
    unset token raw_token_output
    printf 'pbnsctl enrollment token is not 256-bit base64url\n' >&2
    exit 1
fi
raw_token_output=$(printf '%043d' 0)
unset raw_token_output
if [[ ! -f $database || -L $database || $(stat -c %a "$database") != 600 ]]; then
    token=$(printf '%043d' 0)
    unset token
    printf 'private gateway database was not created\n' >&2
    exit 1
fi

start_gateway
"$pbns_root/integration/swtpm/start-swtpm.sh" "$swtpm_state" \
    >"$work_dir/swtpm-start.log"
swtpm_running=1
write_startup PbnsEnroll.efi
verify_pico
printf '%s\n' "$token" | python3 "$script_dir/enrollment-time-driver.py" \
    --phase enrollment --mode t \
    --code "$work_dir/OVMF_CODE.fd" \
    --variables "$work_dir/OVMF_VARS.fd" \
    --esp "$esp" \
    --swtpm-control "$(<"$swtpm_state/socket.path").ctrl" \
    --log "$enrollment_log"
if grep -Fq -- "$token" "$enrollment_log" "$gateway_log"; then
    token=$(printf '%043d' 0)
    unset token
    printf 'enrollment token reached retained output\n' >&2
    exit 1
fi
token=$(printf '%043d' 0)
unset token
if ! grep -Fq 'PBNS ENROLL TPM CHECKPOINT PASS' "$enrollment_log"; then
    printf 'mode-T enrollment checkpoint is absent\n' >&2
    exit 1
fi

stop_gateway
"$pbns_root/integration/swtpm/pause-swtpm.sh" "$swtpm_state" \
    >"$work_dir/swtpm-pause-after-enrollment.log"
swtpm_running=0
swtpm_running=1
"$pbns_root/integration/swtpm/resume-swtpm.sh" "$swtpm_state" \
    >"$work_dir/swtpm-resume-for-time.log"
start_gateway
write_startup PbnsTimeLive.efi
verify_pico
python3 "$script_dir/enrollment-time-driver.py" \
    --phase time --mode t \
    --code "$work_dir/OVMF_CODE.fd" \
    --variables "$work_dir/OVMF_VARS.fd" \
    --esp "$esp" \
    --swtpm-control "$(<"$swtpm_state/socket.path").ctrl" \
    --log "$time_log"
if ! grep -Fq 'PBNS TIME LIVE INTERVAL PASS' "$time_log" ||
   ! grep -Fq 'PBNS TIME LIVE REPLAY REJECT PASS' "$time_log"; then
    printf 'trusted-time reopen checkpoint is absent\n' >&2
    exit 1
fi
stop_gateway
"$pbns_root/integration/swtpm/pause-swtpm.sh" "$swtpm_state" \
    >"$work_dir/swtpm-pause-after-time.log"
swtpm_running=0
swtpm_running=1
"$pbns_root/integration/swtpm/resume-swtpm.sh" "$swtpm_state" \
    >"$work_dir/swtpm-resume-for-policy.log"
host_output=$("$pbnsctl_binary" --db "$database" hosts list)
if ! grep -Fqx 'hosts=1' <<<"$host_output"; then
    host_output=
    unset host_output
    printf 'closed enrollment database does not contain one host\n' >&2
    exit 1
fi
host_output=
unset host_output

"$pbns_root/integration/swtpm/run-recovery-policy-live.sh" initialize \
    "$swtpm_state" 5
"$pbns_root/integration/swtpm/run-recovery-policy-live.sh" authorize \
    "$swtpm_state" 5 7 target-7
"$pbns_root/integration/swtpm/run-recovery-policy-live.sh" authorize \
    "$swtpm_state" 4 5 downgrade-5
"$pbns_root/integration/swtpm/run-recovery-policy-live.sh" read \
    "$swtpm_state" "$swtpm_state/current-version.bin"
printf '\x00\x00\x00\x00\x00\x00\x00\x05' >"$work_dir/expected-version.bin"
cmp "$swtpm_state/current-version.bin" "$work_dir/expected-version.bin"
rm -f -- "$swtpm_state/current-version.bin"
"$pbns_root/integration/swtpm/pause-swtpm.sh" "$swtpm_state" \
    >"$work_dir/swtpm-pause-base.log"
swtpm_running=0

for forbidden_state in swtpm.pid process.identity owner.pid runtime.path socket.path \
                       pause.intent; do
    if [[ -e $swtpm_state/$forbidden_state || -L $swtpm_state/$forbidden_state ]]; then
        printf 'paused base retains swtpm runtime metadata\n' >&2
        exit 1
    fi
done
if [[ -n $gateway_pid ]]; then
    printf 'base still has a gateway owner\n' >&2
    exit 1
fi
rm -rf -- "$private" "$tls"
rm -f -- "$gateway_binary" "$pbnsctl_binary" "$gateway_log" \
    "$enrollment_log" "$time_log" "$work_dir"/*.log \
    "$work_dir/expected-version.bin" "$esp/startup.nsh"

mkdir -m 0700 "$base_tmp"
install -m 0600 "$work_dir/OVMF_CODE.fd" "$base_tmp/OVMF_CODE.fd"
install -m 0600 "$work_dir/OVMF_VARS.fd" "$base_tmp/OVMF_VARS.fd"
install -m 0600 "$database" "$base_tmp/gateway.db"
cp -a -- "$esp" "$base_tmp/esp-template"
cp -a -- "$swtpm_state" "$base_tmp/swtpm-state"
find "$base_tmp" -type d -exec chmod 0700 {} +
find "$base_tmp" -type f -exec chmod 0600 {} +
python3 - "$base_tmp" <<'PY'
import os
import pathlib
import stat
import sys
root = pathlib.Path(sys.argv[1])
if {item.name for item in root.iterdir()} != {
    "OVMF_CODE.fd", "OVMF_VARS.fd", "gateway.db", "esp-template", "swtpm-state"
}:
    raise SystemExit("invalid recovery-base inventory")
for path in root.rglob("*"):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit("recovery-base contains a symlink")
    if stat.S_ISDIR(info.st_mode):
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise SystemExit("recovery-base directory mode mismatch")
    elif stat.S_ISREG(info.st_mode):
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise SystemExit("recovery-base files must use mode 0600")
    else:
        raise SystemExit("recovery-base contains a special file")
for name in (
    "private", "swtpm.pid", "process.identity", "owner.pid", "runtime.path", "socket.path",
    "pause.intent",
):
    if any(path.name == name for path in root.rglob("*")):
        raise SystemExit("recovery-base contains runtime or private state")
required = (
    root / "esp-template/EFI/BOOT/BOOTX64.EFI",
    root / "esp-template/EFI/PBNS/PbnsEnroll.efi",
    root / "esp-template/EFI/PBNS/PbnsTimeLive.efi",
    root / "esp-template/EFI/PBNS/PBNSRecovery.efi",
    root / "esp-template/EFI/PBNS/PBNSLauncher.efi",
    root / "esp-template/EFI/PBNS/PbnsBootSetup.efi",
    root / "esp-template/EFI/PBNS/PBNSNormal.efi",
    root / "swtpm-state/managed",
    root / "swtpm-state/paused",
    root / "swtpm-state/recovery-policy/initialization.cbor",
    root / "swtpm-state/recovery-policy/target-7.cbor",
    root / "swtpm-state/recovery-policy/downgrade-5.cbor",
)
if any(not path.is_file() for path in required):
    raise SystemExit("recovery-base is incomplete")
for path in sorted(root.rglob("*"), reverse=True):
    if path.is_file():
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
for path in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
mv -T -- "$base_tmp" "$base"
sync -f "$state_dir"
base_tmp=
printf '%s\n' 'PBNS RECOVERY LIVE BASE PASS mode=T current=5 hosts=1'
