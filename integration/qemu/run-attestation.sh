#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
repo_root=$(cd -- "$pbns_root/.." && pwd -P)
state_root="$pbns_root/integration/state"
current_path="$pbns_root/integration/state/qemu/attestation-passthrough-current.path"
driver="$script_dir/attestation-passthrough-driver.py"
provisioner="$script_dir/provision-swtpm-ek.py"
phase=
evidence_arg=

usage() {
    printf 'usage: %s --evidence-dir ABSOLUTE_DIRECTORY --phase enroll|attest\n' "$0" >&2
    exit 2
}

while (( $# > 0 )); do
    case $1 in
        --evidence-dir)
            (( $# >= 2 )) || usage
            evidence_arg=$2
            shift 2
            ;;
        --phase)
            (( $# >= 2 )) || usage
            phase=$2
            shift 2
            ;;
        *) usage ;;
    esac
done
[[ -n $evidence_arg && ( $phase == enroll || $phase == attest ) ]] || usage
[[ $evidence_arg == /* && $evidence_arg =~ ^/[A-Za-z0-9._/-]+$ ]] || {
    printf '%s\n' 'evidence path must be an absolute safe build path' >&2
    exit 2
}
[[ -d $evidence_arg && ! -L $evidence_arg ]] || {
    printf '%s\n' 'evidence directory must exist and must not be a symlink' >&2
    exit 1
}
evidence_dir=$(cd -- "$evidence_arg" && pwd -P)
[[ $evidence_dir == "$state_root/"* && $(stat -c %u "$evidence_dir") -eq $(id -u) &&
   $(stat -c %a "$evidence_dir") == 700 ]] || {
    printf '%s\n' 'evidence directory must be owned mode 0700 below integration/state' >&2
    exit 1
}
if [[ -L $current_path ]]; then
    printf '%s\n' 'refusing symlink attestation current-path file' >&2
    exit 1
fi
if [[ -e $current_path && ( ! -f $current_path || $(stat -c %u "$current_path") -ne $(id -u) ||
   $(stat -c %a "$current_path") != 600 ) ]]; then
    printf '%s\n' 'attestation current-path file must be an owned mode 0600 regular file' >&2
    exit 1
fi
gateway_pid=
gateway_start_time=

record_attestation_gateway_start() {
    gateway_start_time=$(python3 - "$gateway_pid" <<'PY'
import pathlib
import sys

encoded = pathlib.Path(f"/proc/{int(sys.argv[1])}/stat").read_bytes()
value = encoded.rsplit(b") ", 1)[1].split()[19].decode("ascii")
if not value.isdecimal():
    raise SystemExit("invalid gateway process identity")
print(value)
PY
)
}

require_gateway_address() {
    command -v ip >/dev/null 2>&1 || {
        printf '%s\n' 'missing passthrough checkpoint tool: ip' >&2
        return 1
    }
    ip -4 -o address show | grep -F ' 192.168.1.180/32 ' >/dev/null || {
        printf '%s\n' 'the temporary 192.168.1.180/32 gateway address is not assigned' >&2
        return 1
    }
}

stop_attestation_gateway() {
    if [[ -z $gateway_pid ]]; then
        return 0
    fi
    if kill -0 "$gateway_pid" 2>/dev/null; then
        if ! timeout --signal=KILL 10s python3 \
            "$script_dir/terminate-child-process.py" "$gateway_pid" \
            "$checkpoint_binary" "$gateway_start_time" \
            --term-timeout 5 --kill-timeout 1; then
            printf '%s\n' 'checkpoint gateway did not terminate within the bound' >&2
            return 1
        fi
    fi
    wait "$gateway_pid" 2>/dev/null || true
    gateway_pid=
    gateway_start_time=
}

if [[ $phase == attest ]]; then
    [[ -f $current_path && $(<"$current_path") == "$evidence_dir" ]] || {
        printf '%s\n' 'attestation must use the published enrolled base' >&2
        exit 1
    }
    require_gateway_address
    private_dir="$evidence_dir/private"
    deployment_dir="$private_dir/deployment"
    administrator_dir="$private_dir/administrator"
    enrollment_dir="$private_dir/enrollment"
    generated_dir="$private_dir/generated"
    secure_boot_dir="$private_dir/secure-boot"
    signed_dir="$private_dir/signed"
    esp="$evidence_dir/esp"
    swtpm_state="$evidence_dir/swtpm-state"
    gateway_database="$private_dir/gateway.db"
    gateway_binary="$private_dir/pbns-gateway"
    pbnsctl_binary="$private_dir/pbnsctl"
    checkpoint_binary="$private_dir/pbns-attestation-checkpoint"
    pbns_attest="$pbns_root/.deps/edk2/Build/PbnsPkg/DEBUG_GCC/X64/PbnsAttest.efi"
    ovmf_code="/usr/share/edk2/OvmfX64/OVMF_CODE.secboot.fd"
    candidate="$evidence_dir/candidate.cbor"
    proposal="$evidence_dir/baseline-proposal.cbor"
    approval="$evidence_dir/baseline-approval.cose"
    receipt="$evidence_dir/receipt.cose"
    preflight_log="$evidence_dir/preflight-serial.log"
    attest_log="$evidence_dir/attestation-serial.log"
    [[ ! -e $candidate && ! -e $proposal && ! -e $approval && ! -e $receipt &&
       ! -e $preflight_log && ! -e $attest_log ]] || {
        printf '%s\n' 'attestation checkpoint outputs already exist' >&2
        exit 1
    }
    for artifact in "$gateway_binary" "$pbnsctl_binary" "$deployment_dir/deployment.cbor" \
        "$enrollment_dir/enrollment.cbor" "$generated_dir/PbnsGeneratedDeploymentTrust.h" \
        "$generated_dir/PbnsDeploymentTrustBuild.c" "$generated_dir/PbnsGeneratedEnrollmentTrust.h" \
        "$generated_dir/PbnsEnrollmentTrustBuild.c" "$secure_boot_dir/secure-boot-key.pem" \
        "$secure_boot_dir/secure-boot-cert.pem" "$administrator_dir/administrator-private.pem" \
        "$administrator_dir/administrator-public.pem"; do
        [[ -f $artifact && ! -L $artifact ]] || { printf 'missing enrolled-base artifact: %s\n' "$artifact" >&2; exit 1; }
    done
    swtpm_active=0
    attestation_cleanup() {
        local status=$?
        if ! stop_attestation_gateway; then
            status=1
        fi
        if (( swtpm_active == 1 )); then
            timeout --signal=TERM --kill-after=10s 30s \
                "$pbns_root/integration/swtpm/pause-swtpm.sh" "$swtpm_state" \
                >>"$evidence_dir/swtpm-pause.log" 2>&1 || status=1
        fi
        trap - EXIT
        exit "$status"
    }
    trap attestation_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    timeout --signal=TERM --kill-after=10s 30s "$pbns_root/integration/swtpm/resume-swtpm.sh" "$swtpm_state" >"$evidence_dir/swtpm-resume.log" 2>&1
    swtpm_active=1
    chmod 0600 "$evidence_dir/swtpm-resume.log"
    swtpm_socket=$(<"$swtpm_state/socket.path")
    swtpm_control="$swtpm_socket.ctrl"
    (
        cd -- "$pbns_root/gateway"
        timeout --signal=TERM --kill-after=10s 5m go build -trimpath -o "$checkpoint_binary" ./cmd/pbns-attestation-checkpoint
    ) >"$evidence_dir/checkpoint-build.log" 2>&1
    chmod 0600 "$evidence_dir/checkpoint-build.log"
    chmod 0700 "$checkpoint_binary"
    PBNS_DEPLOYMENT_BUNDLE="$deployment_dir/deployment.cbor" \
    PBNS_ENROLLMENT_BUNDLE="$enrollment_dir/enrollment.cbor" \
    PBNS_UEFI_DEPLOYMENT_TRUST_HEADER="$generated_dir/PbnsGeneratedDeploymentTrust.h" \
    PBNS_UEFI_DEPLOYMENT_TRUST_SOURCE="$generated_dir/PbnsDeploymentTrustBuild.c" \
    PBNS_UEFI_ENROLLMENT_TRUST_HEADER="$generated_dir/PbnsGeneratedEnrollmentTrust.h" \
    PBNS_UEFI_ENROLLMENT_TRUST_SOURCE="$generated_dir/PbnsEnrollmentTrustBuild.c" \
    PBNS_EDK2_DIR="${PBNS_EDK2_DIR:-$pbns_root/.deps/edk2}" \
        timeout --signal=TERM --kill-after=10s 20m "$pbns_root/tools/build-uefi.sh" \
        >"$evidence_dir/attestation-uefi-rebuild.log" 2>&1
    [[ -f $pbns_attest && ! -L $pbns_attest ]] || {
        printf '%s\n' 'fresh PbnsAttest.efi was not produced' >&2
        exit 1
    }
    timeout --signal=TERM --kill-after=10s 2m sbsign \
        --key "$secure_boot_dir/secure-boot-key.pem" \
        --cert "$secure_boot_dir/secure-boot-cert.pem" \
        --output "$signed_dir/PbnsAttest.efi" "$pbns_attest" \
        >"$evidence_dir/attestation-secure-boot-sign.log" 2>&1
    timeout --signal=TERM --kill-after=10s 2m sbverify --cert \
        "$secure_boot_dir/secure-boot-cert.pem" "$signed_dir/PbnsAttest.efi" \
        >>"$evidence_dir/attestation-secure-boot-sign.log" 2>&1
    chmod 0600 "$evidence_dir/attestation-uefi-rebuild.log" \
        "$evidence_dir/attestation-secure-boot-sign.log" "$signed_dir/PbnsAttest.efi"
    install -m 0600 "$signed_dir/PbnsAttest.efi" "$esp/PbnsAttest.efi"
    printf 'fs0:\\PbnsAttest.efi\r\necho PBNS ATTEST EFI RETURN %%lasterror%%\r\nreset -s\r\n' >"$esp/startup.nsh"
    chmod 0600 "$esp/startup.nsh"
    gateway_arguments=(
        --listen 0.0.0.0:8443 --tls-cert "$deployment_dir/tls-cert.pem" --tls-key "$deployment_dir/tls-key.pem"
        --enrollment-store "$gateway_database" --deployment-bundle "$deployment_dir/deployment.cbor"
        --attestation-recipient-key "$deployment_dir/recipient-key.pem" --attestation-recipient-kid pbns-recipient-v1
        --attestation-signing-key "$deployment_dir/challenge-key.pem" --attestation-signing-kid pbns-challenge-v1
        --attestation-receipt-signing-key "$deployment_dir/receipt-key.pem" --attestation-receipt-signing-kid pbns-receipt-v1
        --time-signing-key "$deployment_dir/time-key.pem" --time-signing-kid pbns-time-v1 --time-uncertainty 0s --time-quality checkpoint
    )
    pico_selection=$(python3 "$driver" select-pico)
    [[ $pico_selection =~ ^hostbus=([0-9]+)$'\n'hostaddr=([0-9]+)$ ]] || {
        printf '%s\n' 'Pico selector returned an invalid result' >&2
        exit 1
    }
    hostbus=${BASH_REMATCH[1]}
    hostaddr=${BASH_REMATCH[2]}
    "$checkpoint_binary" --candidate-output "$candidate" -- "${gateway_arguments[@]}" >"$evidence_dir/preflight-gateway.log" 2>&1 &
    gateway_pid=$!
    record_attestation_gateway_start
    for _ in $(seq 1 150); do
        kill -0 "$gateway_pid" 2>/dev/null || { cat "$evidence_dir/preflight-gateway.log" >&2; exit 1; }
        python3 - <<'PY' && break || true
import socket
s = socket.socket(); s.settimeout(0.1)
try: s.connect(('127.0.0.1', 8443))
finally: s.close()
PY
        sleep 0.1
    done
    python3 "$driver" run-attestation --code "$ovmf_code" --variables "$evidence_dir/OVMF_VARS.fd" --esp "$esp" --swtpm-control "$swtpm_control" --hostbus "$hostbus" --hostaddr "$hostaddr" --log "$preflight_log" --timeout 240 --expect-preflight
    stop_attestation_gateway
    [[ -s $candidate ]] || { printf '%s\n' 'trusted preflight did not produce a candidate' >&2; exit 1; }
    chmod 0600 "$candidate" "$preflight_log" "$evidence_dir/preflight-gateway.log"
    host=$(awk -F'[=:]' '/^host_0=/ {print $2}' "$evidence_dir/hosts.txt")
    [[ $host =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'invalid enrolled host fingerprint' >&2; exit 1; }
    admin_id=$(openssl pkey -pubin -in "$administrator_dir/administrator-public.pem" -pubout -outform DER | openssl dgst -sha256 -binary | xxd -p -c 256)
    "$pbnsctl_binary" --db "$gateway_database" baseline propose --host "$host" --baseline "$candidate" --classification security --admin-key-id "$admin_id" --output "$proposal" >"$evidence_dir/baseline-propose.log"
    signature_source=$(mktemp "$pbns_root/gateway/pbns-attestation-sign.XXXXXX.go")
    cat >"$signature_source" <<'GO'
package main
import("crypto/rand";"os";"pbns.local/gateway/internal/baselineupdate";"pbns.local/gateway/internal/keys";"github.com/veraison/go-cose")
func main(){p,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)};v,e:=baselineupdate.DecodeProposal(p);if e!=nil{panic(e)};k,e:=keys.LoadECPrivateKey(os.Args[2]);if e!=nil{panic(e)};m:=cose.NewSign1Message();m.Headers.Protected.SetAlgorithm(cose.AlgorithmES256);m.Headers.Protected[cose.HeaderLabelKeyID]=v.AdminKeyID[:];m.Payload=p;s,e:=cose.NewSigner(cose.AlgorithmES256,k);if e!=nil{panic(e)};if e=m.Sign(rand.Reader,baselineupdate.ApprovalAAD(v),s);e!=nil{panic(e)};o,e:=m.MarshalCBOR();if e!=nil{panic(e)};if e=os.WriteFile(os.Args[3],o,0600);e!=nil{panic(e)}}
GO
    if ! (cd "$pbns_root/gateway" && go run "$signature_source" "$proposal" "$administrator_dir/administrator-private.pem" "$approval"); then
        rm -f -- "$signature_source"
        exit 1
    fi
    rm -f -- "$signature_source"
    "$pbnsctl_binary" --db "$gateway_database" baseline approve --proposal "$proposal" --signature "$approval" --admin-public-key "$administrator_dir/administrator-public.pem" >"$evidence_dir/baseline-approve.log"
    chmod 0600 "$proposal" "$approval" "$evidence_dir/baseline-propose.log" "$evidence_dir/baseline-approve.log"
    "$checkpoint_binary" --receipt-output "$receipt" -- "${gateway_arguments[@]}" >"$evidence_dir/attestation-gateway.log" 2>&1 &
    gateway_pid=$!
    record_attestation_gateway_start
    for _ in $(seq 1 150); do
        kill -0 "$gateway_pid" 2>/dev/null || { cat "$evidence_dir/attestation-gateway.log" >&2; exit 1; }
        python3 - <<'PY' && break || true
import socket
s = socket.socket(); s.settimeout(0.1)
try: s.connect(('127.0.0.1', 8443))
finally: s.close()
PY
        sleep 0.1
    done
    python3 "$driver" run-attestation --code "$ovmf_code" --variables "$evidence_dir/OVMF_VARS.fd" --esp "$esp" --swtpm-control "$swtpm_control" --hostbus "$hostbus" --hostaddr "$hostaddr" --log "$attest_log" --timeout 240
    stop_attestation_gateway
    [[ -s $receipt ]] || { printf '%s\n' 'ordinary gateway did not retain receipt' >&2; exit 1; }
    timeout --signal=TERM --kill-after=10s 30s "$pbns_root/integration/swtpm/pause-swtpm.sh" "$swtpm_state" >"$evidence_dir/swtpm-pause.log" 2>&1
    swtpm_active=0
    trap - EXIT INT TERM
    printf 'PBNS PICO PASSTHROUGH CHECKPOINT PASS evidence=%s\n' "$evidence_dir"
    exit 0
fi
if [[ -n $(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    printf '%s\n' 'enrollment evidence directory must be empty' >&2
    exit 1
fi

ulimit -f 131072
for tool in python3 qemu-system-x86_64 swtpm tpm2_getcap openssl go ip install stat find \
    timeout virt-fw-vars sbsign sbverify; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing passthrough checkpoint tool: %s\n' "$tool" >&2
        exit 1
    }
done
qemu_version=$(qemu-system-x86_64 --version | head -n 1)
[[ $qemu_version == 'QEMU emulator version 10.2.2' ]] || {
    printf '%s\n' 'stock QEMU 10.2.2 is required' >&2
    exit 1
}
require_gateway_address
python3 - <<'PY'
import socket
sock = socket.socket()
try:
    sock.bind(("0.0.0.0", 8443))
except OSError as error:
    raise SystemExit(f"TCP/8443 is already in use: {error}") from error
finally:
    sock.close()
PY

pico_selection=$(python3 "$driver" select-pico)
[[ $pico_selection =~ ^hostbus=([0-9]+)$'\n'hostaddr=([0-9]+)$ ]] || {
    printf '%s\n' 'Pico selector returned an invalid result' >&2
    exit 1
}
hostbus=${BASH_REMATCH[1]}
hostaddr=${BASH_REMATCH[2]}
# O perfil efetivo fica centralizado no driver: q35,accel=tcg, -nic none e usb-host numérico.
printf 'selected exact PBNS Pico hostbus=%s hostaddr=%s\n' "$hostbus" "$hostaddr"

gateway_pid=
gateway_start_time=
swtpm_active=0
enrollment_token=
token_output=
stop_gateway() {
    if [[ -z $gateway_pid ]]; then
        return
    fi
    if kill -0 "$gateway_pid" 2>/dev/null; then
        if ! timeout --signal=KILL 10s python3 \
            "$script_dir/terminate-child-process.py" "$gateway_pid" \
            "$gateway_binary" "$gateway_start_time" \
            --term-timeout 5 --kill-timeout 1; then
            printf '%s\n' 'gateway child did not terminate within the bound' >&2
            return 1
        fi
    fi
    wait "$gateway_pid" 2>/dev/null || true
    gateway_pid=
    gateway_start_time=
}
cleanup() {
    status=$?
    enrollment_token=
    token_output=
    if ! stop_gateway; then
        status=1
    fi
    if (( swtpm_active == 1 )); then
        timeout --signal=TERM --kill-after=10s 30s \
            "$pbns_root/integration/swtpm/pause-swtpm.sh" "$evidence_dir/swtpm-state" \
            >>"$evidence_dir/cleanup.log" 2>&1 || true
    fi
    if (( status != 0 )); then
        printf 'passthrough checkpoint failed; retained private evidence: %s\n' "$evidence_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

private_dir="$evidence_dir/private"
deployment_dir="$private_dir/deployment"
enrollment_dir="$private_dir/enrollment"
generated_dir="$private_dir/generated"
ek_private_dir="$private_dir/ek"
secure_boot_dir="$private_dir/secure-boot"
administrator_dir="$private_dir/administrator"
signed_dir="$private_dir/signed"
esp="$evidence_dir/esp"
swtpm_state="$evidence_dir/swtpm-state"
ovmf_code="/usr/share/edk2/OvmfX64/OVMF_CODE.secboot.fd"
ovmf_vars_template="/usr/share/edk2/OvmfX64/OVMF_VARS.fd"
shell_source="/usr/share/edk2/OvmfX64/Shell.efi"
ovmf_vars="$evidence_dir/OVMF_VARS.fd"
gateway_database="$private_dir/gateway.db"
gateway_binary="$private_dir/pbns-gateway"
pbnsctl_binary="$private_dir/pbnsctl"
serial_log="$evidence_dir/enrollment-serial.log"
checkpoint="$evidence_dir/enrollment-checkpoint.json"

mkdir -m 0700 "$private_dir" "$generated_dir" "$ek_private_dir" \
    "$secure_boot_dir" "$administrator_dir" "$signed_dir" "$esp"
mkdir -m 0700 "$esp/EFI" "$esp/EFI/BOOT"
for artifact in "$ovmf_code" "$ovmf_vars_template" "$shell_source"; do
    [[ -f $artifact && ! -L $artifact ]] || {
        printf 'missing pinned EDK II OVMF artifact: %s\n' "$artifact" >&2
        exit 1
    }
done
timeout --signal=TERM --kill-after=10s 2m openssl req -new -newkey rsa:3072 -nodes -x509 \
    -keyout "$secure_boot_dir/secure-boot-key.pem" \
    -out "$secure_boot_dir/secure-boot-cert.pem" \
    -subj '/CN=PBNS TEST ONLY Recovery Image/' -days 3650 -sha256 \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    >"$evidence_dir/secure-boot-keygen.log" 2>&1
timeout --signal=TERM --kill-after=10s 2m openssl ecparam -name prime256v1 -genkey -noout \
    -out "$administrator_dir/administrator-private.pem" \
    >>"$evidence_dir/secure-boot-keygen.log" 2>&1
timeout --signal=TERM --kill-after=10s 2m openssl pkey \
    -in "$administrator_dir/administrator-private.pem" -pubout \
    -out "$administrator_dir/administrator-public.pem" \
    >>"$evidence_dir/secure-boot-keygen.log" 2>&1
chmod 0600 "$evidence_dir/secure-boot-keygen.log" "$secure_boot_dir"/* "$administrator_dir"/*
timeout --signal=TERM --kill-after=10s 2m virt-fw-vars \
    --input "$ovmf_vars_template" --output "$ovmf_vars" \
    --enroll-cert "$secure_boot_dir/secure-boot-cert.pem" \
    --microsoft-kek none --no-microsoft \
    --add-db a0baa8a3-041d-48a8-bc87-c36d121b5e3d "$secure_boot_dir/secure-boot-cert.pem" \
    --secure-boot >"$evidence_dir/secure-boot-vars.log" 2>&1
chmod 0600 "$ovmf_vars" "$evidence_dir/secure-boot-vars.log"
timeout --signal=TERM --kill-after=10s 2m python3 "$script_dir/verify-secureboot-store.py" \
    --vars "$ovmf_vars" --fixture-cert "$secure_boot_dir/secure-boot-cert.pem" \
    --decoded "$evidence_dir/OVMF_VARS.secboot.txt" --scratch-parent "$private_dir" \
    >>"$evidence_dir/secure-boot-vars.log" 2>&1
chmod 0600 "$evidence_dir/OVMF_VARS.secboot.txt"

(
    cd -- "$pbns_root/gateway"
    timeout --signal=TERM --kill-after=10s 2m go run ./cmd/pbns-deployment generate --out-dir "$deployment_dir" --server-name 192.168.1.180
    timeout --signal=TERM --kill-after=10s 2m go run ./cmd/pbns-deployment generate-enrollment --out-dir "$enrollment_dir"
    timeout --signal=TERM --kill-after=10s 2m go run ./cmd/pbns-deployment render-c \
        --bundle "$deployment_dir/deployment.cbor" \
        --header "$generated_dir/PbnsGeneratedDeploymentTrust.h" \
        --source "$generated_dir/PbnsDeploymentTrustBuild.c"
    timeout --signal=TERM --kill-after=10s 2m go run ./cmd/pbns-deployment render-enrollment-c \
        --bundle "$enrollment_dir/enrollment.cbor" \
        --header "$generated_dir/PbnsGeneratedEnrollmentTrust.h" \
        --source "$generated_dir/PbnsEnrollmentTrustBuild.c"
    timeout --signal=TERM --kill-after=10s 5m go build -trimpath -o "$gateway_binary" ./cmd/pbns-gateway
    timeout --signal=TERM --kill-after=10s 5m go build -trimpath -o "$pbnsctl_binary" ./cmd/pbnsctl
) >"$evidence_dir/trust-and-gateway-build.log" 2>&1
chmod 0600 "$evidence_dir/trust-and-gateway-build.log"
chmod 0700 "$gateway_binary" "$pbnsctl_binary"

PBNS_DEPLOYMENT_BUNDLE="$deployment_dir/deployment.cbor" \
PBNS_ENROLLMENT_BUNDLE="$enrollment_dir/enrollment.cbor" \
PBNS_UEFI_DEPLOYMENT_TRUST_HEADER="$generated_dir/PbnsGeneratedDeploymentTrust.h" \
PBNS_UEFI_DEPLOYMENT_TRUST_SOURCE="$generated_dir/PbnsDeploymentTrustBuild.c" \
PBNS_UEFI_ENROLLMENT_TRUST_HEADER="$generated_dir/PbnsGeneratedEnrollmentTrust.h" \
PBNS_UEFI_ENROLLMENT_TRUST_SOURCE="$generated_dir/PbnsEnrollmentTrustBuild.c" \
PBNS_EDK2_DIR="$pbns_root/.deps/edk2" \
    timeout --signal=TERM --kill-after=10s 20m "$pbns_root/tools/build-uefi.sh" \
    >"$evidence_dir/uefi-build.log" 2>&1
chmod 0600 "$evidence_dir/uefi-build.log"
pbns_enroll="$pbns_root/.deps/edk2/Build/PbnsPkg/DEBUG_GCC/X64/PbnsEnroll.efi"
pbns_attest="$pbns_root/.deps/edk2/Build/PbnsPkg/DEBUG_GCC/X64/PbnsAttest.efi"
for application in "$pbns_enroll" "$pbns_attest"; do
    [[ -f $application && ! -L $application ]] || {
        printf 'fresh UEFI application was not produced: %s\n' "$application" >&2
        exit 1
    }
done
timeout --signal=TERM --kill-after=10s 2m sbsign \
    --key "$secure_boot_dir/secure-boot-key.pem" \
    --cert "$secure_boot_dir/secure-boot-cert.pem" \
    --output "$signed_dir/PbnsEnroll.efi" "$pbns_enroll" \
    >"$evidence_dir/secure-boot-sign.log" 2>&1
timeout --signal=TERM --kill-after=10s 2m sbsign \
    --key "$secure_boot_dir/secure-boot-key.pem" \
    --cert "$secure_boot_dir/secure-boot-cert.pem" \
    --output "$signed_dir/PbnsAttest.efi" "$pbns_attest" \
    >>"$evidence_dir/secure-boot-sign.log" 2>&1
timeout --signal=TERM --kill-after=10s 2m sbsign \
    --key "$secure_boot_dir/secure-boot-key.pem" \
    --cert "$secure_boot_dir/secure-boot-cert.pem" \
    --output "$signed_dir/Shell.efi" "$shell_source" \
    >>"$evidence_dir/secure-boot-sign.log" 2>&1
for application in PbnsEnroll.efi PbnsAttest.efi Shell.efi; do
    timeout --signal=TERM --kill-after=10s 2m sbverify --cert \
        "$secure_boot_dir/secure-boot-cert.pem" "$signed_dir/$application" \
        >>"$evidence_dir/secure-boot-sign.log" 2>&1
done
chmod 0600 "$evidence_dir/secure-boot-sign.log" "$signed_dir"/*
install -m 0600 "$signed_dir/PbnsEnroll.efi" "$esp/PbnsEnroll.efi"
install -m 0600 "$signed_dir/Shell.efi" "$esp/EFI/BOOT/BOOTX64.EFI"
printf 'fs0:\\PbnsEnroll.efi\r\necho PBNS ENROLL EFI RETURN %%lasterror%%\r\nreset -s\r\n' \
    >"$esp/startup.nsh"
chmod 0600 "$esp/startup.nsh"

timeout --signal=TERM --kill-after=10s 30s \
    "$pbns_root/integration/swtpm/start-swtpm.sh" "$swtpm_state" \
    >"$evidence_dir/swtpm-start.log" 2>&1
chmod 0600 "$evidence_dir/swtpm-start.log"
swtpm_active=1
swtpm_socket=$(<"$swtpm_state/socket.path")
swtpm_control="$swtpm_socket.ctrl"
timeout --signal=TERM --kill-after=10s 10m python3 "$provisioner" \
    --tcti "swtpm:path=$swtpm_socket" --private-dir "$ek_private_dir" \
    >"$evidence_dir/swtpm-ek.log" 2>&1
chmod 0600 "$evidence_dir/swtpm-ek.log"
grep -F 'SWTPM EK CERTIFICATE PASS index=0x01c0000a' "$evidence_dir/swtpm-ek.log" >/dev/null

token_output=$(timeout --signal=TERM --kill-after=10s 30s \
    "$pbnsctl_binary" --db "$gateway_database" enrollment create --ttl 15m)
enrollment_token=$(printf '%s\n' "$token_output" | awk -F= '$1 == "enrollment_token" { print substr($0, index($0, "=") + 1) }')
enrollment_id=$(printf '%s\n' "$token_output" | awk -F= '$1 == "enrollment_id" { print $2 }')
[[ $enrollment_token =~ ^[A-Za-z0-9_-]{43}$ && $enrollment_id =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s\n' 'pbnsctl returned an invalid enrollment token record' >&2
    exit 1
}
token_output=
chmod 0600 "$gateway_database"

"$gateway_binary" \
    --listen 0.0.0.0:8443 \
    --tls-cert "$deployment_dir/tls-cert.pem" \
    --tls-key "$deployment_dir/tls-key.pem" \
    --enrollment-store "$gateway_database" \
    --enrollment-bundle "$enrollment_dir/enrollment.cbor" \
    --enrollment-recipient-key "$enrollment_dir/recipient-key.pem" \
    --enrollment-recipient-kid pbns-enrollment-recipient-v1 \
    --enrollment-signing-key "$enrollment_dir/signer-key.pem" \
    --enrollment-signing-kid pbns-enrollment-signer-v1 \
    --ek-roots "$ek_private_dir/manufacturer-root-cert.pem" \
    >"$evidence_dir/gateway.log" 2>&1 &
gateway_pid=$!
gateway_start_time=$(python3 - "$gateway_pid" <<'PY'
import pathlib
import sys

encoded = pathlib.Path(f"/proc/{int(sys.argv[1])}/stat").read_bytes()
value = encoded.rsplit(b") ", 1)[1].split()[19].decode("ascii")
if not value.isdecimal():
    raise SystemExit("invalid gateway process identity")
print(value)
PY
)
chmod 0600 "$evidence_dir/gateway.log"
python3 - "$gateway_pid" <<'PY'
import os
import socket
import sys
import time

pid = int(sys.argv[1])
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except OSError as error:
        raise SystemExit("gateway exited before readiness") from error
    try:
        with socket.create_connection(("127.0.0.1", 8443), timeout=0.2):
            break
    except OSError:
        time.sleep(0.05)
else:
    raise SystemExit("gateway readiness deadline expired")
PY

printf '%s\n' "$enrollment_token" | python3 "$driver" run-enrollment \
    --code "$ovmf_code" \
    --variables "$ovmf_vars" \
    --esp "$esp" \
    --swtpm-control "$swtpm_control" \
    --hostbus "$hostbus" \
    --hostaddr "$hostaddr" \
    --log "$serial_log" \
    --timeout 240
enrollment_token=
stop_gateway

timeout --signal=TERM --kill-after=10s 30s \
    "$pbnsctl_binary" --db "$gateway_database" enrollment show --id "$enrollment_id" \
    >"$evidence_dir/enrollment-status.txt"
timeout --signal=TERM --kill-after=10s 30s \
    "$pbnsctl_binary" --db "$gateway_database" hosts list \
    >"$evidence_dir/hosts.txt"
chmod 0600 "$evidence_dir/enrollment-status.txt" "$evidence_dir/hosts.txt"
grep -Fx 'state=consumed' "$evidence_dir/enrollment-status.txt" >/dev/null
grep -Fx 'hosts=1' "$evidence_dir/hosts.txt" >/dev/null
grep -E '^host_0=[0-9a-f]{64}:tpm-verified:[0-9]+$' "$evidence_dir/hosts.txt" >/dev/null

timeout --signal=TERM --kill-after=10s 30s \
    "$pbns_root/integration/swtpm/pause-swtpm.sh" "$swtpm_state" \
    >"$evidence_dir/swtpm-pause.log" 2>&1
chmod 0600 "$evidence_dir/swtpm-pause.log"
swtpm_active=0
python3 - "$checkpoint" "$enrollment_id" "$hostbus" "$hostaddr" "$ovmf_code" \
    "$ovmf_vars" "$signed_dir/PbnsEnroll.efi" "$signed_dir/PbnsAttest.efi" <<'PY'
import hashlib
import json
import os
import pathlib
import sys


def digest(path: str) -> str:
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short checkpoint write")
        view = view[written:]


path = pathlib.Path(sys.argv[1])
record = {
    "schema": "pbns-pico-passthrough-enrollment-v1",
    "phase": "enroll",
    "status": "passed",
    "qemu": "10.2.2-tcg",
    "network": "none",
    "usb": {
        "vendor": "cafe",
        "product_id": "4011",
        "product": "PBNS Proxy v1",
        "serial": "E66130100F527A26",
        "bcd_device": "0100",
        "hostbus": int(sys.argv[3]),
        "hostaddr": int(sys.argv[4]),
    },
    "tpm": "private-swtpm",
    "ek_nv_index": "0x01c0000a",
    "assurance": "tpm-verified",
    "enrollment_id": sys.argv[2],
    "ovmf_code_sha256": digest(sys.argv[5]),
    "ovmf_variables_sha256": digest(sys.argv[6]),
    "enroll_efi_sha256": digest(sys.argv[7]),
    "attest_efi_sha256": digest(sys.argv[8]),
}
data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
try:
    os.fchmod(descriptor, 0o600)
    write_all(descriptor, data)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY

python3 - "$current_path" "$evidence_dir" <<'PY'
import os
import pathlib
import stat
import sys


def write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short current-path write")
        view = view[written:]


current = pathlib.Path(sys.argv[1])
evidence = pathlib.Path(sys.argv[2])
if current.exists() or current.is_symlink():
    metadata = current.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("unsafe existing current-path file")
temporary = current.parent / f".attestation-passthrough-current.path.{os.getpid()}"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(temporary, flags, 0o600)
try:
    os.fchmod(descriptor, 0o600)
    write_all(descriptor, (str(evidence) + "\n").encode("ascii"))
    os.fsync(descriptor)
finally:
    os.close(descriptor)
try:
    os.replace(temporary, current)
except BaseException:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    raise
parent = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
printf 'PBNS PICO PASSTHROUGH ENROLLMENT PASS evidence=%s assurance=tpm-verified\n' "$evidence_dir"
