#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)

if (( $# != 1 )) || [[ $1 != --software && $1 != --tpm ]]; then
    printf 'usage: %s --software|--tpm\n' "$0" >&2
    exit 2
fi
if [[ -z ${PBNS_EDK2_DIR:-} || -z ${PBNS_GATEWAY_SERVER_NAME:-} ]]; then
    printf '%s\n' 'PBNS_EDK2_DIR and PBNS_GATEWAY_SERVER_NAME are required' >&2
    exit 2
fi
if [[ $PBNS_EDK2_DIR != /* && ! -d $PBNS_EDK2_DIR ]]; then
    PBNS_EDK2_DIR="$REPO_ROOT/$PBNS_EDK2_DIR"
fi
PBNS_EDK2_DIR=$(cd -- "$PBNS_EDK2_DIR" && pwd -P)
for tool in go openssl python3 qemu-system-x86_64 sha256sum swtpm tpm2_getcap; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing live enrollment/time tool: %s\n' "$tool" >&2
        exit 1
    }
done
if ! qemu-system-x86_64 -device help 2>/dev/null | grep -Fq 'name "usb-host"'; then
    printf '%s\n' 'QEMU lacks usb-host support' >&2
    exit 1
fi

MODE=s
IDENTITY_MODE=software-reduced
ASSURANCE=software
PASS_ORACLE='PBNS ENROLL SOFTWARE CHECKPOINT PASS'
if [[ $1 == --tpm ]]; then
    MODE=t
    IDENTITY_MODE=tpm
    ASSURANCE=tpm-unverified-ek
    PASS_ORACLE='PBNS ENROLL TPM CHECKPOINT PASS'
fi

python3 - <<'PY'
import pathlib

matches = []
for device in pathlib.Path("/sys/bus/usb/devices").glob("*"):
    try:
        vendor = (device / "idVendor").read_text().strip().lower()
        product = (device / "idProduct").read_text().strip().lower()
    except OSError:
        continue
    if (vendor == "cafe" and product == "4011"):
        serial = (device / "serial").read_text().strip()
        description = (device / "product").read_text().strip()
        matches.append((serial, description))
if matches != [("E66130100F527A26", "PBNS Proxy v1")]:
    raise SystemExit(f"exact PBNS proxy identity not present: {matches!r}")
PY
for tty in /dev/ttyACM0 /dev/ttyACM1; do
    [[ -c $tty ]] || {
        printf 'PBNS CDC device absent: %s\n' "$tty" >&2
        exit 1
    }
    permissions=$(stat -c %a "$tty")
    if (( (8#$permissions & 8#007) != 0 )); then
        printf 'PBNS CDC device has unsafe other-user permissions: %s\n' "$tty" >&2
        exit 1
    fi
done

CODE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"
VARS_TEMPLATE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_VARS.fd"
ENROLL="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsEnroll.efi"
TIME_LIVE="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsTimeLive.efi"
for artifact in "$CODE" "$VARS_TEMPLATE" "$ENROLL" "$TIME_LIVE"; do
    [[ -f $artifact ]] || {
        printf 'missing live enrollment/time artifact: %s\n' "$artifact" >&2
        exit 1
    }
done

STATE_DIR="$PBNS_ROOT/integration/state/qemu"
mkdir -p "$STATE_DIR"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-qemu-enrollment-time-XXXXXX")
chmod 0700 "$RUN_DIR"
ESP="$RUN_DIR/esp"
VARS="$RUN_DIR/OVMF_VARS.fd"
SWTPM_STATE="$RUN_DIR/swtpm-state"
DATABASE="$RUN_DIR/gateway.db"
GATEWAY_LOG="$STATE_DIR/enrollment-time-${IDENTITY_MODE}-gateway.log"
ENROLL_LOG="$STATE_DIR/enrollment-time-${IDENTITY_MODE}-enrollment.log"
TIME_LOG="$STATE_DIR/enrollment-time-${IDENTITY_MODE}-time.log"
RESULT="$STATE_DIR/enrollment-time-${IDENTITY_MODE}.json"
GATEWAY_BINARY="$RUN_DIR/pbns-gateway"
PBNSCTL_BINARY="$RUN_DIR/pbnsctl"
TLS_CERT="$RUN_DIR/tls/gateway-reissued-cert.pem"
TLS_KEY="$RUN_DIR/private/tls-key.pem"
RECIPIENT_KEY="$RUN_DIR/private/enrollment-recipient.pem"
ENROLLMENT_KEY="$RUN_DIR/private/enrollment-signing.pem"
TIME_KEY="$RUN_DIR/private/time-signing.pem"
GATEWAY_PID=
SWTPM_STARTED=0
cleanup() {
    unset TOKEN TOKEN_OUTPUT || true
    if [[ -n $GATEWAY_PID ]] && kill -0 "$GATEWAY_PID" 2>/dev/null; then
        kill -TERM "$GATEWAY_PID" 2>/dev/null || true
        wait "$GATEWAY_PID" 2>/dev/null || true
    fi
    if (( SWTPM_STARTED == 1 )); then
        "$PBNS_ROOT/integration/swtpm/stop-swtpm.sh" "$SWTPM_STATE" \
            >/dev/null 2>&1 || true
    fi
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$ESP/EFI/BOOT" "$RUN_DIR/private" "$RUN_DIR/tls"
chmod 0700 "$RUN_DIR/private" "$RUN_DIR/tls"
cp -- "$ENROLL" "$ESP/EFI/BOOT/BOOTX64.EFI"
cp -- "$VARS_TEMPLATE" "$VARS"
cp -- "$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-key.pem" "$TLS_KEY"
cp -- "$PBNS_ROOT/tests/fixtures/keys/enrollment-recipient-test-private.pem" \
    "$RECIPIENT_KEY"
cp -- "$PBNS_ROOT/tests/fixtures/keys/enrollment-signing-test-private.pem" \
    "$ENROLLMENT_KEY"
openssl ec -in \
    "$PBNS_ROOT/tests/fixtures/keys/service-signing-test-private.pem" \
    -out "$TIME_KEY" >/dev/null 2>&1
chmod 0600 "$TLS_KEY" "$RECIPIENT_KEY" "$ENROLLMENT_KEY" "$TIME_KEY"
: >"$GATEWAY_LOG"
: >"$ENROLL_LOG"
: >"$TIME_LOG"
chmod 0600 "$GATEWAY_LOG" "$ENROLL_LOG" "$TIME_LOG"

"$PBNS_ROOT/integration/tls/make-test-pki.sh" \
    "$RUN_DIR/tls" "$PBNS_GATEWAY_SERVER_NAME" >"$RUN_DIR/tls.log"
python3 "$PBNS_ROOT/integration/tls/verify-spki.py" \
    "$TLS_CERT" "$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-spki.sha256"
(
    cd -- "$PBNS_ROOT/gateway"
    go build -trimpath -o "$GATEWAY_BINARY" ./cmd/pbns-gateway
    go build -trimpath -o "$PBNSCTL_BINARY" ./cmd/pbnsctl
)
TOKEN_OUTPUT=$("$PBNSCTL_BINARY" --db "$DATABASE" enrollment create --ttl 10m)
TOKEN=$(printf '%s\n' "$TOKEN_OUTPUT" | awk -F= '$1 == "enrollment_token" {print $2}')
if [[ ${#TOKEN} -ne 43 ]] || [[ $(printf '%s\n' "$TOKEN_OUTPUT" | grep -c '^enrollment_token=') -ne 1 ]]; then
    printf '%s\n' 'pbnsctl did not emit exactly one 256-bit token' >&2
    exit 1
fi

start_gateway() {
    "$GATEWAY_BINARY" \
        --listen "${PBNS_GATEWAY_LISTEN:-0.0.0.0:8443}" \
        --tls-cert "$TLS_CERT" \
        --tls-key "$TLS_KEY" \
        --handshake-timeout 15s \
        --read-timeout 60s \
        --write-timeout 60s \
        --enrollment-store "$DATABASE" \
        --enrollment-recipient-key "$RECIPIENT_KEY" \
        --enrollment-recipient-kid enrollment-recipient-1 \
        --enrollment-signing-key "$ENROLLMENT_KEY" \
        --enrollment-signing-kid enrollment-signer-1 \
        --time-signing-key "$TIME_KEY" \
        --time-signing-kid time-key-1 \
        --time-uncertainty 250ms \
        --time-quality qemu-gateway-synchronized \
        >>"$GATEWAY_LOG" 2>&1 &
    GATEWAY_PID=$!
    sleep 1
    kill -0 "$GATEWAY_PID" 2>/dev/null || {
        printf '%s\n' 'PBNS gateway failed to start' >&2
        exit 1
    }
}
stop_gateway() {
    if [[ -n $GATEWAY_PID ]]; then
        kill -TERM "$GATEWAY_PID"
        wait "$GATEWAY_PID" || true
        GATEWAY_PID=
    fi
}

start_gateway
"$PBNS_ROOT/integration/swtpm/start-swtpm.sh" "$SWTPM_STATE" \
    >"$RUN_DIR/swtpm-start.log"
SWTPM_STARTED=1
SWTPM_SOCKET=$(<"$SWTPM_STATE/socket.path")
SWTPM_CONTROL="$SWTPM_SOCKET.ctrl"
printf '%s\n' "$TOKEN" | python3 "$SCRIPT_DIR/enrollment-time-driver.py" \
    --phase enrollment \
    --mode "$MODE" \
    --code "$CODE" \
    --variables "$VARS" \
    --esp "$ESP" \
    --swtpm-control "$SWTPM_CONTROL" \
    --log "$ENROLL_LOG"
unset TOKEN TOKEN_OUTPUT
if ! grep -Fq "$PASS_ORACLE" "$ENROLL_LOG"; then
    printf '%s\n' 'live enrollment serial oracle missing' >&2
    exit 1
fi

stop_gateway
start_gateway
cp -- "$TIME_LIVE" "$ESP/EFI/BOOT/BOOTX64.EFI"
if [[ $MODE == t ]]; then
    python3 - "$SWTPM_STATE" <<'PY'
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

state = pathlib.Path(sys.argv[1])
pid_path = state / "swtpm.pid"
if pid_path.exists():
    pid = int(pid_path.read_text().strip())
    command_line = pathlib.Path(f"/proc/{pid}/cmdline")
    if command_line.exists():
        if b"swtpm" not in command_line.read_bytes():
            raise SystemExit("cannot verify swtpm process before restart")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while pathlib.Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if pathlib.Path(f"/proc/{pid}").exists():
            os.kill(pid, signal.SIGKILL)
    pid_path.unlink(missing_ok=True)
old_runtime = pathlib.Path((state / "runtime.path").read_text().strip())
if old_runtime.exists():
    shutil.rmtree(old_runtime)
runtime = pathlib.Path(tempfile.mkdtemp(prefix="pbns-swtpm."))
runtime.chmod(0o700)
socket_path = runtime / "server.sock"
control_path = pathlib.Path(str(socket_path) + ".ctrl")
for name, value in (("runtime.path", runtime), ("socket.path", socket_path)):
    path = state / name
    path.write_text(str(value) + "\n")
    path.chmod(0o600)
subprocess.run([
    "swtpm", "socket", "--tpm2",
    "--tpmstate", f"dir={state / 'tpm'},mode=0600",
    "--ctrl", f"type=unixio,path={control_path},mode=0600",
    "--server", f"type=unixio,path={socket_path},mode=0600",
    "--flags", "startup-clear",
    "--pid", f"file={state / 'swtpm.pid'}",
    "--log", f"file={state / 'swtpm.log'},level=2",
    "--daemon",
], check=True)
deadline = time.monotonic() + 5
while not (socket_path.exists() and control_path.exists()):
    if time.monotonic() >= deadline:
        raise SystemExit("restarted swtpm sockets were not created")
    time.sleep(0.05)
environment = os.environ.copy()
environment["TPM2TOOLS_TCTI"] = f"swtpm:path={socket_path}"
subprocess.run(
    ["tpm2_getcap", "properties-fixed"], env=environment,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
)
PY
    SWTPM_SOCKET=$(<"$SWTPM_STATE/socket.path")
    SWTPM_CONTROL="$SWTPM_SOCKET.ctrl"
    time_tpm_arguments=(--swtpm-control "$SWTPM_CONTROL")
else
    time_tpm_arguments=()
fi
python3 "$SCRIPT_DIR/enrollment-time-driver.py" \
    --phase time \
    --mode "$MODE" \
    --code "$CODE" \
    --variables "$VARS" \
    --esp "$ESP" \
    "${time_tpm_arguments[@]}" \
    --log "$TIME_LOG"
if ! grep -Fq 'PBNS TIME LIVE INTERVAL PASS' "$TIME_LOG" ||
    ! grep -Fq 'PBNS TIME LIVE REPLAY REJECT PASS' "$TIME_LOG"; then
    printf '%s\n' 'live trusted-time success or replay-rejection oracle missing' >&2
    exit 1
fi

stop_gateway
HOST_OUTPUT=$("$PBNSCTL_BINARY" --db "$DATABASE" hosts list)
if ! grep -Fqx 'hosts=1' <<<"$HOST_OUTPUT"; then
    printf 'gateway host inventory mismatch: %s\n' "$HOST_OUTPUT" >&2
    exit 1
fi

python3 - \
    "$RESULT" "$ENROLL_LOG" "$TIME_LOG" "$CODE" "$VARS_TEMPLATE" \
    "$ENROLL" "$TIME_LIVE" "$IDENTITY_MODE" "$ASSURANCE" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

(
    result_path,
    enroll_log,
    time_log,
    code_path,
    vars_path,
    enroll_path,
    time_path,
) = map(pathlib.Path, sys.argv[1:8])
identity_mode, assurance = sys.argv[8:10]
enrollment = enroll_log.read_text(encoding="utf-8", errors="replace")
trusted_time = time_log.read_text(encoding="utf-8", errors="replace")
def metric(text: str, label: str) -> int:
    matches = re.findall(rf"^{re.escape(label)} ([0-9]+)\r?$", text, re.MULTILINE)
    if len(matches) != 1:
        raise SystemExit(f"missing or repeated metric: {label}")
    return int(matches[0])
def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
result = {
    "schema": "pbns-identity-time-result-v1",
    "evidence_class": "emulated-system-with-physical-proxy",
    "identity_mode": identity_mode,
    "assurance": assurance,
    "recorded_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    "platform": {
        "qemu": subprocess.check_output(
            ["qemu-system-x86_64", "--version"], text=True
        ).splitlines()[0],
        "swtpm": subprocess.check_output(
            ["swtpm", "--version"], text=True, stderr=subprocess.STDOUT
        ).splitlines()[0],
        "proxy_vid_pid": "cafe:4011",
        "proxy_serial": "E66130100F527A26",
    },
    "timing_ms": {
        "baseline_local": metric(enrollment, "PBNS ENROLL BASELINE LOCAL MS"),
        "init_crypto": metric(enrollment, "PBNS ENROLL INIT CRYPTO MS"),
        "begin_exchange": metric(enrollment, "PBNS ENROLL BEGIN EXCHANGE MS"),
        "proof_crypto": metric(enrollment, "PBNS ENROLL PROOF CRYPTO MS"),
        "complete_exchange": metric(enrollment, "PBNS ENROLL COMPLETE EXCHANGE MS"),
        "enrollment_total": metric(enrollment, "PBNS ENROLL TOTAL MS"),
        "trusted_time_total": metric(trusted_time, "PBNS TIME LIVE TOTAL MS"),
    },
    "trusted_time_interval_width_ns": metric(
        trusted_time, "PBNS TIME LIVE INTERVAL WIDTH NS"
    ),
    "sha256": {
        "ovmf_code": digest(code_path),
        "ovmf_vars_template": digest(vars_path),
        "pbns_enroll_efi": digest(enroll_path),
        "pbns_time_live_efi": digest(time_path),
    },
    "checks": {
        "enrollment": "pass",
        "gateway_restart": "pass",
        "trusted_time_interval": "pass",
        "trusted_time_replay_rejected": "pass",
        "token_serial_output": "pass",
    },
}
result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
result_path.chmod(0o600)
PY
MANIFEST="${RESULT%.json}.sha256"
sha256sum "$RESULT" "$ENROLL_LOG" "$TIME_LOG" "$GATEWAY_LOG" >"$MANIFEST"
chmod 0600 "$MANIFEST"
printf '[PASS] hosts=1 after atomic controlled enrollment\n'
printf '[PASS] gateway restart retained enrolled identity for trusted time\n'
printf '[PASS] token absent from UEFI serial output and delivered only through hidden input\n'
printf '%s\n' 'IDENTITY TIME QEMU SWTPM PASS'
