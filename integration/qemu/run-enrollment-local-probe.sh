#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
REPO_ROOT=$(cd -- "$PBNS_ROOT/.." && pwd -P)

if (( $# != 0 )); then
    printf 'usage: %s\n' "$0" >&2
    exit 2
fi
if [[ -z ${PBNS_EDK2_DIR:-} ]]; then
    printf '%s\n' 'PBNS_EDK2_DIR is required' >&2
    exit 2
fi
if [[ $PBNS_EDK2_DIR != /* && ! -d $PBNS_EDK2_DIR ]]; then
    PBNS_EDK2_DIR="$REPO_ROOT/$PBNS_EDK2_DIR"
fi
PBNS_EDK2_DIR=$(cd -- "$PBNS_EDK2_DIR" && pwd -P)
for tool in python3 qemu-system-x86_64 swtpm; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing QEMU enrollment probe tool: %s\n' "$tool" >&2
        exit 1
    }
done

CODE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"
VARS_TEMPLATE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_VARS.fd"
PROBE="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsEnroll.efi"
for artifact in "$CODE" "$VARS_TEMPLATE" "$PROBE"; do
    [[ -f $artifact ]] || {
        printf 'missing QEMU enrollment artifact: %s\n' "$artifact" >&2
        exit 1
    }
done

MODE=${PBNS_ENROLLMENT_LOCAL_MODE:-s}
if [[ $MODE != s && $MODE != t ]]; then
    printf '%s\n' 'PBNS_ENROLLMENT_LOCAL_MODE must be s or t' >&2
    exit 2
fi
STATE_DIR="$PBNS_ROOT/integration/state/qemu"
mkdir -p "$STATE_DIR"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-qemu-enrollment-XXXXXX")
ESP="$RUN_DIR/esp"
VARS="$RUN_DIR/OVMF_VARS.fd"
SWTPM_STATE="$RUN_DIR/swtpm-state"
if [[ $MODE == t ]]; then
    LOG="$STATE_DIR/enrollment-tpm-local-probe.log"
    RESULT="$STATE_DIR/enrollment-tpm-local-probe.json"
    MODE_ORACLE='PBNS ENROLL TPM MODE EXPLICIT'
else
    LOG="$STATE_DIR/enrollment-local-probe.log"
    RESULT="$STATE_DIR/enrollment-local-probe.json"
    MODE_ORACLE='PBNS ENROLL SOFTWARE MODE EXPLICIT'
fi
SWTPM_STARTED=0
cleanup() {
    if (( SWTPM_STARTED == 1 )); then
        "$PBNS_ROOT/integration/swtpm/stop-swtpm.sh" "$SWTPM_STATE" \
            >/dev/null 2>&1 || true
    fi
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$ESP/EFI/BOOT"
cp -- "$PROBE" "$ESP/PbnsEnroll.efi"
cp -- "$PROBE" "$ESP/EFI/BOOT/BOOTX64.EFI"
printf 'fs0:\\PbnsEnroll.efi software-create\r\nreset -s\r\n' >"$ESP/startup.nsh"
cp -- "$VARS_TEMPLATE" "$VARS"
: >"$LOG"
chmod 0600 "$LOG"
"$PBNS_ROOT/integration/swtpm/start-swtpm.sh" "$SWTPM_STATE" \
    >"$RUN_DIR/swtpm-start.log"
SWTPM_STARTED=1
SWTPM_SOCKET=$(<"$SWTPM_STATE/socket.path")
SWTPM_CONTROL="$SWTPM_SOCKET.ctrl"

python3 - "$CODE" "$VARS" "$ESP" "$SWTPM_CONTROL" "$LOG" "$MODE" <<'PY'
import base64
import hashlib
import os
import pathlib
import select
import subprocess
import sys
import time

code, variables, esp, swtpm_control, log_path, mode = sys.argv[1:]
if mode not in ("s", "t"):
    raise SystemExit("invalid explicit identity mode")
command = [
    "qemu-system-x86_64",
    "-machine", "q35,accel=tcg",
    "-cpu", "max",
    "-m", "256M",
    "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
    "-drive", f"if=pflash,format=raw,file={variables}",
    "-drive", f"format=raw,file=fat:rw:{esp}",
    "-chardev", f"socket,id=chrtpm,path={swtpm_control}",
    "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
    "-device", "tpm-tis,tpmdev=tpm0",
    "-nic", "none",
    "-display", "none",
    "-serial", "stdio",
    "-monitor", "none",
    "-no-reboot",
]
process = subprocess.Popen(
    command,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    bufsize=0,
)
assert process.stdin is not None and process.stdout is not None
output = bytearray()
mode_sent = False
token_sent = False
token_id_marker = None
mode_marker = b"PBNS ENROLL MODE: S=explicit reduced software, T=explicit TPM"
token_marker = b"PBNS ENROLL TOKEN READY (input hidden)"
terminal_marker = b"PBNS ENROLL FAIL CDC0 unavailable"
deadline = time.monotonic() + 35
try:
    while process.poll() is None and time.monotonic() < deadline:
        readable, _, _ = select.select([process.stdout], [], [], 0.2)
        if readable:
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            output.extend(chunk)
            if not mode_sent and mode_marker in output:
                process.stdin.write(mode.encode("ascii"))
                process.stdin.flush()
                mode_sent = True
            if mode_sent and not token_sent and token_marker in output:
                for _ in range(256):
                    token = bytearray(os.urandom(32))
                    encoded = bytearray(base64.urlsafe_b64encode(token).rstrip(b"="))
                    if b"-" in encoded and b"_" in encoded:
                        break
                    token[:] = b"\x00" * len(token)
                    encoded[:] = b"\x00" * len(encoded)
                else:
                    raise SystemExit("unable to generate bounded mixed Base64URL token")
                token_id_marker = (
                    b"PBNS ENROLL TOKEN ID "
                    + hashlib.sha256(token).hexdigest().encode("ascii")
                )
                process.stdin.write(encoded + b"\r")
                process.stdin.flush()
                token[:] = b"\x00" * len(token)
                encoded[:] = b"\x00" * len(encoded)
                token_sent = True
            if terminal_marker in output:
                break
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    remainder = process.stdout.read()
    if remainder:
        output.extend(remainder)
finally:
    pathlib.Path(log_path).write_bytes(output)
if not mode_sent:
    raise SystemExit("explicit software mode prompt was not observed")
if not token_sent:
    raise SystemExit("enrollment token prompt was not observed")
if token_id_marker is None or token_id_marker not in output:
    raise SystemExit("decoded enrollment token identifier did not match the input")
if process.returncode not in (0, -15):
    raise SystemExit(f"QEMU enrollment local probe exited unexpectedly: {process.returncode}")
PY
for oracle in \
    "$MODE_ORACLE" \
    'PBNS ENROLL TOKEN ACCEPTED' \
    'PBNS ENROLL INIT ENCRYPTION CHECKPOINT PASS' \
    'PBNS ENROLL FAIL CDC0 unavailable'; do
    grep -Fq "$oracle" "$LOG" || {
        printf 'QEMU enrollment serial oracle missing: %s\n' "$oracle" >&2
        exit 1
    }
done
if grep -Fq 'PBNS ENROLL SOFTWARE CHECKPOINT PASS' "$LOG"; then
    printf '%s\n' 'local-only probe unexpectedly reported live enrollment' >&2
    exit 1
fi

python3 - "$RESULT" "$CODE" "$VARS_TEMPLATE" "$PROBE" "$MODE" <<'PY'
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys

result_path, code_path, vars_path, probe_path = map(pathlib.Path, sys.argv[1:5])
mode = sys.argv[5]
def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
result = {
    "schema": "pbns-qemu-enrollment-local-v1",
    "evidence_class": "emulated-system-local-only",
    "recorded_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    "qemu_version": subprocess.check_output(
        ["qemu-system-x86_64", "--version"], text=True
    ).splitlines()[0],
    "swtpm_version": subprocess.check_output(
        ["swtpm", "--version"], text=True, stderr=subprocess.STDOUT
    ).splitlines()[0],
    "network": "disabled",
    "cdc0": "intentionally absent",
    "explicit_identity_mode": "tpm" if mode == "t" else "software-reduced",
    "sha256": {
        "ovmf_code": digest(code_path),
        "ovmf_vars_template": digest(vars_path),
        "pbns_enroll_efi": digest(probe_path),
    },
    "checks": {
        "hidden_token_input": "pass",
        "measured_boot_baseline": "pass",
        "encrypted_init_construction": "pass",
        "missing_cdc0": "rejected",
    },
}
result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
result_path.chmod(0o600)
PY
printf '[PASS] disposable FAT, copied OVMF variables, TCG, swtpm, no network, and no OS disk\n'
printf '[PASS] hidden token input and encrypted enrollment init constructed before CDC0 use\n'
printf '%s\n' 'UEFI ENROLLMENT LOCAL EMULATED CHECKPOINT PASS'
