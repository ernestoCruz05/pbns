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
MODE=${PBNS_TIME_LIVE_LOCAL_MODE:-s}
if [[ $MODE != s && $MODE != t ]]; then
    printf '%s\n' 'PBNS_TIME_LIVE_LOCAL_MODE must be s or t' >&2
    exit 2
fi
for tool in python3 qemu-system-x86_64 swtpm tpm2_getcap; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing QEMU trusted-time live probe tool: %s\n' "$tool" >&2
        exit 1
    }
done

CODE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"
VARS_TEMPLATE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_VARS.fd"
ENROLL="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsEnroll.efi"
TIME_LIVE="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsTimeLive.efi"
for artifact in "$CODE" "$VARS_TEMPLATE" "$ENROLL" "$TIME_LIVE"; do
    [[ -f $artifact ]] || {
        printf 'missing QEMU trusted-time live artifact: %s\n' "$artifact" >&2
        exit 1
    }
done

STATE_DIR="$PBNS_ROOT/integration/state/qemu"
mkdir -p "$STATE_DIR"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-qemu-time-live-XXXXXX")
ESP="$RUN_DIR/esp"
VARS="$RUN_DIR/OVMF_VARS.fd"
SWTPM_STATE="$RUN_DIR/swtpm-state"
if [[ $MODE == t ]]; then
    ENROLL_LOG="$STATE_DIR/time-live-tpm-prerequisite-enrollment.log"
    TIME_LOG="$STATE_DIR/time-live-tpm-local-probe.log"
    RESULT="$STATE_DIR/time-live-tpm-local-probe.json"
    IDENTITY_MODE=tpm
else
    ENROLL_LOG="$STATE_DIR/time-live-software-prerequisite-enrollment.log"
    TIME_LOG="$STATE_DIR/time-live-software-local-probe.log"
    RESULT="$STATE_DIR/time-live-software-local-probe.json"
    IDENTITY_MODE=software-reduced
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
cp -- "$ENROLL" "$ESP/EFI/BOOT/BOOTX64.EFI"
cp -- "$VARS_TEMPLATE" "$VARS"
: >"$ENROLL_LOG"
: >"$TIME_LOG"
chmod 0600 "$ENROLL_LOG" "$TIME_LOG"
"$PBNS_ROOT/integration/swtpm/start-swtpm.sh" "$SWTPM_STATE" \
    >"$RUN_DIR/swtpm-start.log"
SWTPM_STARTED=1
SWTPM_SOCKET=$(<"$SWTPM_STATE/socket.path")
SWTPM_CONTROL="$SWTPM_SOCKET.ctrl"

python3 - \
    "$CODE" "$VARS" "$ESP" "$SWTPM_CONTROL" "$SWTPM_STATE" "$MODE" \
    "$ENROLL_LOG" "$TIME_LOG" "$TIME_LIVE" <<'PY'
import base64
import os
import pathlib
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

(
    code,
    variables,
    esp_text,
    swtpm_control,
    swtpm_state_text,
    mode,
    enroll_log,
    time_log,
    time_live,
) = sys.argv[1:]
esp = pathlib.Path(esp_text)
swtpm_state = pathlib.Path(swtpm_state_text)

def qemu_command(use_tpm: bool) -> list[str]:
    command = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=tcg",
        "-cpu", "max",
        "-m", "256M",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={variables}",
        "-drive", f"format=raw,file=fat:rw:{esp}",
        "-nic", "none",
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
        "-no-reboot",
    ]
    if use_tpm:
        command.extend([
            "-chardev", f"socket,id=chrtpm,path={swtpm_control}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis,tpmdev=tpm0",
        ])
    return command

def restart_swtpm() -> None:
    global swtpm_control
    pid_path = swtpm_state / "swtpm.pid"
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
    old_runtime = pathlib.Path((swtpm_state / "runtime.path").read_text().strip())
    if old_runtime.exists():
        shutil.rmtree(old_runtime)
    runtime = pathlib.Path(tempfile.mkdtemp(prefix="pbns-swtpm."))
    runtime.chmod(0o700)
    socket_path = runtime / "server.sock"
    control_path = pathlib.Path(str(socket_path) + ".ctrl")
    for name, value in (
        ("runtime.path", str(runtime)),
        ("socket.path", str(socket_path)),
    ):
        path = swtpm_state / name
        path.write_text(value + "\n")
        path.chmod(0o600)
    subprocess.run([
        "swtpm", "socket", "--tpm2",
        "--tpmstate", f"dir={swtpm_state / 'tpm'},mode=0600",
        "--ctrl", f"type=unixio,path={control_path},mode=0600",
        "--server", f"type=unixio,path={socket_path},mode=0600",
        "--flags", "startup-clear",
        "--pid", f"file={swtpm_state / 'swtpm.pid'}",
        "--log", f"file={swtpm_state / 'swtpm.log'},level=2",
        "--daemon",
    ], check=True)
    deadline = time.monotonic() + 5
    while not (socket_path.exists() and control_path.exists()):
        if time.monotonic() >= deadline:
            raise SystemExit("restarted swtpm sockets were not created")
        time.sleep(0.05)
    readiness_environment = os.environ.copy()
    readiness_environment["TPM2TOOLS_TCTI"] = f"swtpm:path={socket_path}"
    subprocess.run(
        ["tpm2_getcap", "properties-fixed"],
        env=readiness_environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    swtpm_control = str(control_path)

def run_guest(
    mode_marker: bytes,
    terminal_marker: bytes,
    log_path: str,
    token: bool,
    use_tpm: bool,
) -> bytes:
    process = subprocess.Popen(
        qemu_command(use_tpm),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    assert process.stdin is not None and process.stdout is not None
    output = bytearray()
    mode_sent = False
    token_sent = False
    token_marker = b"PBNS ENROLL TOKEN READY (input hidden)"
    deadline = time.monotonic() + 35
    try:
        while process.poll() is None and time.monotonic() < deadline:
            readable, _, _ = select.select([process.stdout], [], [], 0.2)
            if not readable:
                continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            output.extend(chunk)
            if not mode_sent and mode_marker in output:
                process.stdin.write(mode.encode("ascii"))
                process.stdin.flush()
                mode_sent = True
            if token and mode_sent and not token_sent and token_marker in output:
                secret = bytearray(os.urandom(32))
                encoded = bytearray(base64.urlsafe_b64encode(secret).rstrip(b"="))
                process.stdin.write(encoded + b"\r")
                process.stdin.flush()
                secret[:] = b"\x00" * len(secret)
                encoded[:] = b"\x00" * len(encoded)
                token_sent = True
            if terminal_marker in output:
                break
    finally:
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
        pathlib.Path(log_path).write_bytes(output)
    if not mode_sent or (token and not token_sent) or terminal_marker not in output:
        raise SystemExit(f"missing serial checkpoint in {log_path}")
    if process.returncode not in (0, -15):
        raise SystemExit(f"QEMU exited unexpectedly: {process.returncode}")
    return bytes(output)

run_guest(
    b"PBNS ENROLL MODE: S=explicit reduced software, T=explicit TPM",
    b"PBNS ENROLL FAIL CDC0 unavailable",
    enroll_log,
    True,
    True,
)
shutil.copyfile(time_live, esp / "EFI" / "BOOT" / "BOOTX64.EFI")
if mode == "t":
    restart_swtpm()
time_output = run_guest(
    b"PBNS TIME MODE: S=enrolled reduced software, T=enrolled TPM",
    b"PBNS TIME LIVE FAIL CDC0 unavailable",
    time_log,
    False,
    mode == "t",
)
if b"PBNS TIME LIVE FAIL identity open" in time_output:
    raise SystemExit("persistent identity failed to reopen")
PY

for oracle in \
    'PBNS ENROLL INIT ENCRYPTION CHECKPOINT PASS' \
    'PBNS ENROLL FAIL CDC0 unavailable'; do
    grep -Fq "$oracle" "$ENROLL_LOG" || {
        printf 'prerequisite enrollment oracle missing: %s\n' "$oracle" >&2
        exit 1
    }
done
for oracle in \
    'PBNS TIME LIVE FAIL CDC0 unavailable'; do
    grep -Fq "$oracle" "$TIME_LOG" || {
        printf 'trusted-time live local oracle missing: %s\n' "$oracle" >&2
        exit 1
    }
done
if grep -Fq 'PBNS TIME LIVE FAIL identity open' "$TIME_LOG"; then
    printf '%s\n' 'persistent identity did not reopen for trusted time' >&2
    exit 1
fi

python3 - \
    "$RESULT" "$CODE" "$VARS_TEMPLATE" "$ENROLL" "$TIME_LIVE" \
    "$IDENTITY_MODE" <<'PY'
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys

result_path, code_path, vars_path, enroll_path, time_path = map(
    pathlib.Path, sys.argv[1:6]
)
identity_mode = sys.argv[6]
def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
result = {
    "schema": "pbns-qemu-time-live-local-v1",
    "evidence_class": "emulated-system-local-only",
    "recorded_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    "explicit_identity_mode": identity_mode,
    "qemu_version": subprocess.check_output(
        ["qemu-system-x86_64", "--version"], text=True
    ).splitlines()[0],
    "swtpm_version": subprocess.check_output(
        ["swtpm", "--version"], text=True, stderr=subprocess.STDOUT
    ).splitlines()[0],
    "network": "disabled",
    "cdc0": "intentionally absent",
    "sha256": {
        "ovmf_code": digest(code_path),
        "ovmf_vars_template": digest(vars_path),
        "pbns_enroll_efi": digest(enroll_path),
        "pbns_time_live_efi": digest(time_path),
    },
    "checks": {
        "persistent_identity_create": "pass",
        "persistent_identity_reopen": "pass",
        "live_time_client_setup": "pass",
        "missing_cdc0": "rejected",
        "rtc_access": "absent-by-source-policy",
    },
}
result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
result_path.chmod(0o600)
PY
printf '[PASS] persistent %s identity reopened across copied-OVMF-variable boot\n' \
    "$IDENTITY_MODE"
printf '[PASS] live trusted-time client reached the intentional missing-CDC0 boundary\n'
printf '%s\n' 'UEFI TRUSTED TIME LIVE LOCAL EMULATED CHECKPOINT PASS'
