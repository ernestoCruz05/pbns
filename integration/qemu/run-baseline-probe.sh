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
for tool in python3 qemu-system-x86_64 swtpm timeout tpm2_getcap; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing QEMU baseline probe tool: %s\n' "$tool" >&2
        exit 1
    }
done

CODE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"
VARS_TEMPLATE="$PBNS_EDK2_DIR/Build/OvmfX64/DEBUG_GCC/FV/OVMF_VARS.fd"
PROBE="$PBNS_EDK2_DIR/Build/PbnsPkg/DEBUG_GCC/X64/PbnsBaseline.efi"
for artifact in "$CODE" "$VARS_TEMPLATE" "$PROBE"; do
    if [[ ! -f $artifact ]]; then
        printf 'missing QEMU baseline artifact: %s\n' "$artifact" >&2
        exit 1
    fi
done

STATE_DIR="$PBNS_ROOT/integration/state/qemu"
mkdir -p "$STATE_DIR"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pbns-qemu-baseline-XXXXXX")
ESP="$RUN_DIR/esp"
VARS="$RUN_DIR/OVMF_VARS.fd"
NO_TPM_VARS="$RUN_DIR/OVMF_VARS_NO_TPM.fd"
SWTPM_STATE="$RUN_DIR/swtpm-state"
LOG="$STATE_DIR/baseline-probe.log"
NO_TPM_LOG="$STATE_DIR/baseline-probe-no-tpm.log"
RESULT="$STATE_DIR/baseline-probe.json"
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
cp -- "$PROBE" "$ESP/PbnsBaseline.efi"
cp -- "$PROBE" "$ESP/EFI/BOOT/BOOTX64.EFI"
printf 'fs0:\\PbnsBaseline.efi\r\nreset -s\r\n' >"$ESP/startup.nsh"
cp -- "$VARS_TEMPLATE" "$VARS"
cp -- "$VARS_TEMPLATE" "$NO_TPM_VARS"
: >"$LOG"
: >"$NO_TPM_LOG"
chmod 0600 "$LOG" "$NO_TPM_LOG"
"$PBNS_ROOT/integration/swtpm/start-swtpm.sh" "$SWTPM_STATE" \
    >"$RUN_DIR/swtpm-start.log"
SWTPM_STARTED=1
SWTPM_SOCKET=$(<"$SWTPM_STATE/socket.path")
SWTPM_CONTROL="$SWTPM_SOCKET.ctrl"

set +e
timeout --signal=TERM --kill-after=5s 20s qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -cpu max \
    -m 256M \
    -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
    -drive "if=pflash,format=raw,file=$VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    -chardev "socket,id=chrtpm,path=$SWTPM_CONTROL" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -nic none \
    -display none \
    -serial stdio \
    -monitor none \
    -no-reboot >"$LOG" 2>&1
qemu_status=$?
set -e
if [[ $qemu_status != 0 && $qemu_status != 124 ]]; then
    printf 'QEMU baseline probe exited unexpectedly: %s\n' "$qemu_status" >&2
    exit 1
fi
for oracle in \
    'PBNS BASELINE EVENT LOG MS' \
    'PBNS BASELINE HASHING MS' \
    'PBNS BASELINE PCR READ MS' \
    'PBNS BASELINE ENCODING MS' \
    'PBNS BASELINE CAPTURE PASS'; do
    if ! grep -Fq "$oracle" "$LOG"; then
        printf 'QEMU baseline serial oracle missing: %s\n' "$oracle" >&2
        exit 1
    fi
done
if grep -Fq 'PBNS BASELINE PROBE FAIL' "$LOG"; then
    printf '%s\n' 'QEMU baseline probe reported failure' >&2
    exit 1
fi

set +e
timeout --signal=TERM --kill-after=5s 20s qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -cpu max \
    -m 256M \
    -drive "if=pflash,format=raw,readonly=on,file=$CODE" \
    -drive "if=pflash,format=raw,file=$NO_TPM_VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    -nic none \
    -display none \
    -serial stdio \
    -monitor none \
    -no-reboot >"$NO_TPM_LOG" 2>&1
no_tpm_status=$?
set -e
if [[ $no_tpm_status != 0 && $no_tpm_status != 124 ]]; then
    printf 'QEMU baseline no-TPM probe exited unexpectedly: %s\n' \
        "$no_tpm_status" >&2
    exit 1
fi
if ! grep -Fq 'PBNS BASELINE PROBE FAIL status Unsupported' "$NO_TPM_LOG" ||
   grep -Fq 'PBNS BASELINE CAPTURE PASS' "$NO_TPM_LOG"; then
    printf '%s\n' 'QEMU baseline no-TPM rejection oracle missing' >&2
    exit 1
fi

python3 - "$LOG" "$RESULT" "$CODE" "$VARS_TEMPLATE" "$PROBE" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

log_path, result_path, code_path, vars_path, probe_path = map(pathlib.Path, sys.argv[1:])
text = log_path.read_text(encoding="utf-8", errors="replace")

def metric(label: str) -> int:
    matches = re.findall(rf"^{re.escape(label)} ([0-9]+)\r?$", text, re.MULTILINE)
    if len(matches) != 1:
        raise SystemExit(f"missing or repeated baseline metric: {label}")
    return int(matches[0])

def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

result = {
    "schema": "pbns-qemu-measured-boot-v1",
    "evidence_class": "emulated-system",
    "recorded_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    "qemu_version": subprocess.check_output(
        ["qemu-system-x86_64", "--version"], text=True
    ).splitlines()[0],
    "swtpm_version": subprocess.check_output(
        ["swtpm", "--version"], text=True, stderr=subprocess.STDOUT
    ).splitlines()[0],
    "sha256": {
        "ovmf_code": digest(code_path),
        "ovmf_vars_template": digest(vars_path),
        "pbns_baseline_efi": digest(probe_path),
    },
    "event_count": metric("PBNS BASELINE EVENTS"),
    "encoded_bytes": metric("PBNS BASELINE ENCODED BYTES"),
    "pcr_update_counter": metric("PBNS BASELINE PCR UPDATE COUNTER"),
    "negative_checks": {"missing_tcg2": "rejected"},
    "timing_ms": {
        "total_capture": metric("PBNS BASELINE CAPTURE MS"),
        "event_log_capture": metric("PBNS BASELINE EVENT LOG MS"),
        "hashing": metric("PBNS BASELINE HASHING MS"),
        "pcr_read": metric("PBNS BASELINE PCR READ MS"),
        "encoding": metric("PBNS BASELINE ENCODING MS"),
    },
}
result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
result_path.chmod(0o600)
PY
printf '[PASS] disposable FAT, copied OVMF variables, TCG, swtpm, and no installed OS disk\n'
printf '[PASS] GetEventLog, SHA-256 PCRs 0/2/4/7, Secure Boot variables, and bounded encoding\n'
printf '[PASS] missing TCG2 rejected without software fallback\n'
printf '[PASS] component timings recorded as emulated-system measurements in %s\n' "$RESULT"
printf '%s\n' 'UEFI MEASURED BOOT EMULATED CHECKPOINT PASS'
