#!/usr/bin/env python3
import argparse
import ctypes
import functools
import os
import pathlib
import re
import resource
import select
import signal
import shutil
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable


RECOVERY_CASES = (
    "signed-trusted",
    "unsigned-untrusted",
    "truncated",
    "gateway-interruption",
    "forged-manifest",
    "forged-digest",
    "forged-chunk",
    "downgrade",
)
LAUNCHER_CASES = ("normal-launcher", "pico-absent")
ALL_CASES = RECOVERY_CASES + LAUNCHER_CASES
PHASES = ("recovery", "launcher-setup", "launcher-run")
CONFIRMATION = b"Type RECOVER to download a RAM-only recovery image: "
ASSURANCE = b"Select recovery assurance: T/t or S/s: "
NORMAL_LINE = re.compile(
    rb"(?m)^  \[([0-9]+)\] Boot[0-9A-Fa-f]{4} PBNS Normal Fixture\r?$"
)
FORBIDDEN_LOG = re.compile(
    rb"private[ _-]*key|identity[ _-]*(?:material|key|cose)|"
    rb"tpm[ _-]*(?:blob|auth|authorization|session|nonce)|auth[ _-]*value|"
    rb"session[ _-]*nonce|token|nonce|decrypted[ _-]*transcript|"
    rb"policy[ _-]*(?:authorization|internal)|artifact[ _-]*bytes|"
    rb"transient[ _-]*crypto",
    re.IGNORECASE,
)
OUTPUT_CAP = 8 * 1024 * 1024
INITIAL_EXIT_WAIT_SECONDS = 0.2
TERM_CLEANUP_WAIT_SECONDS = 5.0
KILL_CLEANUP_WAIT_SECONDS = 5.0
# The runner grants the driver longer than this complete cooperative cleanup.
WORST_CLEANUP_SECONDS = (
    INITIAL_EXIT_WAIT_SECONDS + TERM_CLEANUP_WAIT_SECONDS + KILL_CLEANUP_WAIT_SECONDS
)

# Load and configure libc before Popen forks.  Loading a shared library in a
# preexec_fn can deadlock if another thread held the dynamic-loader lock.
_LIBC: ctypes.CDLL | None = None
if sys.platform.startswith("linux"):
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
    _LIBC.prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    _LIBC.prctl.restype = ctypes.c_int
_PR_SET_PDEATHSIG = 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--case-root", type=pathlib.Path, required=True)
    result.add_argument("--case", choices=ALL_CASES, required=True)
    result.add_argument("--phase", choices=PHASES, required=True)
    result.add_argument("--code", type=pathlib.Path, required=True)
    result.add_argument("--variables", type=pathlib.Path, required=True)
    result.add_argument("--esp", type=pathlib.Path, required=True)
    result.add_argument("--swtpm-state", type=pathlib.Path, required=True)
    result.add_argument("--disk", type=pathlib.Path, required=True)
    result.add_argument("--log", type=pathlib.Path, required=True)
    result.add_argument("--pico", choices=("present", "absent"), required=True)
    return result


def _private_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink")
    resolved = path.resolve(strict=True)
    absolute = pathlib.Path(os.path.abspath(path))
    if absolute != resolved:
        raise SystemExit(f"{label} contains a symlink")
    information = resolved.stat()
    if not stat.S_ISDIR(information.st_mode) or information.st_uid != os.getuid():
        raise SystemExit(f"{label} must be an owned directory")
    if stat.S_IMODE(information.st_mode) != 0o700:
        raise SystemExit(f"{label} must use mode 0700")
    return resolved


def _beneath(path: pathlib.Path, root: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.resolve(strict=True)
    absolute = pathlib.Path(os.path.abspath(path))
    if absolute != resolved or (resolved != root and root not in resolved.parents):
        raise SystemExit(f"{label} must be a non-symlink path below case root")
    if any(character in str(resolved) for character in (",", "\n", "\r")):
        raise SystemExit(f"{label} contains an unsafe QEMU path character")
    return resolved


def _regular_private_file(
    path: pathlib.Path, root: pathlib.Path, label: str
) -> pathlib.Path:
    resolved = _beneath(path, root, label)
    information = resolved.stat()
    if not stat.S_ISREG(information.st_mode) or information.st_uid != os.getuid():
        raise SystemExit(f"{label} must be an owned regular file")
    if stat.S_IMODE(information.st_mode) != 0o600:
        raise SystemExit(f"{label} must use mode 0600")
    return resolved


def _metadata(path: pathlib.Path, label: str) -> pathlib.Path:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink")
    information = path.stat()
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o600
        or information.st_size <= 0
        or information.st_size > 4096
    ):
        raise SystemExit(f"{label} must be an owned mode-0600 file")
    return path


def _unix_socket(path: pathlib.Path, label: str) -> pathlib.Path:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink")
    try:
        information = path.stat()
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    if (
        not stat.S_ISSOCK(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o600
    ):
        raise SystemExit(f"{label} must be an owned mode-0600 Unix socket")
    return path


def validate(arguments: argparse.Namespace) -> argparse.Namespace:
    root = _private_directory(arguments.case_root, "case root")
    if arguments.phase == "recovery" and arguments.case not in RECOVERY_CASES:
        raise SystemExit("recovery phase requires a recovery-protocol case")
    if arguments.phase != "recovery" and arguments.case not in LAUNCHER_CASES:
        raise SystemExit("launcher phase requires a launcher case")
    if arguments.case == "pico-absent":
        if arguments.pico != "absent":
            raise SystemExit("pico-absent must omit the Pico")
    elif arguments.pico != "present":
        raise SystemExit("only pico-absent may omit the Pico")

    arguments.case_root = root
    arguments.code = _regular_private_file(arguments.code, root, "OVMF code")
    arguments.variables = _regular_private_file(
        arguments.variables, root, "OVMF variables"
    )
    arguments.disk = _regular_private_file(arguments.disk, root, "raw disk")
    if stat.S_ISBLK(arguments.disk.stat().st_mode) or str(arguments.disk).startswith(
        "/dev/"
    ):
        raise SystemExit("raw disk must not be a block device")
    arguments.esp = _private_directory(
        _beneath(arguments.esp, root, "ESP"), "ESP"
    )
    arguments.swtpm_state = _private_directory(
        _beneath(arguments.swtpm_state, root, "swtpm state"), "swtpm state"
    )
    tpm_state = _private_directory(arguments.swtpm_state / "tpm", "TPM state")
    managed = _metadata(arguments.swtpm_state / "managed", "managed swtpm marker")
    if managed.read_text(encoding="ascii").strip() != "PBNS_SWTPM_STATE_V1":
        raise SystemExit("invalid managed swtpm marker")

    log_parent_input = arguments.log.parent
    log_parent = _private_directory(
        _beneath(log_parent_input, root, "log parent"), "log parent"
    )
    arguments.log = log_parent / arguments.log.name
    if arguments.log.exists() or arguments.log.is_symlink():
        raise SystemExit("serial log must be create-exclusive")
    if arguments.log.name in ("", ".", "..") or any(
        character in arguments.log.name for character in ("/", "\n", "\r")
    ):
        raise SystemExit("invalid serial log name")

    verifier = pathlib.Path(__file__).parents[1] / "swtpm" / "quiesce-swtpm-runtime.py"
    try:
        socket_text = subprocess.check_output(
            [str(verifier), "--verify-live", str(arguments.swtpm_state)], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit("swtpm PID ownership check failed") from error
    socket_path = pathlib.Path(socket_text)
    if socket_path.name != "server.sock":
        raise SystemExit("invalid swtpm server socket name")
    control_path = pathlib.Path(f"{socket_path}.ctrl")
    _unix_socket(socket_path, "swtpm server socket")
    _unix_socket(control_path, "swtpm control socket")
    arguments.swtpm_socket = socket_path
    arguments.swtpm_control = control_path
    return arguments


def verify_pico(
    sysfs_root: pathlib.Path = pathlib.Path("/sys/bus/usb/devices"),
) -> None:
    matches: list[tuple[str, str]] = []
    for device in sysfs_root.glob("*"):
        try:
            vendor = (device / "idVendor").read_text(encoding="ascii").strip().lower()
            product = (device / "idProduct").read_text(encoding="ascii").strip().lower()
            if (vendor, product) != ("cafe", "4011"):
                continue
            serial = (device / "serial").read_text(encoding="utf-8").strip()
            description = (device / "product").read_text(encoding="utf-8").strip()
            matches.append((serial, description))
        except OSError:
            continue
    if matches != [("E66130100F527A26", "PBNS Proxy v1")]:
        raise SystemExit("exact PBNS proxy identity is not present")


def command(arguments: argparse.Namespace, executable: str) -> list[str]:
    result = [
        executable,
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-m",
        "512M",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={arguments.code}",
        "-drive",
        f"if=pflash,format=raw,file={arguments.variables}",
        "-drive",
        f"format=raw,file=fat:rw:{arguments.esp}",
        "-blockdev",
        f"driver=file,filename={arguments.disk},node-name=pbns-file,read-only=on",
        "-blockdev",
        "driver=raw,file=pbns-file,node-name=pbns-disk,read-only=on",
        "-device",
        "virtio-blk-pci,drive=pbns-disk",
        "-chardev",
        f"socket,id=chrtpm,path={arguments.swtpm_control}",
        "-tpmdev",
        "emulator,id=tpm0,chardev=chrtpm",
        "-device",
        "tpm-tis,tpmdev=tpm0",
    ]
    if arguments.pico == "present":
        result.extend(
            [
                "-device",
                "qemu-xhci,id=xhci",
                "-device",
                "usb-host,bus=xhci.0,vendorid=0xcafe,productid=0x4011",
            ]
        )
    result.extend(
        [
            "-nic",
            "none",
            "-display",
            "none",
            "-serial",
            "stdio",
            "-monitor",
            "none",
            "-no-reboot",
        ]
    )
    return result


def _line_complete(output: bytearray, marker: bytes) -> bool:
    offset = output.find(marker)
    return offset >= 0 and output.find(b"\n", offset) >= 0


def _terminal(arguments: argparse.Namespace, output: bytearray) -> bool:
    if arguments.phase == "recovery":
        failure_stages = {
            "unsigned-untrusted": 6,
            "truncated": 6,
            "gateway-interruption": 4,
            "forged-manifest": 2,
            "forged-digest": 5,
            "forged-chunk": 4,
            "downgrade": 5,
        }
        if arguments.case == "signed-trusted":
            return _line_complete(output, b"PBNS RECOVERY READ-ONLY MODE")
        return _line_complete(
            output, f"PBNS RECOVERY FAILED stage={failure_stages[arguments.case]}".encode("ascii")
        )
    if arguments.phase == "launcher-setup":
        return _line_complete(output, b"PBNS BOOT SETUP PASS ")
    normal = output.find(b"PBNS NORMAL FIXTURE PASS")
    fallback = output.find(b"PBNS RECOVERY FALLBACK", normal + 1)
    confirmation = output.find(CONFIRMATION, fallback + 1)
    return normal >= 0 and fallback > normal and confirmation > fallback


def _write_log(path: pathlib.Path, output: bytearray) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(output)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _limit_output_size() -> None:
    limit = 64 * 1024 * 1024
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    if hard != resource.RLIM_INFINITY:
        limit = min(limit, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard))


def _qemu_preexec(expected_parent_pid: int) -> None:
    _limit_output_size()
    if _LIBC is None:
        return
    if _LIBC.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(127)
    # The parent can die between fork and prctl.  Do not exec an independent
    # QEMU if that race reparented this child before PDEATHSIG was installed.
    if os.getppid() != expected_parent_pid:
        os._exit(127)


def _wait_for_exit(process: subprocess.Popen[bytes], timeout: float) -> bool:
    try:
        process.wait(timeout=timeout)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def _cleanup_qemu(process: subprocess.Popen[bytes], output: bytearray) -> str:
    """Bound QEMU shutdown and retain output only after it is known to be dead."""
    exited = False
    failure = ""
    try:
        exited = process.poll() is not None
        if not exited:
            exited = _wait_for_exit(process, INITIAL_EXIT_WAIT_SECONDS)
        if not exited:
            try:
                process.terminate()
            except OSError:
                pass
            exited = _wait_for_exit(process, TERM_CLEANUP_WAIT_SECONDS)
        if not exited:
            try:
                process.kill()
            except OSError:
                pass
            exited = _wait_for_exit(process, KILL_CLEANUP_WAIT_SECONDS)
        if not exited:
            # In particular, do not call stdout.read(): the pipe remains open
            # and that read can block forever while QEMU is still alive.
            failure = "QEMU did not exit during bounded cleanup"
        elif process.stdout is not None:
            try:
                remainder = process.stdout.read(OUTPUT_CAP - len(output) + 1)
                if remainder:
                    output.extend(remainder)
            except OSError:
                failure = "QEMU cleanup did not complete"
    finally:
        # Popen uses unbuffered FileIO streams (bufsize=0), so close is only a
        # descriptor close and never attempts to drain a live QEMU pipe.
        for stream in (process.stdin, process.stdout):
            if stream is None:
                continue
            try:
                stream.close()
            except OSError:
                failure = "QEMU cleanup did not complete"
    return failure


def run(
    arguments: argparse.Namespace,
    *,
    executable: str = "qemu-system-x86_64",
    pico_validator: Callable[[], None] = verify_pico,
    deadline_seconds: float = 2760.0,
) -> None:
    # signal.signal is process-global and Python only permits changing it from
    # the main thread.  Reject before validation/launch can install a handler.
    if threading.current_thread() is not threading.main_thread():
        raise SystemExit("recovery live driver must run in the main thread")
    arguments = validate(arguments)
    if arguments.pico == "present":
        pico_validator()
    if shutil.which(executable) is None and not pathlib.Path(executable).is_file():
        raise SystemExit("QEMU executable is unavailable")

    termination_signal: int | None = None

    def request_termination(signum: int, _frame: object) -> None:
        nonlocal termination_signal
        termination_signal = signum

    # TERM must drive the QEMU cleanup below rather than terminate this process
    # immediately.  This is restored by the single outer finally for every
    # launch, polling, cleanup, stream, audit, and log-writing failure.
    previous_term_handler = signal.signal(signal.SIGTERM, request_termination)
    try:
        process: subprocess.Popen[bytes] | None = None
        output = bytearray()
        confirmation_sent = False
        assurance_sent = False
        setup_sent = False
        terminal_seen = False
        failure = ""
        deadline = time.monotonic() + deadline_seconds
        try:
            if termination_signal is None:
                process = subprocess.Popen(
                    command(arguments, executable),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                    preexec_fn=functools.partial(_qemu_preexec, os.getpid()),
                )
            while (
                process is not None
                and termination_signal is None
                and process.poll() is None
                and time.monotonic() < deadline
            ):
                assert process.stdout is not None
                readable, _, _ = select.select(
                    [process.stdout], [], [], INITIAL_EXIT_WAIT_SECONDS
                )
                if not readable:
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                if len(output) + len(chunk) > OUTPUT_CAP:
                    failure = "QEMU serial output exceeded the bound"
                    break
                output.extend(chunk)
                assert process.stdin is not None
                if arguments.phase == "recovery":
                    confirmation_offset = output.find(CONFIRMATION)
                    if not confirmation_sent and confirmation_offset >= 0:
                        process.stdin.write(b"RECOVER\r")
                        process.stdin.flush()
                        confirmation_sent = True
                    assurance_offset = output.find(
                        ASSURANCE,
                        confirmation_offset + len(CONFIRMATION)
                        if confirmation_offset >= 0
                        else 0,
                    )
                    if confirmation_sent and not assurance_sent and assurance_offset >= 0:
                        process.stdin.write(b"T")
                        process.stdin.flush()
                        assurance_sent = True
                elif arguments.phase == "launcher-setup" and not setup_sent:
                    matches = list(NORMAL_LINE.finditer(output))
                    if matches:
                        prompt_offset = output.find(b"> ", matches[-1].end())
                        if prompt_offset >= 0:
                            if len(matches) != 1:
                                failure = "normal fixture boot option is not unique"
                                break
                            process.stdin.write(matches[0].group(1) + b"\r")
                            process.stdin.flush()
                            setup_sent = True
                if _terminal(arguments, output):
                    terminal_seen = True
                    break
            if termination_signal is not None:
                failure = "recovery live driver received SIGTERM"
            elif not terminal_seen and not failure:
                failure = "phase-specific QEMU terminal marker was not observed"
            if termination_signal is None and arguments.phase == "recovery" and (
                not confirmation_sent or not assurance_sent
            ):
                failure = "recovery prompts were not completed"
            if (
                termination_signal is None
                and arguments.phase == "launcher-setup"
                and not setup_sent
            ):
                failure = "normal fixture boot option was not selected"
        finally:
            if process is not None:
                cleanup_failure = _cleanup_qemu(process, output)
                if cleanup_failure:
                    failure = cleanup_failure

        try:
            if termination_signal is not None:
                failure = "recovery live driver received SIGTERM"
            if len(output) > OUTPUT_CAP:
                raise SystemExit("QEMU serial output exceeded the bound")
            if FORBIDDEN_LOG.search(output):
                raise SystemExit("QEMU serial output failed the secret audit")
            _write_log(arguments.log, output)
        finally:
            output[:] = b"\x00" * len(output)
        if failure:
            raise SystemExit(failure)
        if process is None:
            raise SystemExit("QEMU was not started")
        if process.returncode not in (0, -15):
            raise SystemExit(f"QEMU exited unexpectedly: {process.returncode}")
    finally:
        signal.signal(signal.SIGTERM, previous_term_handler)


def main() -> None:
    run(parser().parse_args())


if __name__ == "__main__":
    main()
