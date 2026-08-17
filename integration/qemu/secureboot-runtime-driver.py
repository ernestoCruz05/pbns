#!/usr/bin/env python3
import argparse
import importlib.util
import os
import pathlib
import re
import resource
import select
import shutil
import stat
import subprocess
import time
from collections.abc import Callable


OUTPUT_CAP = 8 * 1024 * 1024
FORBIDDEN_LOG = re.compile(
    rb"private[\s_-]*key|identity[\s_-]*(?:material|key|cose)|"
    rb"tpm[\s_-]*(?:blob|auth|authorization|session|nonce)|"
    rb"auth[\s_-]*value|session[\s_-]*nonce|token|nonce|"
    rb"decrypted[\s_-]*transcript|policy[\s_-]*(?:authorization|internal)|"
    rb"artifact[\s_-]*bytes|transient[\s_-]*crypto",
    re.IGNORECASE,
)


def _load_oracle() -> Callable[[str], None]:
    path = pathlib.Path(__file__).with_name("verify-secureboot-preflight.py")
    spec = importlib.util.spec_from_file_location("pbns_secureboot_oracle", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("secure boot oracle is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_serial


validate_serial = _load_oracle()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--case-root", type=pathlib.Path, required=True)
    result.add_argument("--code", type=pathlib.Path, required=True)
    result.add_argument("--variables", type=pathlib.Path, required=True)
    result.add_argument("--esp", type=pathlib.Path, required=True)
    result.add_argument("--log", type=pathlib.Path, required=True)
    return result


def _private_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink")
    resolved = path.resolve(strict=True)
    information = resolved.stat()
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        raise SystemExit(f"{label} must be an owned mode-0700 directory")
    return resolved


def _beneath(path: pathlib.Path, root: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.resolve(strict=True)
    absolute = pathlib.Path(os.path.abspath(path))
    if absolute != resolved or (resolved != root and root not in resolved.parents):
        raise SystemExit(f"{label} must be a non-symlink path below case root")
    if any(character in str(resolved) for character in (",", "\n", "\r")):
        raise SystemExit(f"{label} contains an unsafe QEMU path character")
    return resolved


def _private_file(path: pathlib.Path, root: pathlib.Path, label: str) -> pathlib.Path:
    resolved = _beneath(path, root, label)
    information = resolved.stat()
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o600
    ):
        raise SystemExit(f"{label} must be an owned mode-0600 regular file")
    return resolved


def validate(arguments: argparse.Namespace) -> argparse.Namespace:
    root = _private_directory(arguments.case_root, "case root")
    arguments.case_root = root
    arguments.code = _private_file(arguments.code, root, "OVMF code")
    arguments.variables = _private_file(
        arguments.variables, root, "OVMF variables"
    )
    arguments.esp = _private_directory(
        _beneath(arguments.esp, root, "ESP"), "ESP"
    )
    log_parent = _private_directory(
        _beneath(arguments.log.parent, root, "log parent"), "log parent"
    )
    arguments.log = log_parent / arguments.log.name
    if arguments.log.exists() or arguments.log.is_symlink():
        raise SystemExit("Secure Boot runtime log must be create-exclusive")
    if arguments.log.name in ("", ".", "..") or any(
        character in arguments.log.name for character in ("/", "\n", "\r")
    ):
        raise SystemExit("invalid Secure Boot runtime log name")
    return arguments


def command(arguments: argparse.Namespace, executable: str) -> list[str]:
    return [
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


def _limit_output_size() -> None:
    limit = 64 * 1024 * 1024
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    if hard != resource.RLIM_INFINITY:
        limit = min(limit, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard))


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


def run(
    arguments: argparse.Namespace,
    *,
    executable: str = "qemu-system-x86_64",
    deadline_seconds: float = 45.0,
    term_timeout: float = 5.0,
    kill_timeout: float = 5.0,
) -> None:
    arguments = validate(arguments)
    if shutil.which(executable) is None and not pathlib.Path(executable).is_file():
        raise SystemExit("QEMU executable is unavailable")
    process = subprocess.Popen(
        command(arguments, executable),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        preexec_fn=_limit_output_size,
    )
    assert process.stdout is not None
    output = bytearray()
    failure = ""
    deadline = time.monotonic() + deadline_seconds
    try:
        while process.poll() is None and time.monotonic() < deadline:
            readable, _, _ = select.select([process.stdout], [], [], 0.2)
            if not readable:
                continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            if len(output) + len(chunk) > OUTPUT_CAP:
                failure = "QEMU serial output exceeded the bound"
                break
            output.extend(chunk)
        if process.poll() is None and not failure:
            failure = "Secure Boot QEMU deadline expired"
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=term_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=kill_timeout)
                except subprocess.TimeoutExpired:
                    failure = "QEMU child did not stop after SIGKILL"
        if process.poll() is not None:
            remainder = process.stdout.read(OUTPUT_CAP - len(output) + 1)
            if remainder:
                output.extend(remainder)
        process.stdout.close()
    if len(output) > OUTPUT_CAP:
        failure = "QEMU serial output exceeded the bound"
    if FORBIDDEN_LOG.search(output):
        output[:] = b"\x00" * len(output)
        diagnostic = bytearray(b"PBNS SECUREBOOT RUNTIME REJECT\n")
        _write_log(arguments.log, diagnostic)
        diagnostic[:] = b"\x00" * len(diagnostic)
        raise SystemExit("QEMU serial output failed the secret audit")
    _write_log(arguments.log, output[:OUTPUT_CAP])
    try:
        validate_serial(output[:OUTPUT_CAP].decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError) as error:
        failure = f"Secure Boot runtime oracle failed: {error}"
    output[:] = b"\x00" * len(output)
    if failure:
        raise SystemExit(failure)
    if process.returncode != 0:
        raise SystemExit(f"QEMU exited unexpectedly: {process.returncode}")


def main() -> None:
    run(parser().parse_args())


if __name__ == "__main__":
    main()
