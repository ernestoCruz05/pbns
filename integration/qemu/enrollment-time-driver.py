#!/usr/bin/env python3
import argparse
import os
import pathlib
import select
import subprocess
import sys
import time


OUTPUT_CAP = 8 * 1024 * 1024


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--phase", choices=("enrollment", "time"), required=True)
    result.add_argument("--mode", choices=("s", "t"), required=True)
    result.add_argument("--code", type=pathlib.Path, required=True)
    result.add_argument("--variables", type=pathlib.Path, required=True)
    result.add_argument("--esp", type=pathlib.Path, required=True)
    result.add_argument("--swtpm-control", type=pathlib.Path)
    result.add_argument("--log", type=pathlib.Path, required=True)
    return result


def command(arguments: argparse.Namespace) -> list[str]:
    result = [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-m",
        "256M",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={arguments.code}",
        "-drive",
        f"if=pflash,format=raw,file={arguments.variables}",
        "-drive",
        f"format=raw,file=fat:rw:{arguments.esp}",
        "-device",
        "qemu-xhci,id=xhci",
        "-device",
        "usb-host,bus=xhci.0,vendorid=0xcafe,productid=0x4011",
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
    if arguments.swtpm_control is not None:
        result.extend(
            [
                "-chardev",
                f"socket,id=chrtpm,path={arguments.swtpm_control}",
                "-tpmdev",
                "emulator,id=tpm0,chardev=chrtpm",
                "-device",
                "tpm-tis,tpmdev=tpm0",
            ]
        )
    return result


def run(arguments: argparse.Namespace) -> None:
    token = bytearray()
    if arguments.phase == "enrollment":
        token.extend(sys.stdin.buffer.readline().strip())
        if len(token) != 43:
            token[:] = b"\x00" * len(token)
            raise SystemExit("enrollment token input has invalid length")
        mode_marker = b"PBNS ENROLL MODE: S=explicit reduced software, T=explicit TPM"
        token_marker = b"PBNS ENROLL TOKEN READY (input hidden)"
        terminal = (
            b"PBNS ENROLL TPM CHECKPOINT PASS"
            if arguments.mode == "t"
            else b"PBNS ENROLL SOFTWARE CHECKPOINT PASS"
        )
    else:
        mode_marker = b"PBNS TIME MODE: S=enrolled reduced software, T=enrolled TPM"
        token_marker = b""
        terminal = b"PBNS TIME LIVE REPLAY REJECT PASS"

    process = subprocess.Popen(
        command(arguments),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    assert process.stdin is not None and process.stdout is not None
    output = bytearray()
    mode_sent = False
    token_sent = False
    terminal_offset = -1
    failure = ""
    deadline = time.monotonic() + 180
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
            if not mode_sent and mode_marker in output:
                process.stdin.write(arguments.mode.encode("ascii"))
                process.stdin.flush()
                mode_sent = True
            if (
                arguments.phase == "enrollment"
                and mode_sent
                and not token_sent
                and token_marker in output
            ):
                process.stdin.write(token + b"\r")
                process.stdin.flush()
                token_sent = True
            if terminal_offset < 0:
                terminal_offset = output.find(terminal)
            if terminal_offset >= 0 and output.find(b"\n", terminal_offset) >= 0:
                break
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    failure = "QEMU child did not stop after SIGKILL"
        if process.poll() is not None:
            remainder = process.stdout.read(OUTPUT_CAP - len(output) + 1)
            if remainder:
                output.extend(remainder)
        process.stdin.close()
        process.stdout.close()
        if len(output) > OUTPUT_CAP:
            failure = "QEMU serial output exceeded the bound"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(arguments.log, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(output[:OUTPUT_CAP])
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    if failure:
        token[:] = b"\x00" * len(token)
        output[:] = b"\x00" * len(output)
        raise SystemExit(failure)
    if not mode_sent or terminal not in output:
        token[:] = b"\x00" * len(token)
        raise SystemExit(f"missing {arguments.phase} serial checkpoint")
    if arguments.phase == "enrollment":
        if not token_sent:
            token[:] = b"\x00" * len(token)
            raise SystemExit("enrollment token was not delivered")
        if bytes(token) in output:
            token[:] = b"\x00" * len(token)
            raise SystemExit("serial output leaked enrollment token")
    token[:] = b"\x00" * len(token)
    if process.returncode not in (0, -15):
        raise SystemExit(f"QEMU exited unexpectedly: {process.returncode}")


if __name__ == "__main__":
    run(parser().parse_args())
