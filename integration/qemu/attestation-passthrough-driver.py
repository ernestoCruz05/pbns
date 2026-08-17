#!/usr/bin/env python3
import argparse
import os
import pathlib
import re
import select
import signal
import stat
import subprocess
import sys
import time


EXPECTED_VENDOR = "cafe"
EXPECTED_PRODUCT_ID = "4011"
EXPECTED_PRODUCT = "PBNS Proxy v1"
EXPECTED_SERIAL = "E66130100F527A26"
EXPECTED_BCD_DEVICE = "0100"
OUTPUT_CAP = 8 * 1024 * 1024


class SelectionError(RuntimeError):
    pass


def read_attribute(device: pathlib.Path, name: str) -> str | None:
    try:
        with (device / name).open("r", encoding="ascii", errors="strict") as stream:
            return stream.read(256).strip()
    except (FileNotFoundError, NotADirectoryError, UnicodeError, OSError):
        return None


def matching_picos(sysfs: pathlib.Path) -> list[tuple[int, int, pathlib.Path]]:
    if not sysfs.is_dir():
        raise SelectionError("USB sysfs root is unavailable")
    matches: list[tuple[int, int, pathlib.Path]] = []
    for device in sorted(sysfs.iterdir(), key=lambda item: item.name):
        values = {
            name: read_attribute(device, name)
            for name in (
                "idVendor",
                "idProduct",
                "product",
                "serial",
                "bcdDevice",
                "busnum",
                "devnum",
            )
        }
        if (
            values["idVendor"] != EXPECTED_VENDOR
            or values["idProduct"] != EXPECTED_PRODUCT_ID
            or values["product"] != EXPECTED_PRODUCT
            or values["serial"] != EXPECTED_SERIAL
            or values["bcdDevice"] != EXPECTED_BCD_DEVICE
        ):
            continue
        try:
            bus = int(values["busnum"] or "", 10)
            address = int(values["devnum"] or "", 10)
        except ValueError as error:
            raise SelectionError("matching Pico has invalid bus/address") from error
        if not (1 <= bus <= 255 and 1 <= address <= 255):
            raise SelectionError("matching Pico bus/address is out of range")
        matches.append((bus, address, device))
    return matches


def select_pico(sysfs: pathlib.Path) -> tuple[int, int]:
    matches = matching_picos(sysfs)
    if len(matches) != 1:
        raise SelectionError(f"expected exactly one PBNS Pico, found {len(matches)}")
    return matches[0][0], matches[0][1]


def validate_selected_pico(sysfs: pathlib.Path, hostbus: int, hostaddr: int) -> pathlib.Path:
    matches = matching_picos(sysfs)
    if len(matches) != 1 or matches[0][:2] != (hostbus, hostaddr):
        raise SelectionError("selected PBNS Pico identity or bus/address changed")
    return matches[0][2]


def pico_device_nodes(
    sysfs: pathlib.Path, usbfs: pathlib.Path, hostbus: int, hostaddr: int
) -> list[pathlib.Path]:
    device = validate_selected_pico(sysfs, hostbus, hostaddr)
    nodes = [usbfs / f"{hostbus:03d}" / f"{hostaddr:03d}"]
    tty_names = sorted({item.name for item in device.rglob("ttyACM*")})
    nodes.extend(pathlib.Path("/dev") / name for name in tty_names)
    return nodes


def checked_device_ids(nodes: list[pathlib.Path], require_ttys: bool) -> set[int]:
    if not nodes or (require_ttys and len(nodes) < 3):
        raise SelectionError("selected PBNS Pico CDC devices are unavailable")
    identifiers: set[int] = set()
    for device in nodes:
        try:
            target = device.stat()
        except OSError as error:
            raise SelectionError("selected USB device node is unavailable") from error
        if not stat.S_ISCHR(target.st_mode):
            raise SelectionError("selected USB device node is not a character device")
        identifiers.add(target.st_rdev)
    return identifiers


def ensure_usb_device_unowned(
    sysfs: pathlib.Path, usbfs: pathlib.Path, hostbus: int, hostaddr: int
) -> None:
    targets = checked_device_ids(
        pico_device_nodes(sysfs, usbfs, hostbus, hostaddr), require_ttys=True
    )
    for process in pathlib.Path("/proc").iterdir():
        if not process.name.isdigit() or int(process.name, 10) == os.getpid():
            continue
        try:
            descriptors = list((process / "fd").iterdir())
        except (FileNotFoundError, PermissionError, OSError):
            continue
        for descriptor in descriptors:
            try:
                opened = descriptor.stat()
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if stat.S_ISCHR(opened.st_mode) and opened.st_rdev in targets:
                raise SelectionError("selected PBNS Pico is open by an unrelated process")


def wait_for_pico_return(
    sysfs: pathlib.Path,
    usbfs: pathlib.Path,
    hostbus: int,
    hostaddr: int,
    timeout_seconds: float = 10.0,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    if not (1 <= hostbus <= 255 and 1 <= hostaddr <= 255):
        return False
    while time.monotonic() < deadline:
        try:
            matches = matching_picos(sysfs)
            if len(matches) != 1 or matches[0][0] != hostbus:
                raise SelectionError("PBNS Pico did not return on its USB bus")
            restored_bus, restored_address, _ = matches[0]
            checked_device_ids(
                pico_device_nodes(sysfs, usbfs, restored_bus, restored_address),
                require_ttys=True,
            )
            return True
        except SelectionError:
            time.sleep(0.05)
    return False


def build_qemu_command(
    *,
    code: pathlib.Path,
    variables: pathlib.Path,
    esp: pathlib.Path,
    swtpm_control: pathlib.Path,
    hostbus: int,
    hostaddr: int,
) -> list[str]:
    if not (1 <= hostbus <= 255 and 1 <= hostaddr <= 255):
        raise ValueError("invalid USB bus/address")
    return [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-m",
        "512M",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive",
        f"if=pflash,format=raw,file={variables}",
        "-drive",
        f"format=raw,file=fat:rw:{esp}",
        "-device",
        "qemu-xhci,id=xhci",
        "-device",
        f"usb-host,bus=xhci.0,hostbus={hostbus},hostaddr={hostaddr}",
        "-chardev",
        f"socket,id=chrtpm,path={swtpm_control}",
        "-tpmdev",
        "emulator,id=tpm0,chardev=chrtpm",
        "-device",
        "tpm-tis,tpmdev=tpm0",
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


def write_exclusive(path: pathlib.Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(value)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("short log write")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def enrollment_result_error(
    output: bytes | bytearray, returncode: int | None, mode_sent: bool, token_sent: bool
) -> str | None:
    if len(output) > OUTPUT_CAP:
        return "QEMU serial output exceeded the bound"
    if not mode_sent or not token_sent:
        return "enrollment prompts were incomplete"
    if b"PBNS ENROLL FAIL" in output:
        return "firmware reported an enrollment failure"
    if b"PBNS ENROLL TPM CHECKPOINT PASS" not in output:
        return "missing enrollment serial checkpoint"
    returns = re.findall(
        rb"(?:^|[\r\n])PBNS ENROLL EFI RETURN (0|0x0+)(?=[\r\n]|$)", output
    )
    if len(returns) != 1:
        return "missing successful post-cleanup EFI return"
    if returncode != 0:
        return f"QEMU exited unexpectedly: {returncode}"
    return None


def redact_token(output: bytearray, token: bytearray) -> bool:
    if not token:
        return False
    found = False
    start = 0
    replacement = b"*" * len(token)
    while True:
        offset = output.find(token, start)
        if offset < 0:
            return found
        output[offset : offset + len(token)] = replacement
        start = offset + len(token)
        found = True


def live_process_group_exists(group: int) -> bool:
    for process in pathlib.Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            fields = (process / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            state = fields[0]
            process_group = int(fields[2], 10)
        except (FileNotFoundError, PermissionError, OSError, IndexError, ValueError):
            continue
        if process_group == group and state != b"Z":
            return True
    return False


def wait_for_process_group(
    process: subprocess.Popen[bytes], group: int, timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        process.poll()
        if not live_process_group_exists(group):
            return True
        time.sleep(0.05)
    process.poll()
    return not live_process_group_exists(group)


def exact_serial_line_count(output: bytes | bytearray, marker: bytes) -> int:
    return len(
        re.findall(rb"(?:^|[\r\n])" + re.escape(marker) + rb"(?=[\r\n]|$)", output)
    )


def attestation_preflight_error(output: bytes | bytearray, returncode: int | None) -> str | None:
    if len(output) > OUTPUT_CAP:
        return "QEMU serial output exceeded the bound"
    if exact_serial_line_count(output, b"PBNS ATTEST FULL VERIFIED") != 0 or exact_serial_line_count(
        output, b"PBNS ATTEST REDUCED VERIFIED"
    ) != 0:
        return "preflight displayed an authenticated receipt"
    expected_failure = b"PBNS ATTEST FAILURE run status=-14 command=0x00000000"
    if exact_serial_line_count(output, expected_failure) != 1:
        return "missing expected baseline authentication rejection"
    returns = re.findall(
        rb"(?:^|[\r\n])PBNS ATTEST EFI RETURN 0x1A(?=[\r\n]|$)", output
    )
    if len(returns) != 1:
        return "missing expected baseline rejection EFI return"
    if returncode != 0:
        return f"QEMU exited unexpectedly: {returncode}"
    return None


def attestation_result_error(output: bytes | bytearray, returncode: int | None) -> str | None:
    if len(output) > OUTPUT_CAP:
        return "QEMU serial output exceeded the bound"
    if b"PBNS ATTEST FAILURE" in output:
        return "firmware reported an attestation failure"
    if exact_serial_line_count(output, b"PBNS ATTEST FULL VERIFIED") != 1:
        return "missing unique authenticated full receipt"
    returns = re.findall(
        rb"(?:^|[\r\n])PBNS ATTEST EFI RETURN (0|0x0+)(?=[\r\n]|$)", output
    )
    if len(returns) != 1:
        return "missing successful post-cleanup EFI return"
    if returncode != 0:
        return f"QEMU exited unexpectedly: {returncode}"
    return None


def stop_process(
    process: subprocess.Popen[bytes],
    *,
    term_timeout: float = 5.0,
    kill_timeout: float = 5.0,
) -> bool:
    group = process.pid
    if not live_process_group_exists(group):
        process.poll()
        return True
    try:
        os.killpg(group, signal.SIGTERM)
    except ProcessLookupError:
        process.poll()
        return True
    if wait_for_process_group(process, group, term_timeout):
        return True
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        process.poll()
        return True
    return wait_for_process_group(process, group, kill_timeout)


def drain_available(stream: object, output: bytearray) -> bool:
    overflow = False
    while True:
        readable, _, _ = select.select([stream], [], [], 0)
        if not readable:
            break
        chunk = os.read(stream.fileno(), 4096)  # type: ignore[attr-defined]
        if not chunk:
            break
        remaining = OUTPUT_CAP + 1 - len(output)
        output.extend(chunk[:remaining])
        if len(chunk) > remaining or len(output) > OUTPUT_CAP:
            overflow = True
            break
    return overflow


def run_enrollment(arguments: argparse.Namespace) -> None:
    token = bytearray(sys.stdin.buffer.readline(45))
    if token.endswith(b"\n"):
        token.pop()
    if token.endswith(b"\r"):
        token.pop()
    if len(token) != 43:
        token[:] = b"\x00" * len(token)
        raise SystemExit("enrollment token input has invalid length")
    output = bytearray()
    mode_marker = b"PBNS ENROLL MODE: S=explicit reduced software, T=explicit TPM"
    token_marker = b"PBNS ENROLL TOKEN READY (input hidden)"
    mode_sent = False
    token_sent = False
    failure = ""
    caught_signal = 0
    process: subprocess.Popen[bytes] | None = None
    handled_signals = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    previous_handlers: dict[signal.Signals, object] = {}

    def request_stop(signum: int, frame: object) -> None:
        del frame
        nonlocal caught_signal
        caught_signal = signum

    for handled_signal in handled_signals:
        previous_handlers[handled_signal] = signal.getsignal(handled_signal)
        signal.signal(handled_signal, request_stop)
    try:
        ensure_usb_device_unowned(
            arguments.sysfs, arguments.usbfs, arguments.hostbus, arguments.hostaddr
        )
        if caught_signal:
            failure = f"driver interrupted by signal {caught_signal}"
        else:
            command = build_qemu_command(
                code=arguments.code,
                variables=arguments.variables,
                esp=arguments.esp,
                swtpm_control=arguments.swtpm_control,
                hostbus=arguments.hostbus,
                hostaddr=arguments.hostaddr,
            )
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                start_new_session=True,
            )
            assert process.stdin is not None and process.stdout is not None
            deadline = time.monotonic() + arguments.timeout
            while process.poll() is None and time.monotonic() < deadline:
                if caught_signal:
                    failure = f"driver interrupted by signal {caught_signal}"
                    break
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
                    process.stdin.write(b"T")
                    process.stdin.flush()
                    mode_sent = True
                if mode_sent and not token_sent and token_marker in output:
                    process.stdin.write(token + b"\r")
                    process.stdin.flush()
                    token_sent = True
            if process.poll() is None and time.monotonic() >= deadline:
                failure = "QEMU enrollment deadline expired"
    finally:
        stopped = process is None or process.poll() is not None
        if process is not None:
            if process.poll() is None:
                stopped = stop_process(process)
                if not stopped:
                    failure = "QEMU child did not stop after SIGKILL"
            if drain_available(process.stdout, output):
                failure = "QEMU serial output exceeded the bound"
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            process.stdout.close()
        if stopped and not wait_for_pico_return(
            arguments.sysfs, arguments.usbfs, arguments.hostbus, arguments.hostaddr
        ):
            failure = "PBNS Pico was not restored to the host"
        token_leaked = redact_token(output, token)
        token[:] = b"\x00" * len(token)
        if token_leaked:
            failure = "serial output leaked enrollment token"
        for handled_signal, previous in previous_handlers.items():
            signal.signal(handled_signal, previous)
        write_exclusive(arguments.log, bytes(output[:OUTPUT_CAP]))

    returncode = process.returncode if process is not None else None
    result_error = enrollment_result_error(output, returncode, mode_sent, token_sent)
    if not failure and result_error is not None:
        failure = result_error
    output[:] = b"\x00" * len(output)
    if failure:
        raise SystemExit(failure)


def run_attestation(arguments: argparse.Namespace) -> None:
    ensure_usb_device_unowned(
        arguments.sysfs, arguments.usbfs, arguments.hostbus, arguments.hostaddr
    )
    process = subprocess.Popen(
        build_qemu_command(
            code=arguments.code,
            variables=arguments.variables,
            esp=arguments.esp,
            swtpm_control=arguments.swtpm_control,
            hostbus=arguments.hostbus,
            hostaddr=arguments.hostaddr,
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,
    )
    assert process.stdout is not None
    output = bytearray()
    failure = ""
    caught_signal = 0
    previous_handlers: dict[signal.Signals, object] = {}

    def request_stop(signum: int, frame: object) -> None:
        del frame
        nonlocal caught_signal
        caught_signal = signum

    for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous_handlers[handled_signal] = signal.getsignal(handled_signal)
        signal.signal(handled_signal, request_stop)
    deadline = time.monotonic() + arguments.timeout
    try:
        while process.poll() is None and time.monotonic() < deadline:
            if caught_signal:
                failure = f"driver interrupted by signal {caught_signal}"
                break
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
        if process.poll() is None and time.monotonic() >= deadline:
            failure = "QEMU attestation deadline expired"
    finally:
        if process.poll() is None and not stop_process(process):
            failure = "QEMU child did not stop after SIGKILL"
        if drain_available(process.stdout, output):
            failure = "QEMU serial output exceeded the bound"
        process.stdout.close()
        if not wait_for_pico_return(
            arguments.sysfs, arguments.usbfs, arguments.hostbus, arguments.hostaddr
        ):
            failure = "PBNS Pico was not restored to the host"
        for handled_signal, previous in previous_handlers.items():
            signal.signal(handled_signal, previous)
        write_exclusive(arguments.log, bytes(output[:OUTPUT_CAP]))
    result_error = (
        attestation_preflight_error(output, process.returncode)
        if arguments.expect_preflight
        else attestation_result_error(output, process.returncode)
    )
    output[:] = b"\x00" * len(output)
    if not failure and result_error is not None:
        failure = result_error
    if failure:
        raise SystemExit(failure)


def existing_absolute_file(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise argparse.ArgumentTypeError("expected absolute regular file")
    return path


def existing_absolute_directory(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise argparse.ArgumentTypeError("expected absolute directory")
    return path


def absolute_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise argparse.ArgumentTypeError("expected absolute non-symlink path")
    return path


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    select_parser = subparsers.add_parser("select-pico")
    select_parser.add_argument(
        "--sysfs", type=existing_absolute_directory, default=pathlib.Path("/sys/bus/usb/devices")
    )
    run_parser = subparsers.add_parser("run-enrollment")
    run_parser.add_argument("--code", type=existing_absolute_file, required=True)
    run_parser.add_argument("--variables", type=existing_absolute_file, required=True)
    run_parser.add_argument("--esp", type=existing_absolute_directory, required=True)
    run_parser.add_argument("--swtpm-control", type=absolute_path, required=True)
    run_parser.add_argument("--hostbus", type=int, required=True)
    run_parser.add_argument("--hostaddr", type=int, required=True)
    run_parser.add_argument(
        "--sysfs", type=existing_absolute_directory, default=pathlib.Path("/sys/bus/usb/devices")
    )
    run_parser.add_argument(
        "--usbfs", type=existing_absolute_directory, default=pathlib.Path("/dev/bus/usb")
    )
    run_parser.add_argument("--log", type=absolute_path, required=True)
    run_parser.add_argument("--timeout", type=int, default=240)
    attest_parser = subparsers.add_parser("run-attestation")
    attest_parser.add_argument("--code", type=existing_absolute_file, required=True)
    attest_parser.add_argument("--variables", type=existing_absolute_file, required=True)
    attest_parser.add_argument("--esp", type=existing_absolute_directory, required=True)
    attest_parser.add_argument("--swtpm-control", type=absolute_path, required=True)
    attest_parser.add_argument("--hostbus", type=int, required=True)
    attest_parser.add_argument("--hostaddr", type=int, required=True)
    attest_parser.add_argument(
        "--sysfs", type=existing_absolute_directory, default=pathlib.Path("/sys/bus/usb/devices")
    )
    attest_parser.add_argument(
        "--usbfs", type=existing_absolute_directory, default=pathlib.Path("/dev/bus/usb")
    )
    attest_parser.add_argument("--log", type=absolute_path, required=True)
    attest_parser.add_argument("--timeout", type=int, default=240)
    attest_parser.add_argument("--expect-preflight", action="store_true")
    return result


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "select-pico":
        try:
            bus, address = select_pico(arguments.sysfs)
        except SelectionError as error:
            raise SystemExit(str(error)) from error
        print(f"hostbus={bus}")
        print(f"hostaddr={address}")
        return
    try:
        if arguments.command == "run-enrollment":
            run_enrollment(arguments)
        else:
            run_attestation(arguments)
    except SelectionError as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
