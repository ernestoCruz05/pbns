#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time


try:
    from pbns.integration.tls.test_identity import (  # noqa: E402
        TLSIdentityError,
        TLS_FIXTURES,
        certificate_spki_sha256 as _shared_certificate_spki_sha256,
        make_matching_certificate as _shared_make_matching_certificate,
    )
except ModuleNotFoundError:
    tls_dir = pathlib.Path(__file__).resolve().parents[1] / "tls"
    sys.path.insert(0, str(tls_dir))
    from test_identity import (  # type: ignore
        TLSIdentityError,
        TLS_FIXTURES,
        certificate_spki_sha256 as _shared_certificate_spki_sha256,
        make_matching_certificate as _shared_make_matching_certificate,
    )


USB_VENDOR = "cafe"
USB_PRODUCT = "40d1"
USB_PRODUCT_NAME = "PBNS Network Diagnostic v1"
INITIAL_BCD_DEVICE = "9100"
EXPECTED_CODES = {
    "9110": "credential-failure",
    "9120": "network-init-failure",
    "9130": "dtr-timeout",
    "9140": "wifi-start-failure",
    "9141": "wifi-authentication-failure",
    "9142": "wifi-link-failure",
    "9143": "wifi-timeout",
    "9150": "tcp-failure",
    "9151": "tcp-timeout",
    "9160": "tls-failure",
    "9161": "tls-timeout",
    "9170": "wifi-timeout-down",
    "9171": "wifi-timeout-join",
    "9172": "wifi-timeout-noip",
    "9173": "wifi-timeout-unknown",
    "9190": "tls-ready",
    "9199": "internal-failure",
}
PRE_TCP_CODES = frozenset(
    ("9110", "9120", "9130", "9140", "9141", "9142", "9143", "9170", "9171", "9172", "9173")
)
TCP_CODES = frozenset(("9150", "9151"))
TLS_CODES = frozenset(("9160", "9161"))
PUBLIC_EVENTS = frozenset(("tcp-accepted", "tls-established"))
SENSITIVE_NAMES = ("ssid", "psk", "password", "credential", "secret", "payload")
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
USB_SERIAL = re.compile(r"[0-9A-F]+")
BCD_DEVICE = re.compile(r"[0-9a-f]{4}")
PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
LOOPBACK_HARNESS = PBNS_ROOT / "integration" / "hil" / "pico-loopback.py"


class DiagnosticError(Exception):
    pass


def _read_sysfs_value(device: pathlib.Path, name: str) -> str:
    try:
        return (device / name).read_text(encoding="ascii").strip()
    except OSError as error:
        raise DiagnosticError("cannot read diagnostic USB identity") from error


def _has_exact_cdc_profile(
    devices: list[pathlib.Path], device: pathlib.Path
) -> bool:
    try:
        if _read_sysfs_value(device, "bNumInterfaces") != "2":
            return False
    except DiagnosticError:
        return False
    profile: list[tuple[str, str]] = []
    prefix = f"{device.name}:"
    for interface in devices:
        if not interface.is_dir() or not interface.name.startswith(prefix):
            continue
        try:
            profile.append(
                (
                    _read_sysfs_value(interface, "bInterfaceNumber").lower(),
                    _read_sysfs_value(interface, "bInterfaceClass").lower(),
                )
            )
        except DiagnosticError:
            return False
    return sorted(profile) == [("00", "02"), ("01", "0a")]


def verify_diagnostic_identity(
    sysfs_root: pathlib.Path,
    *,
    expected_serial: str,
    allowed_bcd: frozenset[str],
) -> dict[str, str]:
    if USB_SERIAL.fullmatch(expected_serial) is None or not allowed_bcd:
        raise DiagnosticError("invalid expected diagnostic identity")
    if any(BCD_DEVICE.fullmatch(code) is None for code in allowed_bcd):
        raise DiagnosticError("invalid expected diagnostic result code")
    try:
        devices = sorted(sysfs_root.iterdir())
    except OSError as error:
        raise DiagnosticError("cannot enumerate USB devices") from error
    matches: list[tuple[pathlib.Path, dict[str, str]]] = []
    for device in devices:
        if not device.is_dir() or not (device / "idVendor").is_file():
            continue
        try:
            identity = {
                "vendor": _read_sysfs_value(device, "idVendor").lower(),
                "product_id": _read_sysfs_value(device, "idProduct").lower(),
                "bcd_device": _read_sysfs_value(device, "bcdDevice").lower(),
                "product": _read_sysfs_value(device, "product"),
                "serial": _read_sysfs_value(device, "serial"),
            }
        except DiagnosticError:
            continue
        if (
            identity["vendor"] == USB_VENDOR
            and identity["product_id"] == USB_PRODUCT
            and identity["product"] == USB_PRODUCT_NAME
            and identity["serial"] == expected_serial
            and identity["bcd_device"] in allowed_bcd
            and _has_exact_cdc_profile(devices, device)
        ):
            matches.append((device, identity))
    if len(matches) != 1:
        raise DiagnosticError("expected exactly one matching diagnostic Pico")
    device, identity = matches[0]
    return {"device": device.name, **identity}


def validate_terminal_evidence(code: str, events: tuple[str, ...]) -> str:
    if code not in EXPECTED_CODES:
        raise DiagnosticError("unknown or nonterminal diagnostic result")
    if len(events) != len(set(events)) or any(event not in PUBLIC_EVENTS for event in events):
        raise DiagnosticError("invalid diagnostic gateway events")
    event_set = frozenset(events)
    if code in PRE_TCP_CODES and event_set:
        raise DiagnosticError("pre-TCP result contradicts gateway events")
    if code in TCP_CODES and not event_set.issubset(("tcp-accepted",)):
        raise DiagnosticError("TCP result contradicts gateway events")
    if code in TLS_CODES and event_set != frozenset(("tcp-accepted",)):
        raise DiagnosticError("TLS result contradicts gateway events")
    if code == "9190" and event_set != PUBLIC_EVENTS:
        raise DiagnosticError("TLS-ready result lacks exact gateway events")
    if code == "9199" and "tls-established" in event_set:
        raise DiagnosticError("internal result contradicts established TLS")
    return EXPECTED_CODES[code]


def _contains_sensitive_key(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(name in lowered for name in SENSITIVE_NAMES):
                return True
            if _contains_sensitive_key(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _write_private(path: pathlib.Path, contents: bytes) -> None:
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
    )
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    published = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            written = stream.write(contents)
            if written != len(contents):
                raise DiagnosticError("cannot write complete diagnostic result")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        published = True
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except (OSError, DiagnosticError):
        if published:
            path.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def write_result(
    directory: pathlib.Path, result: dict[str, object], *, timestamp: str
) -> tuple[pathlib.Path, pathlib.Path]:
    if _contains_sensitive_key(result) or re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", timestamp) is None:
        raise DiagnosticError("diagnostic result is not redacted")
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise DiagnosticError("invalid diagnostic results directory")
        directory.chmod(0o700)
    except OSError as error:
        raise DiagnosticError("cannot prepare diagnostic results directory") from error
    encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    output = directory / f"{timestamp}-pico-network-diagnostic.json"
    manifest = directory / f"{timestamp}-pico-network-diagnostic.sha256"
    created: list[pathlib.Path] = []
    try:
        _write_private(output, encoded)
        created.append(output)
        digest = hashlib.sha256(encoded).hexdigest()
        _write_private(manifest, f"{digest}  {output.name}\n".encode("ascii"))
        created.append(manifest)
    except (OSError, DiagnosticError) as error:
        for path in created:
            path.unlink(missing_ok=True)
        if isinstance(error, DiagnosticError):
            raise
        raise DiagnosticError("cannot persist diagnostic result") from error
    return output, manifest


def verify_artifact(path: pathlib.Path, expected_sha256: str) -> str:
    if SHA256_HEX.fullmatch(expected_sha256) is None:
        raise DiagnosticError("invalid expected diagnostic artifact digest")
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise DiagnosticError("cannot read diagnostic artifact") from error
    if not hmac.compare_digest(digest, expected_sha256):
        raise DiagnosticError("diagnostic artifact digest mismatch")
    return digest


def verify_private_record(path: pathlib.Path) -> None:
    try:
        information = path.lstat()
    except OSError as error:
        raise DiagnosticError("cannot inspect private credential record") from error
    if (
        stat.S_ISLNK(information.st_mode)
        or not stat.S_ISREG(information.st_mode)
        or stat.S_IMODE(information.st_mode) != 0o600
    ):
        raise DiagnosticError("private credential record must be a mode-0600 regular file")


def certificate_spki_sha256(certificate: pathlib.Path) -> str:
    try:
        return _shared_certificate_spki_sha256(certificate)
    except TLSIdentityError as error:
        raise DiagnosticError("cannot derive diagnostic certificate SPKI") from error


def make_matching_certificate(
    directory: pathlib.Path, *, server_name: str
) -> pathlib.Path:
    try:
        return _shared_make_matching_certificate(
            directory, server_name=server_name
        )
    except TLSIdentityError as error:
        raise DiagnosticError("cannot create diagnostic TLS identity") from error


def _start_echo(
    state: pathlib.Path, listen: str, certificate: pathlib.Path
) -> tuple[subprocess.Popen[bytes], pathlib.Path]:
    ready = state / "echo-ready"
    events = state / "events"
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(LOOPBACK_HARNESS),
                "echo-server",
                "--listen",
                listen,
                "--cert",
                str(certificate),
                "--key",
                str(TLS_FIXTURES / "tls-gateway-test-key.pem"),
                "--ready-file",
                str(ready),
                "--event-file",
                str(events),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise DiagnosticError("cannot start diagnostic TLS oracle") from error
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if ready.is_file():
            return process, events
        if process.poll() is not None:
            process.wait()
            raise DiagnosticError("diagnostic TLS oracle stopped")
        time.sleep(0.05)
    _stop_echo(process)
    raise DiagnosticError("diagnostic TLS oracle readiness timed out")


def _stop_echo(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def _wait_for_disappearance(device: pathlib.Path, deadline: float) -> None:
    while time.monotonic() < deadline:
        if not device.exists():
            return
        time.sleep(0.05)
    raise DiagnosticError("diagnostic USB reboot timed out")


def _wait_for_terminal(
    sysfs_root: pathlib.Path, *, expected_serial: str, deadline: float
) -> dict[str, str]:
    allowed = frozenset(EXPECTED_CODES)
    while time.monotonic() < deadline:
        try:
            return verify_diagnostic_identity(
                sysfs_root,
                expected_serial=expected_serial,
                allowed_bcd=allowed,
            )
        except DiagnosticError:
            time.sleep(0.05)
    raise DiagnosticError("terminal diagnostic USB identity timed out")


def run_diagnostic(arguments: argparse.Namespace) -> pathlib.Path:
    verify_private_record(arguments.record)
    firmware_digest = verify_artifact(
        arguments.firmware_uf2, arguments.expected_uf2_sha256
    )
    initial = verify_diagnostic_identity(
        arguments.sysfs_root,
        expected_serial=arguments.expected_serial,
        allowed_bcd=frozenset((INITIAL_BCD_DEVICE,)),
    )
    initial_path = arguments.sysfs_root / initial["device"]
    state = pathlib.Path(tempfile.mkdtemp(prefix="pbns-network-diagnostic-"))
    state.chmod(0o700)
    process = None
    started = time.monotonic()
    try:
        certificate = make_matching_certificate(
            state, server_name=arguments.server_name
        )
        process, events_path = _start_echo(
            state, arguments.listen, certificate
        )
        try:
            import serial  # type: ignore[import-untyped]
        except ImportError as error:
            raise DiagnosticError("pyserial is not installed") from error
        deadline = time.monotonic() + 75.0
        try:
            with serial.Serial(
                arguments.port,
                baudrate=115200,
                timeout=5,
                write_timeout=5,
                exclusive=True,
            ) as serial_port:
                serial_port.dtr = True
                _wait_for_disappearance(initial_path, deadline)
        except (OSError, serial.SerialException) as error:
            if initial_path.exists():
                raise DiagnosticError("diagnostic CDC trigger failed") from error
        terminal = _wait_for_terminal(
            arguments.sysfs_root,
            expected_serial=arguments.expected_serial,
            deadline=deadline,
        )
        _stop_echo(process)
        process = None
        try:
            events = (
                tuple(events_path.read_text(encoding="ascii").splitlines())
                if events_path.exists()
                else ()
            )
        except OSError as error:
            raise DiagnosticError("cannot read diagnostic gateway events") from error
        result_name = validate_terminal_evidence(terminal["bcd_device"], events)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        result = {
            "diagnostic_firmware_sha256": firmware_digest,
            "elapsed_ms": elapsed_ms,
            "events": list(events),
            "result_code": terminal["bcd_device"],
            "result_name": result_name,
            "usb_product": terminal["product"],
            "usb_serial": terminal["serial"],
            "usb_vid_pid": f"{terminal['vendor']}:{terminal['product_id']}",
        }
        output, _manifest = write_result(
            arguments.results_dir, result, timestamp=timestamp
        )
        print(f"PICO NETWORK DIAGNOSTIC RESULT {terminal['bcd_device']} {result_name}")
        return output
    finally:
        if process is not None:
            _stop_echo(process)
        shutil.rmtree(state, ignore_errors=True)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        device = root / "1-3"
        device.mkdir()
        values = {
            "idVendor": "cafe\n",
            "idProduct": "40d1\n",
            "bcdDevice": "9100\n",
            "bNumInterfaces": "2\n",
            "product": "PBNS Network Diagnostic v1\n",
            "serial": "E66130100F527A26\n",
        }
        for key, value in values.items():
            (device / key).write_text(value, encoding="ascii")
        for number, interface_class in (("00", "02"), ("01", "0a")):
            interface = root / f"1-3:1.{int(number)}"
            interface.mkdir()
            (interface / "bInterfaceNumber").write_text(
                f"{number}\n", encoding="ascii"
            )
            (interface / "bInterfaceClass").write_text(
                f"{interface_class}\n", encoding="ascii"
            )
        verify_diagnostic_identity(
            root,
            expected_serial="E66130100F527A26",
            allowed_bcd=frozenset(("9100",)),
        )
        validate_terminal_evidence("9142", ())
    print("PICO NETWORK DIAGNOSTIC SOFTWARE PASS")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the isolated PBNS Pico diagnostic")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--expected-serial", required=True)
    preflight.add_argument(
        "--sysfs-root", type=pathlib.Path, default=pathlib.Path("/sys/bus/usb/devices")
    )

    run = subparsers.add_parser("run")
    run.add_argument("--port", required=True)
    run.add_argument("--expected-serial", required=True)
    run.add_argument("--firmware-uf2", required=True, type=pathlib.Path)
    run.add_argument("--expected-uf2-sha256", required=True)
    run.add_argument("--record", required=True, type=pathlib.Path)
    run.add_argument("--server-name", required=True)
    run.add_argument("--results-dir", required=True, type=pathlib.Path)
    run.add_argument("--listen", default="0.0.0.0:8443")
    run.add_argument(
        "--sysfs-root", type=pathlib.Path, default=pathlib.Path("/sys/bus/usb/devices")
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "self-test":
            self_test()
        elif arguments.command == "preflight":
            verify_diagnostic_identity(
                arguments.sysfs_root,
                expected_serial=arguments.expected_serial,
                allowed_bcd=frozenset((INITIAL_BCD_DEVICE,)),
            )
            print("PICO NETWORK DIAGNOSTIC PREFLIGHT PASS")
        else:
            run_diagnostic(arguments)
    except (DiagnosticError, OSError) as error:
        print(f"diagnostic failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
