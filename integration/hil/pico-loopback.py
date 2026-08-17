#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import hmac
import json
import math
import os
import pathlib
import re
import stat
import sys
import tempfile
import time
from typing import Protocol, cast


USB_VENDOR = "cafe"
USB_PRODUCT = "4011"
USB_PRODUCT_NAME = "PBNS Proxy v1"
USB_SERIAL = "E66130100F527A26"
USB_BCD_DEVICE = "0100"
USB_SPEED = "12"
CDC0_PATH = pathlib.Path("/dev/ttyACM0")
CDC1_PATH = pathlib.Path("/dev/ttyACM1")
TLS_CIPHER = "ECDHE-ECDSA-AES128-GCM-SHA256"
TLS_ALPN = "pbns/1"
TLS_SAN = "192.168.1.180"
TLS_SPKI_SHA256 = "a0d21923ddfccba12d0a7bbd7408650cb8c54f1be537fe3a7e69adb1376da106"
RAW_UF2_SHA256 = "e99ced85ba0c91c3b8d914ec3fcd7b7b5531e81a87a72830e181eb43de3ecd14"
MAX_SERIAL_COMPLETIONS = 524288
UEFI_PROBE_SHA256 = "245db7d544efcd4f2fb8d69f292d14bf5bf1f4aac81ed07e4ec6f301da5ce1c7"
ARTIFACT_SHA256 = "d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3"
ARTIFACT_BYTES = 26_553_920
WARMUP_BYTES = 65_536
DIRECT_BYTES = 1_048_576
RATE_NUMERATOR = 3
RATE_DENOMINATOR = 5
EXPECTED_RESULT_TRIALS = {
    "upstream-warmup.json": ("upstream", True),
    "downstream-warmup.json": ("downstream", True),
    "upstream.json": ("upstream", False),
    "downstream.json": ("downstream", False),
    "artifact.json": ("artifact", False),
    "wrong-san.json": ("wrong-san", False),
    "wrong-spki.json": ("wrong-spki", False),
    "wrong-alpn.json": ("wrong-alpn", False),
    "wrong-cipher.json": ("wrong-cipher", False),
    "cancellation.json": ("cancellation", False),
    "fresh-reconnect.json": ("fresh-reconnect", False),
    "truncation.json": ("truncation", False),
    "digest-mismatch.json": ("digest-mismatch", False),
}
EXPECTED_RESULT_FILES = frozenset(EXPECTED_RESULT_TRIALS)
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")
SENSITIVE_NAMES = (
    "ssid",
    "psk",
    "password",
    "credential",
    "secret",
    "payload",
    "capture",
    "private",
    "record",
)
RESULT_KEYS = frozenset(
    (
        "schema",
        "trial",
        "status",
        "error_code",
        "warmup",
        "bytes_expected",
        "bytes_observed",
        "sha256_expected",
        "sha256_observed",
        "duration_ns",
        "rate_mib_s",
        "required_tls_version",
        "required_cipher",
        "required_alpn",
        "expected_san",
        "required_spki_sha256",
        "usb_vendor",
        "usb_product_id",
        "usb_product",
        "usb_serial",
        "usb_bcd_device",
        "usb_speed",
        "cdc0",
        "cdc1",
        "reviewed_pico_uf2_sha256",
        "pico_firmware_verification",
        "reviewed_uefi_probe_sha256",
        "driver",
        "uefi_execution",
        "completion_count",
        "completion_status_count",
        "completion_p50_ns",
        "completion_p95_ns",
        "completion_p99_ns",
        "artifact_id",
        "rollback_needed",
    )
)
TRIALS = frozenset(
    (
        "self-test",
        "upstream",
        "downstream",
        "artifact",
        "wrong-san",
        "wrong-spki",
        "wrong-alpn",
        "wrong-cipher",
        "cancellation",
        "fresh-reconnect",
        "truncation",
        "digest-mismatch",
        "rollback-needed",
        "summary",
    )
)
ERROR_CODES = frozenset(
    (
        "none",
        "identity",
        "wrong-san",
        "wrong-spki",
        "wrong-alpn",
        "wrong-cipher",
        "wrong-version",
        "tls-handshake",
        "timeout",
        "zero-progress",
        "io",
        "cancelled",
        "truncated",
        "byte-count",
        "digest-mismatch",
        "throughput",
        "missing-trial",
        "internal",
        "signal",
    )
)


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...

    def flush(self) -> None: ...

    def read(self, size: int) -> bytes: ...


class LoopbackError(Exception):
    pass


def reject_unsafe_path(
    path: pathlib.Path, *, metadata: os.stat_result | object | None = None
) -> None:
    absolute = pathlib.Path(os.path.abspath(path))
    if absolute == pathlib.Path("/dev/sdc"):
        raise LoopbackError("forbidden device path")
    if metadata is None:
        try:
            metadata = path.lstat()
        except FileNotFoundError as error:
            if path in (CDC0_PATH, CDC1_PATH):
                raise LoopbackError("CDC path is missing") from error
            return
        except OSError as error:
            raise LoopbackError("cannot inspect device path") from error
    mode = getattr(metadata, "st_mode", None)
    if not isinstance(mode, int) or stat.S_ISLNK(mode) or stat.S_ISBLK(mode):
        raise LoopbackError("unsafe device path")
    if path in (CDC0_PATH, CDC1_PATH) and not stat.S_ISCHR(mode):
        raise LoopbackError("CDC path is not a character device")


def verify_cdc_node_metadata(metadata: object, expected_dev: str) -> None:
    mode = getattr(metadata, "st_mode", None)
    device = getattr(metadata, "st_rdev", None)
    if not isinstance(mode, int) or not stat.S_ISCHR(mode) or not isinstance(device, int):
        raise LoopbackError("CDC path is not a character device")
    observed = f"{os.major(device)}:{os.minor(device)}"
    if observed != expected_dev:
        raise LoopbackError("CDC device number mismatch")


def _interface_for_terminal(
    tty_root: pathlib.Path, terminal: str, expected_device: str
) -> tuple[str, str]:
    try:
        terminal_root = tty_root / terminal
        terminal_path = (terminal_root / "device").resolve(strict=True)
        interface_path = next(
            candidate
            for candidate in (terminal_path, *terminal_path.parents)
            if (candidate / "bInterfaceNumber").is_file()
        )
        number = _read_sysfs_value(interface_path, "bInterfaceNumber")
        device_number = _read_sysfs_value(terminal_root, "dev")
    except (OSError, StopIteration, LoopbackError) as error:
        raise LoopbackError("cannot verify CDC role") from error
    if interface_path.name.split(":", 1)[0] != expected_device:
        raise LoopbackError("CDC roles do not share the Pico")
    if re.fullmatch(r"[0-9]+:[0-9]+", device_number) is None:
        raise LoopbackError("invalid CDC device number")
    return number, device_number


def verify_hardware_identity(
    sysfs_root: pathlib.Path,
    tty_root: pathlib.Path,
    *,
    cdc0: pathlib.Path,
    cdc1: pathlib.Path,
    expected_serial: str,
    cdc_metadata: dict[str, object] | None = None,
) -> dict[str, str]:
    if cdc0 != CDC0_PATH or cdc1 != CDC1_PATH:
        raise LoopbackError("unexpected CDC role path")
    if expected_serial != USB_SERIAL:
        raise LoopbackError("unexpected Pico serial")
    identity = verify_usb_identity(
        sysfs_root, expected_serial=expected_serial, expected_bcd_device=USB_BCD_DEVICE
    )
    if identity.get("speed") != USB_SPEED:
        raise LoopbackError("unexpected USB speed")
    cdc0_interface, cdc0_dev = _interface_for_terminal(tty_root, cdc0.name, identity["device"])
    cdc1_interface, cdc1_dev = _interface_for_terminal(tty_root, cdc1.name, identity["device"])
    if cdc0_interface != "00" or cdc1_interface != "02":
        raise LoopbackError("unexpected CDC interface roles")
    metadata = cdc_metadata
    if metadata is None:
        reject_unsafe_path(cdc0)
        reject_unsafe_path(cdc1)
        metadata = {cdc0.name: cdc0.lstat(), cdc1.name: cdc1.lstat()}
    verify_cdc_node_metadata(metadata[cdc0.name], cdc0_dev)
    verify_cdc_node_metadata(metadata[cdc1.name], cdc1_dev)
    return {
        **identity,
        "cdc0": str(cdc0), "cdc1": str(cdc1),
        "cdc0_interface": cdc0_interface, "cdc1_interface": cdc1_interface,
        "cdc0_dev": cdc0_dev, "cdc1_dev": cdc1_dev,
    }


def verify_build_artifact(
    path: pathlib.Path, *, expected_sha256: str, expected_size: int
) -> str:
    if SHA256_HEX.fullmatch(expected_sha256) is None or expected_size <= 0:
        raise LoopbackError("invalid build expectation")
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            information = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(information.st_mode)
                or information.st_uid != os.getuid()
                or information.st_size != expected_size
                or stat.S_IMODE(information.st_mode) not in (0o600, 0o644)
            ):
                raise LoopbackError("build artifact profile mismatch")
            while chunk := stream.read(16384):
                digest.update(chunk)
    except OSError as error:
        raise LoopbackError("cannot hash build artifact") from error
    observed = digest.hexdigest()
    if not hmac.compare_digest(observed, expected_sha256):
        raise LoopbackError("build artifact digest mismatch")
    return observed


def read_public_pin(path: pathlib.Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LoopbackError("cannot read public pin") from error
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) not in (0o444, 0o644)
            or information.st_size not in (64, 65)
        ):
            raise LoopbackError("public pin profile mismatch")
        encoded = os.read(descriptor, 66)
    except OSError as error:
        raise LoopbackError("cannot read public pin") from error
    finally:
        os.close(descriptor)
    try:
        pin = encoded.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise LoopbackError("public pin profile mismatch") from error
    if SHA256_HEX.fullmatch(pin) is None:
        raise LoopbackError("public pin profile mismatch")
    return pin


def verify_digest_artifact(
    path: pathlib.Path, *, expected_sha256: str, expected_size: int
) -> str:
    if SHA256_HEX.fullmatch(expected_sha256) is None or expected_size <= 0:
        raise LoopbackError("invalid artifact expectation")
    if path.name != expected_sha256:
        raise LoopbackError("artifact profile mismatch")
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            information = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(information.st_mode)
                or information.st_uid != os.getuid()
                or stat.S_IMODE(information.st_mode) != 0o444
                or information.st_size != expected_size
            ):
                raise LoopbackError("artifact profile mismatch")
            while chunk := stream.read(16384):
                digest.update(chunk)
    except OSError as error:
        raise LoopbackError("cannot hash artifact") from error
    observed = digest.hexdigest()
    if not hmac.compare_digest(observed, expected_sha256):
        raise LoopbackError("artifact digest mismatch")
    return observed


def display_rate_mib_s(byte_count: int, duration_ns: int) -> float:
    if byte_count < 0 or duration_ns <= 0:
        raise LoopbackError("invalid throughput result")
    return round(byte_count * 1_000_000_000 / (duration_ns * 1024 * 1024), 6)


def meets_minimum_rate(byte_count: int, duration_ns: int) -> bool:
    if byte_count < 0 or duration_ns <= 0:
        return False
    return byte_count * RATE_DENOMINATOR * 1_000_000_000 >= (
        duration_ns * RATE_NUMERATOR * 1024 * 1024
    )


def _base_result(
    *,
    trial: str,
    status: str = "passed",
    error_code: str = "none",
    warmup: bool = False,
    bytes_expected: int = 0,
    bytes_observed: int = 0,
    sha256_expected: str | None = None,
    sha256_observed: str | None = None,
    duration_ns: int = 1,
    rate_mib_s: float | None = None,
    artifact_id: str | None = None,
    rollback_needed: bool = False,
) -> dict[str, object]:
    if rate_mib_s is None:
        rate_mib_s = display_rate_mib_s(bytes_observed, duration_ns)
    return {
        "schema": "pbns-uefi-tls-raw-v1",
        "trial": trial,
        "status": status,
        "error_code": error_code,
        "warmup": warmup,
        "bytes_expected": bytes_expected,
        "bytes_observed": bytes_observed,
        "sha256_expected": sha256_expected,
        "sha256_observed": sha256_observed,
        "duration_ns": duration_ns,
        "rate_mib_s": rate_mib_s,
        "required_tls_version": "TLSv1.2",
        "required_cipher": TLS_CIPHER,
        "required_alpn": TLS_ALPN,
        "expected_san": TLS_SAN,
        "required_spki_sha256": TLS_SPKI_SHA256,
        "usb_vendor": USB_VENDOR,
        "usb_product_id": USB_PRODUCT,
        "usb_product": USB_PRODUCT_NAME,
        "usb_serial": USB_SERIAL,
        "usb_bcd_device": USB_BCD_DEVICE,
        "usb_speed": USB_SPEED,
        "cdc0": str(CDC0_PATH),
        "cdc1": str(CDC1_PATH),
        "reviewed_pico_uf2_sha256": RAW_UF2_SHA256,
        "pico_firmware_verification": "usb-profile-plus-local-artifact",
        "reviewed_uefi_probe_sha256": UEFI_PROBE_SHA256,
        "driver": "host-python-ssl-memorybio",
        "uefi_execution": "not-run",
        "completion_count": 0,
        "completion_status_count": 0,
        "completion_p50_ns": 0,
        "completion_p95_ns": 0,
        "completion_p99_ns": 0,
        "artifact_id": artifact_id,
        "rollback_needed": rollback_needed,
    }


def self_test_result() -> dict[str, object]:
    return _base_result(trial="self-test")


def _contains_bytes(value: object) -> bool:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return True
    if isinstance(value, dict):
        return any(_contains_bytes(key) or _contains_bytes(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_bytes(item) for item in value)
    return False


def validate_result(result: dict[str, object]) -> None:
    if set(result) != RESULT_KEYS or _contains_sensitive_name(result) or _contains_bytes(result):
        raise LoopbackError("result schema is not payload-free")
    exact_fields = {
        "required_tls_version": "TLSv1.2",
        "required_cipher": TLS_CIPHER,
        "required_alpn": TLS_ALPN,
        "expected_san": TLS_SAN,
        "required_spki_sha256": TLS_SPKI_SHA256,
        "usb_vendor": USB_VENDOR,
        "usb_product_id": USB_PRODUCT,
        "usb_product": USB_PRODUCT_NAME,
        "usb_serial": USB_SERIAL,
        "usb_bcd_device": USB_BCD_DEVICE,
        "usb_speed": USB_SPEED,
        "cdc0": str(CDC0_PATH),
        "cdc1": str(CDC1_PATH),
        "reviewed_pico_uf2_sha256": RAW_UF2_SHA256,
        "pico_firmware_verification": "usb-profile-plus-local-artifact",
        "reviewed_uefi_probe_sha256": UEFI_PROBE_SHA256,
        "driver": "host-python-ssl-memorybio",
        "uefi_execution": "not-run",
    }
    if (
        result["schema"] != "pbns-uefi-tls-raw-v1"
        or result["trial"] not in TRIALS
        or result["status"] not in ("passed", "failed")
        or result["error_code"] not in ERROR_CODES
        or type(result["warmup"]) is not bool
        or type(result["rollback_needed"]) is not bool
        or any(result[name] != value for name, value in exact_fields.items())
    ):
        raise LoopbackError("invalid result fields")
    for name in (
        "bytes_expected",
        "bytes_observed",
        "duration_ns",
        "completion_count",
        "completion_status_count",
        "completion_p50_ns",
        "completion_p95_ns",
        "completion_p99_ns",
    ):
        value = result[name]
        if type(value) is not int or cast(int, value) < 0:
            raise LoopbackError("invalid numeric result")
    rate = result["rate_mib_s"]
    if (
        type(rate) not in (int, float)
        or not math.isfinite(cast(float, rate))
        or cast(float, rate) < 0
        or cast(float, rate) != display_rate_mib_s(
            cast(int, result["bytes_observed"]), cast(int, result["duration_ns"])
        )
    ):
        raise LoopbackError("invalid throughput result")
    successful_errors = {
        "self-test": "none", "upstream": "none", "downstream": "none",
        "artifact": "none", "wrong-san": "wrong-san", "wrong-spki": "wrong-spki",
        "wrong-alpn": "wrong-alpn", "wrong-cipher": "wrong-cipher",
        "cancellation": "cancelled", "fresh-reconnect": "none",
        "truncation": "truncated", "digest-mismatch": "digest-mismatch",
        "summary": "none",
    }
    if result["status"] == "passed" and result["error_code"] != successful_errors.get(result["trial"]):
        raise LoopbackError("inconsistent trial status")
    if result["status"] == "failed" and result["error_code"] == "none":
        raise LoopbackError("inconsistent trial status")
    if (
        cast(int, result["duration_ns"]) == 0
        or cast(int, result["bytes_observed"]) > cast(int, result["bytes_expected"])
        or cast(int, result["completion_count"]) > MAX_SERIAL_COMPLETIONS
        or cast(int, result["completion_status_count"])
        > cast(int, result["completion_count"])
        or not (
            cast(int, result["completion_p50_ns"])
            <= cast(int, result["completion_p95_ns"])
            <= cast(int, result["completion_p99_ns"])
        )
        or (result["status"] == "failed") != result["rollback_needed"]
        or (
            result["artifact_id"] is not None
            and (
                not isinstance(result["artifact_id"], str)
                or SHA256_HEX.fullmatch(cast(str, result["artifact_id"])) is None
            )
        )
    ):
        raise LoopbackError("inconsistent result metadata")
    for name in ("sha256_expected", "sha256_observed"):
        value = result[name]
        if value is not None and (
            not isinstance(value, str) or SHA256_HEX.fullmatch(value) is None
        ):
            raise LoopbackError("invalid result digest")


def create_run_directory(
    results_root: pathlib.Path, *, timestamp: str | None = None
) -> pathlib.Path:
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    if TIMESTAMP.fullmatch(timestamp) is None:
        raise LoopbackError("invalid result timestamp")
    try:
        root_info = results_root.lstat()
        if (
            stat.S_ISLNK(root_info.st_mode)
            or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise LoopbackError("invalid results root")
        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        root_fd = os.open(results_root, flags)
        try:
            name = f"{timestamp}-uefi-tls-raw"
            os.mkdir(name, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
    except (FileExistsError, OSError) as error:
        raise LoopbackError("cannot create exclusive results directory") from error
    run = results_root / name
    information = run.lstat()
    if (
        stat.S_ISLNK(information.st_mode)
        or not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        raise LoopbackError("invalid results directory")
    return run


def _mark_invalid(directory_fd: int, marker: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(marker, flags, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(b"invalid evidence transaction\n")
        while view:
            amount = os.write(descriptor, view)
            if amount <= 0:
                raise LoopbackError("cannot mark invalid transaction")
            view = view[amount:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def _quarantine_directory(directory: pathlib.Path) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(directory, flags)
    try:
        try:
            _mark_invalid(descriptor, ".run.invalid")
        except FileExistsError:
            return
    finally:
        os.close(descriptor)


def write_result(
    directory: pathlib.Path, result: dict[str, object], *, filename: str
) -> pathlib.Path:
    validate_result(result)
    if re.fullmatch(r"[a-z0-9-]+\.json", filename) is None:
        raise LoopbackError("invalid result filename")
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = -1
    stage = f".{filename}.stage"
    invalid = f".{filename}.invalid"
    publish_error: BaseException | None = None
    try:
        directory_fd = os.open(directory, flags)
        information = os.fstat(directory_fd)
        path_information = os.stat(directory, follow_symlinks=False)
        if (
            not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != 0o700
            or (information.st_dev, information.st_ino)
            != (path_information.st_dev, path_information.st_ino)
        ):
            raise LoopbackError("invalid results directory")
        _mark_invalid(directory_fd, invalid)
        output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            output_flags |= os.O_NOFOLLOW
        descriptor = os.open(stage, output_flags, 0o600, dir_fd=directory_fd)
        close_error = None
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(encoded)
            while view:
                amount = os.write(descriptor, view)
                if amount <= 0:
                    raise LoopbackError("cannot write complete result")
                view = view[amount:]
            os.fsync(descriptor)
        finally:
            try:
                os.close(descriptor)
            except OSError as error:
                close_error = error
        if close_error is not None:
            raise close_error
        os.link(
            stage, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.fsync(directory_fd)
        os.unlink(stage, dir_fd=directory_fd)
        os.fsync(directory_fd)
        os.unlink(invalid, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except (OSError, LoopbackError) as error:
        publish_error = error
    finally:
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except OSError as error:
                if publish_error is None:
                    publish_error = error
    if publish_error is not None:
        try:
            _quarantine_directory(directory)
        except (OSError, LoopbackError) as quarantine_error:
            raise LoopbackError("cannot quarantine failed result") from quarantine_error
        raise LoopbackError("cannot publish result") from publish_error
    return directory / filename


def self_test_gate_records() -> list[dict[str, object]]:
    records = [
        _base_result(
            trial="upstream", warmup=True, bytes_expected=WARMUP_BYTES,
            bytes_observed=WARMUP_BYTES, sha256_expected="1" * 64,
            sha256_observed="1" * 64,
        ),
        _base_result(
            trial="downstream", warmup=True, bytes_expected=WARMUP_BYTES,
            bytes_observed=WARMUP_BYTES, sha256_expected="2" * 64,
            sha256_observed="2" * 64,
        ),
        _base_result(
            trial="upstream", bytes_expected=DIRECT_BYTES,
            bytes_observed=DIRECT_BYTES, sha256_expected="3" * 64,
            sha256_observed="3" * 64,
        ),
        _base_result(
            trial="downstream", bytes_expected=DIRECT_BYTES,
            bytes_observed=DIRECT_BYTES, sha256_expected="4" * 64,
            sha256_observed="4" * 64,
        ),
        _base_result(
            trial="artifact",
            bytes_expected=ARTIFACT_BYTES,
            bytes_observed=ARTIFACT_BYTES,
            sha256_expected=ARTIFACT_SHA256,
            sha256_observed=ARTIFACT_SHA256,
            artifact_id=ARTIFACT_SHA256,
        ),
    ]
    negative_codes = {
        "wrong-san": "wrong-san",
        "wrong-spki": "wrong-spki",
        "wrong-alpn": "wrong-alpn",
        "wrong-cipher": "wrong-cipher",
        "cancellation": "cancelled",
        "fresh-reconnect": "none",
        "truncation": "truncated",
        "digest-mismatch": "digest-mismatch",
    }
    for trial, code in negative_codes.items():
        records.append(_base_result(trial=trial, error_code=code))
    return records


def validate_performance_gate(
    records: list[dict[str, object]], *, expected_artifact_sha256: str
) -> None:
    if expected_artifact_sha256 != ARTIFACT_SHA256:
        raise LoopbackError("unexpected artifact expectation")
    for record in records:
        validate_result(record)
    if (
        len(records) != 13
        or any(
            record["status"] != "passed" or record["rollback_needed"]
            for record in records
        )
    ):
        raise LoopbackError("unexpected performance evidence")

    def select(trial: str, warmup: bool) -> list[dict[str, object]]:
        return [
            record
            for record in records
            if record["trial"] == trial and record["warmup"] is warmup
        ]

    for trial in ("upstream", "downstream"):
        warmed = select(trial, True)
        measured = select(trial, False)
        if len(warmed) != 1 or len(measured) != 1:
            raise LoopbackError("missing warmed throughput sample")
        warmup = warmed[0]
        sample = measured[0]
        if (
            warmup["status"] != "passed"
            or warmup["error_code"] != "none"
            or warmup["bytes_expected"] != WARMUP_BYTES
            or warmup["bytes_observed"] != WARMUP_BYTES
            or warmup["sha256_expected"] != warmup["sha256_observed"]
            or sample["status"] != "passed"
            or sample["error_code"] != "none"
            or sample["bytes_expected"] != DIRECT_BYTES
            or sample["bytes_observed"] != DIRECT_BYTES
            or sample["sha256_expected"] != sample["sha256_observed"]
            or not meets_minimum_rate(cast(int, sample["bytes_observed"]), cast(int, sample["duration_ns"]))
        ):
            raise LoopbackError("throughput gate failed")
    artifacts = select("artifact", False)
    if len(artifacts) != 1:
        raise LoopbackError("missing artifact result")
    artifact = artifacts[0]
    if (
        artifact["status"] != "passed"
        or artifact["error_code"] != "none"
        or artifact["bytes_expected"] != ARTIFACT_BYTES
        or artifact["bytes_observed"] != ARTIFACT_BYTES
        or artifact["sha256_expected"] != expected_artifact_sha256
        or artifact["sha256_observed"] != expected_artifact_sha256
        or artifact["artifact_id"] != expected_artifact_sha256
    ):
        raise LoopbackError("artifact gate failed")
    required_negative = {
        "wrong-san": "wrong-san",
        "wrong-spki": "wrong-spki",
        "wrong-alpn": "wrong-alpn",
        "wrong-cipher": "wrong-cipher",
        "cancellation": "cancelled",
        "fresh-reconnect": "none",
        "truncation": "truncated",
        "digest-mismatch": "digest-mismatch",
    }
    for trial, error_code in required_negative.items():
        matches = select(trial, False)
        if (
            len(matches) != 1
            or matches[0]["status"] != "passed"
            or matches[0]["error_code"] != error_code
        ):
            raise LoopbackError("negative trial coverage incomplete")


def _read_sysfs_value(device: pathlib.Path, name: str) -> str:
    try:
        return (device / name).read_text(encoding="utf-8").strip()
    except OSError as error:
        raise LoopbackError("cannot read USB identity") from error


def verify_usb_identity(
    sysfs_root: pathlib.Path, *, expected_serial: str, expected_bcd_device: str
) -> dict[str, str]:
    if not expected_serial or not re.fullmatch(r"[0-9A-F]+", expected_serial):
        raise LoopbackError("invalid expected USB serial")
    if not re.fullmatch(r"[0-9a-f]{4}", expected_bcd_device):
        raise LoopbackError("invalid expected USB firmware profile")
    matches: list[tuple[pathlib.Path, dict[str, str]]] = []
    try:
        devices = sorted(sysfs_root.iterdir())
    except OSError as error:
        raise LoopbackError("cannot enumerate USB devices") from error
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
                "speed": _read_sysfs_value(device, "speed"),
            }
        except LoopbackError:
            continue
        if (
            identity["vendor"] == USB_VENDOR
            and identity["product_id"] == USB_PRODUCT
            and identity["bcd_device"] == expected_bcd_device
            and identity["product"] == USB_PRODUCT_NAME
            and identity["serial"] == expected_serial
            and identity["speed"] == USB_SPEED
        ):
            matches.append((device, identity))
    if len(matches) != 1:
        raise LoopbackError("expected exactly one matching PBNS Pico")
    device, identity = matches[0]
    return {"device": device.name, **identity}


def deterministic_bytes(length: int, seed: bytes) -> bytes:
    if length < 0 or not seed:
        raise LoopbackError("invalid deterministic stream parameters")
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(seed + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _write_all(serial_port: SerialPort, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = serial_port.write(data[offset:])
        if written <= 0 or written > len(data) - offset:
            raise LoopbackError("CDC0 write failed")
        offset += written
    serial_port.flush()


def _read_exact(serial_port: SerialPort, length: int, read_chunk: int) -> bytes:
    received = bytearray()
    while len(received) < length:
        amount = min(read_chunk, length - len(received))
        fragment = serial_port.read(amount)
        if not fragment or len(fragment) > amount:
            raise LoopbackError("CDC0 read timed out")
        received.extend(fragment)
    return bytes(received)


def run_serial_trial(
    serial_port: SerialPort,
    *,
    total_bytes: int,
    write_chunks: tuple[int, ...],
    read_chunk: int,
    seed: bytes,
) -> dict[str, int | float | str]:
    if total_bytes <= 0 or not write_chunks or any(chunk <= 0 for chunk in write_chunks):
        raise LoopbackError("invalid loopback size")
    if read_chunk <= 0:
        raise LoopbackError("invalid loopback read size")
    expected = deterministic_bytes(total_bytes, seed)
    started = time.monotonic_ns()
    offset = 0
    chunk_index = 0
    while offset < len(expected):
        amount = min(write_chunks[chunk_index % len(write_chunks)], len(expected) - offset)
        fragment = expected[offset : offset + amount]
        _write_all(serial_port, fragment)
        echoed = _read_exact(serial_port, amount, read_chunk)
        if not hmac.compare_digest(echoed, fragment):
            raise LoopbackError("CDC0 loopback byte mismatch")
        offset += amount
        chunk_index += 1
    duration_ns = max(time.monotonic_ns() - started, 1)
    return {
        "bytes_sent": total_bytes,
        "bytes_received": total_bytes,
        "duration_ms": round(duration_ns / 1_000_000, 3),
        "throughput_bytes_per_second": round(total_bytes * 1_000_000_000 / duration_ns, 3),
        "stream_sha256": hashlib.sha256(expected).hexdigest(),
    }


def _contains_sensitive_name(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(name in lowered for name in SENSITIVE_NAMES):
                return True
            if _contains_sensitive_name(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_name(item) for item in value)
    return False


class _MemorySerial:
    def __init__(self) -> None:
        self.pending = bytearray()

    def write(self, data: bytes) -> int:
        amount = min(len(data), 23)
        self.pending.extend(data[:amount])
        return amount

    def flush(self) -> None:
        return None

    def read(self, size: int) -> bytes:
        amount = min(size, len(self.pending), 19)
        result = bytes(self.pending[:amount])
        del self.pending[:amount]
        return result


def self_test() -> None:
    result = run_serial_trial(
        _MemorySerial(),
        total_bytes=1024 * 1024,
        write_chunks=(1, 7, 64, 255, 1024, 4096),
        read_chunk=31,
        seed=b"pbns-hil-self-test-v1",
    )
    if result["bytes_received"] != 1024 * 1024:
        raise LoopbackError("loopback self-test byte count mismatch")
    validate_performance_gate(
        self_test_gate_records(), expected_artifact_sha256=ARTIFACT_SHA256
    )
    with tempfile.TemporaryDirectory(prefix="pbns-raw-hil-self-test-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o700)
        run = create_run_directory(root, timestamp="20260811T000000Z")
        write_result(run, self_test_result(), filename="self-test.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PBNS raw Pico identity and sanitized evidence gate"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    raw_preflight = subparsers.add_parser("raw-preflight")
    raw_preflight.add_argument("--cdc0", required=True, type=pathlib.Path)
    raw_preflight.add_argument("--cdc1", required=True, type=pathlib.Path)
    raw_preflight.add_argument("--expected-serial", required=True)
    raw_preflight.add_argument("--expected-san", required=True)
    raw_preflight.add_argument("--firmware", required=True, type=pathlib.Path)
    raw_preflight.add_argument("--uefi-probe", required=True, type=pathlib.Path)
    raw_preflight.add_argument("--artifact", required=True, type=pathlib.Path)
    raw_preflight.add_argument("--pin", required=True, type=pathlib.Path)
    raw_preflight.add_argument(
        "--sysfs-root",
        type=pathlib.Path,
        default=pathlib.Path("/sys/bus/usb/devices"),
    )
    raw_preflight.add_argument(
        "--tty-root", type=pathlib.Path, default=pathlib.Path("/sys/class/tty")
    )
    create = subparsers.add_parser("create-run")
    create.add_argument("--results-root", required=True, type=pathlib.Path)
    failure = subparsers.add_parser("publish-failure")
    failure.add_argument("--results-dir", required=True, type=pathlib.Path)
    failure.add_argument(
        "--error-code", choices=tuple(sorted(ERROR_CODES)), required=True
    )
    return parser


def _raw_preflight(arguments: argparse.Namespace) -> str:
    if arguments.expected_san != TLS_SAN:
        raise LoopbackError("unexpected TLS SAN")
    reject_unsafe_path(arguments.cdc0)
    reject_unsafe_path(arguments.cdc1)
    identity = verify_hardware_identity(
        arguments.sysfs_root,
        arguments.tty_root,
        cdc0=arguments.cdc0,
        cdc1=arguments.cdc1,
        expected_serial=arguments.expected_serial,
    )
    verify_build_artifact(
        arguments.firmware,
        expected_sha256=RAW_UF2_SHA256,
        expected_size=792576,
    )
    verify_build_artifact(
        arguments.uefi_probe,
        expected_sha256=UEFI_PROBE_SHA256,
        expected_size=212992,
    )
    verify_digest_artifact(
        arguments.artifact,
        expected_sha256=ARTIFACT_SHA256,
        expected_size=ARTIFACT_BYTES,
    )
    pin = read_public_pin(arguments.pin)
    if not hmac.compare_digest(pin, TLS_SPKI_SHA256):
        raise LoopbackError("unexpected public pin")
    return identity["device"]


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "self-test":
            self_test()
            print("PICO LOOPBACK SELF-TEST PASS")
        elif arguments.command == "create-run":
            print(create_run_directory(arguments.results_root))
        elif arguments.command == "publish-failure":
            result = _base_result(
                trial="rollback-needed",
                status="failed",
                error_code=arguments.error_code,
                rollback_needed=True,
            )
            write_result(
                arguments.results_dir, result, filename="rollback-needed.json"
            )
            print("ROLLBACK NEEDED METADATA PUBLISHED")
        else:
            print(f"RAW PICO PREFLIGHT PASS {_raw_preflight(arguments)}")
    except (LoopbackError, OSError):
        print("pico raw gate failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
