#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import stat
import sys
import time
import types
from typing import Callable, Protocol, cast


SCHEMA = "pbns-raw-tunnel-diagnostic-v1"
ROLLBACK_SCHEMA = "pbns-raw-tunnel-rollback-v1"
LOCK_SCHEMA = "pbns-raw-tunnel-diagnostic-lock-v1"
EVENT_SCHEMA = "pbns-raw-tunnel-server-events-v1"
DRIVER = "host-python-ssl-memorybio"
UEFI_EXECUTION = "not-run"
SERIAL = "E66130100F527A26"
DIAGNOSTIC_VENDOR = "cafe"
DIAGNOSTIC_PRODUCT_ID = "40d2"
DIAGNOSTIC_PRODUCT = "PBNS Raw Tunnel Diagnostic v1"
DIAGNOSTIC_AWAITING_BCD = "9200"
PRODUCTION_PRODUCT_ID = "4011"
PRODUCTION_PRODUCT = "PBNS Proxy v1"
PRODUCTION_BCD = "0100"
USB_SPEED = "12"
CDC_INTERFACE = "00"
APPLICATION_OCTETS = 4096
APPLICATION_SHA256 = "1342cbe0b2091947fea1a31a28352862f0a364225c4da54b9542ac8eae85aca0"
TERMINAL_OBSERVATION_NS = 35_000_000_000
STAGE6_SHA256 = "f388ceb17afa441d916dc6c41c278ccf583e8668f7f2387b32e0f0bbaf5cae74"
STAGE6_SIZE = 968704
STAGE6_TARGET_START = 0x10000000
STAGE6_TARGET_END = 0x10076400
PICOTOOL_SHA256 = "0f8ed96f433d56c27c2f36d808fbbf55b9947eaf5743a21329444f76d618018b"
PRODUCTION_RAW_SHA256 = "e99ced85ba0c91c3b8d914ec3fcd7b7b5531e81a87a72830e181eb43de3ecd14"
PRODUCTION_RAW_SIZE = 792576
PRODUCTION_RAW_TARGET_START = 0x10000000
PRODUCTION_RAW_TARGET_END = 0x10060C00
DEFAULT_LOCK = pathlib.Path(__file__).with_name("raw-tunnel-diagnostic-lock.json")
TIMESTAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")
SHA256 = re.compile(r"[0-9a-f]{64}")

PICO_RESULTS = {
    "9201": "credential-failure",
    "9202": "network-init-failure",
    "9203": "wifi-start-failure",
    "9204": "wifi-failure",
    "9205": "wifi-timeout",
    "9206": "tcp-failure",
    "9207": "tcp-timeout",
    "9208": "no-cdc-ciphertext",
    "9209": "tcp-write-failure",
    "9210": "tcp-output-failure",
    "9211": "no-tcp-rx",
    "9212": "tcp-rx-without-cdc-tx",
    "9213": "cdc-enqueue-without-flush",
    "9214": "application-timeout",
    "9215": "cdc-flush-without-complete",
    "9298": "complete",
    "9299": "internal-failure",
}
ERROR_CODES = frozenset(
    (
        "none",
        "credential-wifi-boundary",
        "endpoint-boundary",
        "cdc-to-tcp-boundary",
        "tcp-receive-boundary",
        "cdc-enqueue-boundary",
        "cdc-flush-boundary",
        "usb-transfer-boundary",
        "usb-downstream-boundary",
        "tls-application",
        "timeout",
        "io",
        "signal",
        "internal",
    )
)
EVENT_ERRORS = frozenset(
    ("none", "timeout", "io", "tls-handshake", "tls-profile", "application", "internal", "signal")
)
CLIENT_ERRORS = frozenset(
    (
        "none",
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
        "internal",
    )
)
EVENT_KEYS = frozenset(
    (
        "schema",
        "status",
        "error_code",
        "ready",
        "process_alive",
        "accept_count",
        "clienthello_seen",
        "tls_established",
        "server_flight_sent",
        "application_complete",
        "duration_ns",
    )
)
DIAGNOSTIC_KEYS = frozenset(
    (
        "schema",
        "status",
        "error_code",
        "driver",
        "uefi_execution",
        "duration_ns",
        "usb_vendor",
        "usb_product_id",
        "usb_product",
        "usb_serial",
        "usb_bcd_initial",
        "usb_bcd_terminal",
        "usb_speed",
        "cdc_interface",
        "pico_result",
        "diagnostic_uf2_sha256",
        "diagnostic_uf2_size",
        "client_status",
        "server_status",
        "server_error_code",
        "application_octets_expected",
        "application_octets_observed",
        "application_sha256_expected",
        "application_sha256_observed",
        "accept_count",
        "clienthello_seen",
        "tls_established",
        "server_flight_sent",
        "application_complete",
    )
)
LOCK_KEYS = frozenset(("schema", "diagnostic", "rollback", "production_raw"))
ARTIFACT_LOCK_KEYS = frozenset(("sha256", "size", "target_start", "target_end"))
ROLLBACK_KEYS = frozenset(
    (
        "schema",
        "status",
        "error_code",
        "duration_ns",
        "usb_vendor",
        "usb_product_id",
        "usb_product",
        "usb_serial",
        "usb_bcd_device",
        "usb_speed",
        "cdc0_interface",
        "cdc1_interface",
        "stage6_sha256",
        "stage6_size",
        "stage6_target_start",
        "stage6_target_end",
        "picotool_sha256",
    )
)
SENSITIVE_NAMES = frozenset(
    (
        "token",
        "secret",
        "private",
        "credential",
        "password",
        "nonce",
        "certificate",
        "tls_record",
        "payload",
        "cdc_data",
        "frame",
        "request_binding",
    )
)


class DiagnosticError(Exception):
    pass


class OpenedSerial(Protocol):
    def fileno(self) -> int: ...
    def close(self) -> None: ...
    def __enter__(self) -> "OpenedSerial": ...
    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None: ...


def _load_module(name: str, filename: str) -> types.ModuleType:
    path = pathlib.Path(__file__).with_name(filename)
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise DiagnosticError("internal")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _load_uf2_module() -> types.ModuleType:
    path = pathlib.Path(__file__).resolve().parents[2] / "tools" / "verify_uf2_range.py"
    specification = importlib.util.spec_from_file_location("pbns_verify_uf2", path)
    if specification is None or specification.loader is None:
        raise DiagnosticError("internal")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _contains_bytes(value: object) -> bool:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return True
    if isinstance(value, dict):
        return any(_contains_bytes(key) or _contains_bytes(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_bytes(item) for item in value)
    return False


def _contains_sensitive_name(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                return True
            normalized = key.lower().replace("-", "_")
            if any(name in normalized for name in SENSITIVE_NAMES):
                return True
            if _contains_sensitive_name(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_sensitive_name(item) for item in value)
    return False


def _contains_unsafe_string(value: object) -> bool:
    if isinstance(value, str):
        if value.startswith(("/", "./", "../")) or "/" in value or "\\" in value:
            return True
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    if isinstance(value, dict):
        return any(_contains_unsafe_string(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_unsafe_string(item) for item in value)
    return False


def _require_safe_object(value: dict[str, object]) -> None:
    if _contains_bytes(value) or _contains_sensitive_name(value) or _contains_unsafe_string(value):
        raise DiagnosticError("unsafe evidence")


def _directory_fd(path: pathlib.Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        information = os.fstat(descriptor)
        observed = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise DiagnosticError("unsafe directory") from error
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o700
        or (information.st_dev, information.st_ino) != (observed.st_dev, observed.st_ino)
    ):
        os.close(descriptor)
        raise DiagnosticError("unsafe directory")
    return descriptor


def create_run_directory(results_root: pathlib.Path, timestamp: str | None = None) -> pathlib.Path:
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    if TIMESTAMP.fullmatch(timestamp) is None:
        raise DiagnosticError("invalid timestamp")
    root_fd = _directory_fd(results_root)
    name = f"{timestamp}-raw-tunnel-diagnostic"
    try:
        os.mkdir(name, 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError as error:
        raise DiagnosticError("cannot create run") from error
    finally:
        os.close(root_fd)
    run = results_root / name
    descriptor = _directory_fd(run)
    os.close(descriptor)
    return run


def _write_all(descriptor: int, encoded: bytes) -> None:
    view = memoryview(encoded)
    while view:
        written = os.write(descriptor, view)
        if written <= 0 or written > len(view):
            raise DiagnosticError("short evidence write")
        view = view[written:]


def _mark_invalid(directory_fd: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(".run.invalid", flags, 0o600, dir_fd=directory_fd)
    except FileExistsError:
        return
    try:
        _write_all(descriptor, b"invalid evidence transaction\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def _publish_json(directory: pathlib.Path, name: str, value: dict[str, object]) -> None:
    if name not in ("diagnostic.json", "rollback.json"):
        raise DiagnosticError("invalid evidence name")
    _require_safe_object(value)
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if not 0 < len(encoded) <= 65536:
        raise DiagnosticError("invalid evidence size")
    directory_fd = _directory_fd(directory)
    stage = f".{name}.stage"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(stage, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(stage, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
        os.unlink(stage, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except (OSError, DiagnosticError) as error:
        try:
            _mark_invalid(directory_fd)
        except (OSError, DiagnosticError) as quarantine_error:
            raise DiagnosticError("cannot quarantine evidence") from quarantine_error
        raise DiagnosticError("cannot publish evidence") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _read_json_descriptor(
    descriptor: int, *, maximum: int, mode: int
) -> dict[str, object]:
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != mode
            or not 0 < information.st_size <= maximum
        ):
            raise DiagnosticError("unsafe evidence file")
        chunks: list[bytes] = []
        remaining = information.st_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        if len(encoded) != information.st_size:
            raise DiagnosticError("unsafe evidence file")
    except OSError as error:
        raise DiagnosticError("cannot read evidence") from error
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticError("invalid evidence JSON") from error
    if not isinstance(value, dict):
        raise DiagnosticError("invalid evidence JSON")
    return cast(dict[str, object], value)


def _read_regular_json_at(
    directory_fd: int,
    name: str,
    *,
    maximum: int = 65536,
    mode: int = 0o600,
) -> dict[str, object]:
    if name not in ("diagnostic.json", "rollback.json"):
        raise DiagnosticError("invalid evidence name")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise DiagnosticError("cannot read evidence") from error
    try:
        return _read_json_descriptor(descriptor, maximum=maximum, mode=mode)
    finally:
        os.close(descriptor)


def _read_regular_json(
    path: pathlib.Path, *, maximum: int = 65536, mode: int = 0o600
) -> dict[str, object]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DiagnosticError("cannot read evidence") from error
    try:
        return _read_json_descriptor(descriptor, maximum=maximum, mode=mode)
    finally:
        os.close(descriptor)


def _validate_lock_record(lock: dict[str, object]) -> None:
    if set(lock) != LOCK_KEYS or lock.get("schema") != LOCK_SCHEMA:
        raise DiagnosticError("invalid artifact lock")
    artifacts: dict[str, dict[str, object]] = {}
    for name in ("diagnostic", "rollback", "production_raw"):
        value = lock.get(name)
        if not isinstance(value, dict) or set(value) != ARTIFACT_LOCK_KEYS:
            raise DiagnosticError("invalid artifact lock")
        artifact = cast(dict[str, object], value)
        digest = artifact.get("sha256")
        size = artifact.get("size")
        target_start = artifact.get("target_start")
        target_end = artifact.get("target_end")
        if (
            not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or type(size) is not int
            or size <= 0
            or type(target_start) is not int
            or type(target_end) is not int
            or not 0x10000000 <= target_start < target_end <= 0x101FE000
        ):
            raise DiagnosticError("invalid artifact lock")
        artifacts[name] = artifact
    rollback = artifacts["rollback"]
    production = artifacts["production_raw"]
    if (
        rollback["sha256"] != STAGE6_SHA256
        or rollback["size"] != STAGE6_SIZE
        or rollback["target_start"] != STAGE6_TARGET_START
        or rollback["target_end"] != STAGE6_TARGET_END
        or production["sha256"] != PRODUCTION_RAW_SHA256
        or production["size"] != PRODUCTION_RAW_SIZE
        or production["target_start"] != PRODUCTION_RAW_TARGET_START
        or production["target_end"] != PRODUCTION_RAW_TARGET_END
        or artifacts["diagnostic"]["target_start"] != 0x10000000
    ):
        raise DiagnosticError("invalid artifact lock")


def _read_artifact_lock(path: pathlib.Path = DEFAULT_LOCK) -> dict[str, object]:
    lock = _read_regular_json(path, mode=0o644)
    _validate_lock_record(lock)
    return lock


def _event_is_consistent(event: dict[str, object], *, final: bool) -> bool:
    accept_count = event.get("accept_count")
    duration_ns = event.get("duration_ns")
    if (
        set(event) != EVENT_KEYS
        or event.get("schema") != EVENT_SCHEMA
        or event.get("status") not in ("passed", "failed", "not-run")
        or event.get("error_code") not in EVENT_ERRORS
        or type(accept_count) is not int
        or accept_count not in (0, 1)
        or type(duration_ns) is not int
        or duration_ns <= 0
    ):
        return False
    for name in (
        "ready",
        "process_alive",
        "clienthello_seen",
        "tls_established",
        "server_flight_sent",
        "application_complete",
    ):
        if type(event.get(name)) is not bool:
            return False
    if (
        (not event["ready"] and event["accept_count"] != 0)
        or (event["accept_count"] == 0 and event["clienthello_seen"])
        or (event["server_flight_sent"] and not event["clienthello_seen"])
        or (
            event["tls_established"]
            and not (event["clienthello_seen"] and event["server_flight_sent"])
        )
        or (event["application_complete"] and not event["tls_established"])
    ):
        return False
    error_code = event["error_code"]
    if (
        error_code in ("tls-handshake", "tls-profile")
        and (event["tls_established"] or event["application_complete"])
    ) or (
        error_code == "tls-handshake" and event["accept_count"] != 1
    ) or (
        error_code == "tls-profile"
        and not (
            event["accept_count"] == 1
            and event["clienthello_seen"]
            and event["server_flight_sent"]
        )
    ) or (
        error_code == "application"
        and not (
            event["accept_count"] == 1
            and event["clienthello_seen"]
            and event["server_flight_sent"]
            and event["tls_established"]
            and not event["application_complete"]
        )
    ):
        return False
    if event["status"] == "passed":
        valid_status = (
            event["error_code"] == "none"
            and event["process_alive"] is False
            and event["application_complete"] is True
        )
    elif event["status"] == "failed":
        valid_status = (
            event["error_code"] != "none" and event["process_alive"] is False
        )
    else:
        valid_status = event["error_code"] == "none" and event["process_alive"] is True
    return valid_status and (not final or event["status"] != "not-run")


def read_event_journal(path: pathlib.Path) -> dict[str, object]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != 0o600
            or not 0 < information.st_size <= 65536
        ):
            raise DiagnosticError("unsafe journal")
        encoded = os.read(descriptor, information.st_size + 1)
    except OSError as error:
        raise DiagnosticError("cannot read journal") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    try:
        records = [json.loads(line) for line in encoded.decode("ascii").splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticError("invalid journal") from error
    if not records:
        raise DiagnosticError("empty journal")
    previous_accepts = 0
    previous_true = {name: False for name in ("ready", "clienthello_seen", "tls_established", "server_flight_sent", "application_complete")}
    for record in records:
        if not isinstance(record, dict) or not _event_is_consistent(record, final=False):
            raise DiagnosticError("invalid journal schema")
        if not previous_accepts <= record["accept_count"] <= 1:
            raise DiagnosticError("invalid journal values")
        previous_accepts = record["accept_count"]
        for name in previous_true:
            if type(record[name]) is not bool or (previous_true[name] and not record[name]):
                raise DiagnosticError("non-monotonic journal")
            previous_true[name] = record[name]
        if type(record["process_alive"]) is not bool:
            raise DiagnosticError("invalid journal values")
    final = cast(dict[str, object], records[-1])
    if not _event_is_consistent(final, final=True):
        raise DiagnosticError("incomplete journal")
    return final


def classify_boundary(pico_result: str, event: dict[str, object], client_status: str) -> tuple[str, str]:
    if pico_result not in PICO_RESULTS or not _event_is_consistent(event, final=True) or client_status not in ("passed", "failed"):
        return "failed", "internal"
    pico = PICO_RESULTS[pico_result]
    accepts = event["accept_count"]
    clienthello = event["clienthello_seen"] is True
    flight = event["server_flight_sent"] is True
    tls_established = event["tls_established"] is True
    server_complete = event["application_complete"] is True
    no_server_transport = (
        accepts == 0
        and not clienthello
        and not flight
        and not tls_established
        and not server_complete
    )
    accepted_without_clienthello = (
        accepts == 1
        and not clienthello
        and not flight
        and not tls_established
        and not server_complete
    )
    server_flight_without_tls = (
        accepts == 1
        and clienthello
        and flight
        and not tls_established
        and not server_complete
    )
    if event["error_code"] == "internal":
        return "failed", "internal"
    if client_status == "passed":
        if (
            pico == "complete"
            and event["status"] == "passed"
            and accepts == 1
            and clienthello
            and flight
            and tls_established
            and server_complete
        ):
            return "passed", "none"
        return "failed", "internal"
    if event["error_code"] == "signal":
        return "failed", "signal"
    if event["error_code"] in ("tls-profile", "application"):
        if pico == "complete" and accepts == 1 and clienthello and flight:
            return "failed", "tls-application"
        return "failed", "internal"
    if pico in ("credential-failure", "network-init-failure", "wifi-start-failure", "wifi-failure", "wifi-timeout"):
        return (
            ("failed", "credential-wifi-boundary")
            if no_server_transport
            else ("failed", "internal")
        )
    if pico in ("tcp-failure", "tcp-timeout"):
        return (
            ("failed", "endpoint-boundary")
            if no_server_transport
            else ("failed", "internal")
        )
    if pico in ("no-cdc-ciphertext", "tcp-write-failure", "tcp-output-failure"):
        return (
            ("failed", "cdc-to-tcp-boundary")
            if accepted_without_clienthello
            else ("failed", "internal")
        )
    if pico == "no-tcp-rx":
        return (
            ("failed", "tcp-receive-boundary")
            if server_flight_without_tls
            else ("failed", "internal")
        )
    if pico == "tcp-rx-without-cdc-tx":
        return (
            ("failed", "cdc-enqueue-boundary")
            if server_flight_without_tls
            else ("failed", "internal")
        )
    if pico == "cdc-enqueue-without-flush":
        return (
            ("failed", "cdc-flush-boundary")
            if server_flight_without_tls
            else ("failed", "internal")
        )
    if pico == "cdc-flush-without-complete":
        return (
            ("failed", "usb-transfer-boundary")
            if server_flight_without_tls
            else ("failed", "internal")
        )
    if pico == "application-timeout":
        return (
            ("failed", "usb-downstream-boundary")
            if accepts == 1 and clienthello and flight
            else ("failed", "internal")
        )
    if pico == "internal-failure":
        return "failed", "internal"
    if pico == "complete":
        if not (accepts == 1 and clienthello and flight):
            return "failed", "internal"
        if event["status"] == "passed":
            return "failed", "usb-downstream-boundary"
    if event["error_code"] in ("tls-handshake", "tls-profile", "application"):
        return "failed", "tls-application"
    if event["error_code"] in ("timeout", "io", "signal"):
        return "failed", event["error_code"]
    return "failed", "internal"


def _hash_regular(path: pathlib.Path, allowed_modes: tuple[int, ...] = (0o444, 0o600, 0o644, 0o755)) -> tuple[str, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, flags)
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) not in allowed_modes
            or information.st_size <= 0
        ):
            raise DiagnosticError("unsafe artifact")
        with os.fdopen(descriptor, "rb") as stream:
            while chunk := stream.read(16384):
                digest.update(chunk)
    except OSError as error:
        raise DiagnosticError("cannot hash artifact") from error
    return digest.hexdigest(), information.st_size


def _validate_client_state(client: dict[str, object]) -> None:
    required = {
        "status",
        "error_code",
        "duration_ns",
        "usb_bcd_initial",
        "usb_bcd_terminal",
        "application_octets_observed",
        "application_sha256_expected",
        "application_sha256_observed",
    }
    duration = client.get("duration_ns")
    observed_octets = client.get("application_octets_observed")
    expected_digest = client.get("application_sha256_expected")
    observed_digest = client.get("application_sha256_observed")
    if (
        set(client) != required
        or client.get("status") not in ("passed", "failed")
        or client.get("error_code") not in CLIENT_ERRORS
        or client.get("usb_bcd_initial") != DIAGNOSTIC_AWAITING_BCD
        or client.get("usb_bcd_terminal") not in PICO_RESULTS
        or type(duration) is not int
        or not 0 < duration <= 65_000_000_000
        or type(observed_octets) is not int
        or not 0 <= observed_octets <= APPLICATION_OCTETS
        or not isinstance(expected_digest, str)
        or not hmac.compare_digest(expected_digest, APPLICATION_SHA256)
        or (
            observed_digest is not None
            and (
                not isinstance(observed_digest, str)
                or SHA256.fullmatch(observed_digest) is None
            )
        )
    ):
        raise DiagnosticError("invalid client state")
    if client["status"] == "passed":
        if (
            client["error_code"] != "none"
            or duration > 60_000_000_000
            or observed_octets != APPLICATION_OCTETS
            or observed_digest is None
            or not hmac.compare_digest(expected_digest, observed_digest)
        ):
            raise DiagnosticError("inconsistent client success")
    elif client["error_code"] == "none":
        raise DiagnosticError("inconsistent client failure")


def _validate_diagnostic_against_lock(
    record: dict[str, object],
    locked_diagnostic: dict[str, object],
) -> None:
    _require_safe_object(record)
    if set(record) != DIAGNOSTIC_KEYS:
        raise DiagnosticError("invalid diagnostic schema")
    exact = {
        "schema": SCHEMA,
        "driver": DRIVER,
        "uefi_execution": UEFI_EXECUTION,
        "usb_vendor": DIAGNOSTIC_VENDOR,
        "usb_product_id": DIAGNOSTIC_PRODUCT_ID,
        "usb_product": DIAGNOSTIC_PRODUCT,
        "usb_serial": SERIAL,
        "usb_bcd_initial": DIAGNOSTIC_AWAITING_BCD,
        "usb_speed": USB_SPEED,
        "cdc_interface": CDC_INTERFACE,
        "application_octets_expected": APPLICATION_OCTETS,
        "application_sha256_expected": APPLICATION_SHA256,
    }
    if (
        any(record[name] != value for name, value in exact.items())
        or record["status"] not in ("passed", "failed")
        or record["error_code"] not in ERROR_CODES
        or record["client_status"] not in ("passed", "failed")
        or record["server_status"] not in ("passed", "failed")
        or record["server_error_code"] not in EVENT_ERRORS
        or record["usb_bcd_terminal"] not in PICO_RESULTS
        or record["pico_result"] != PICO_RESULTS[record["usb_bcd_terminal"]]
    ):
        raise DiagnosticError("invalid diagnostic values")
    numeric: dict[str, int] = {}
    for name in ("duration_ns", "diagnostic_uf2_size", "application_octets_observed", "accept_count"):
        value = record[name]
        if type(value) is not int or value < 0:
            raise DiagnosticError("invalid diagnostic numeric value")
        numeric[name] = value
    if numeric["duration_ns"] <= 0 or not 0 <= numeric["application_octets_observed"] <= APPLICATION_OCTETS or numeric["accept_count"] not in (0, 1):
        raise DiagnosticError("invalid diagnostic numeric value")
    for name in ("clienthello_seen", "tls_established", "server_flight_sent", "application_complete"):
        if type(record[name]) is not bool:
            raise DiagnosticError("invalid diagnostic boolean")
    for name in ("diagnostic_uf2_sha256", "application_sha256_expected"):
        digest = record[name]
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise DiagnosticError("invalid diagnostic digest")
    if (
        record["diagnostic_uf2_sha256"] != locked_diagnostic.get("sha256")
        or record["diagnostic_uf2_size"] != locked_diagnostic.get("size")
        or (record["status"] == "passed") != (record["error_code"] == "none")
    ):
        raise DiagnosticError("inconsistent diagnostic status")
    observed = record["application_sha256_observed"]
    if observed is not None and (not isinstance(observed, str) or SHA256.fullmatch(observed) is None):
        raise DiagnosticError("invalid diagnostic digest")
    status, error = classify_boundary(record["usb_bcd_terminal"], {
        "schema": EVENT_SCHEMA,
        "status": record["server_status"],
        "error_code": record["server_error_code"],
        "ready": True,
        "process_alive": False,
        "accept_count": record["accept_count"],
        "clienthello_seen": record["clienthello_seen"],
        "tls_established": record["tls_established"],
        "server_flight_sent": record["server_flight_sent"],
        "application_complete": record["application_complete"],
        "duration_ns": record["duration_ns"],
    }, record["client_status"])
    if (record["status"], record["error_code"]) != (status, error):
        raise DiagnosticError("inconsistent diagnostic result")
    if record["status"] == "passed":
        if (
            numeric["application_octets_observed"] != APPLICATION_OCTETS
            or observed is None
            or not hmac.compare_digest(
                cast(str, record["application_sha256_expected"]), observed
            )
            or numeric["accept_count"] != 1
            or record["clienthello_seen"] is not True
            or record["tls_established"] is not True
            or record["server_flight_sent"] is not True
            or record["application_complete"] is not True
            or record["usb_bcd_terminal"] != "9298"
        ):
            raise DiagnosticError("inconsistent diagnostic result")


def validate_diagnostic(record: dict[str, object]) -> None:
    lock = _read_artifact_lock()
    locked_diagnostic = lock["diagnostic"]
    if not isinstance(locked_diagnostic, dict):
        raise DiagnosticError("invalid artifact lock")
    _validate_diagnostic_against_lock(
        record, cast(dict[str, object], locked_diagnostic)
    )


def validate_rollback(record: dict[str, object]) -> None:
    _require_safe_object(record)
    exact = {
        "schema": ROLLBACK_SCHEMA,
        "status": "passed",
        "error_code": "none",
        "usb_vendor": DIAGNOSTIC_VENDOR,
        "usb_product_id": PRODUCTION_PRODUCT_ID,
        "usb_product": PRODUCTION_PRODUCT,
        "usb_serial": SERIAL,
        "usb_bcd_device": PRODUCTION_BCD,
        "usb_speed": USB_SPEED,
        "cdc0_interface": "00",
        "cdc1_interface": "02",
        "stage6_sha256": STAGE6_SHA256,
        "stage6_size": STAGE6_SIZE,
        "stage6_target_start": STAGE6_TARGET_START,
        "stage6_target_end": STAGE6_TARGET_END,
        "picotool_sha256": PICOTOOL_SHA256,
    }
    if set(record) != ROLLBACK_KEYS or any(record[name] != value for name, value in exact.items()) or type(record["duration_ns"]) is not int or record["duration_ns"] <= 0:
        raise DiagnosticError("invalid rollback evidence")


def validate_evidence(
    run_directory: pathlib.Path,
) -> tuple[dict[str, object], dict[str, object]]:
    descriptor = _directory_fd(run_directory)
    try:
        directory = os.fstat(descriptor)
        names = set(os.listdir(descriptor))
        if names != {"diagnostic.json", "rollback.json"}:
            raise DiagnosticError("incomplete evidence")
        diagnostic = _read_regular_json_at(descriptor, "diagnostic.json")
        rollback = _read_regular_json_at(descriptor, "rollback.json")
        try:
            observed = os.stat(run_directory, follow_symlinks=False)
        except OSError as error:
            raise DiagnosticError("unsafe directory") from error
        if (directory.st_dev, directory.st_ino) != (
            observed.st_dev,
            observed.st_ino,
        ):
            raise DiagnosticError("unsafe directory")
    finally:
        os.close(descriptor)
    validate_diagnostic(diagnostic)
    validate_rollback(rollback)
    return diagnostic, rollback


def publish_diagnostic(
    run_directory: pathlib.Path,
    client_state: pathlib.Path,
    event_journal: pathlib.Path,
    uf2: pathlib.Path,
    lock: pathlib.Path,
    rollback: pathlib.Path,
    production_raw: pathlib.Path,
) -> dict[str, object]:
    client = _read_regular_json(client_state)
    _validate_client_state(client)
    event = read_event_journal(event_journal)
    locked = verify_lock(lock, uf2, rollback, production_raw)
    diagnostic_artifact = _artifact_record(uf2)
    if locked["diagnostic"] != diagnostic_artifact:
        raise DiagnosticError("diagnostic artifact changed after lock verification")
    uf2_digest = cast(str, diagnostic_artifact["sha256"])
    uf2_size = cast(int, diagnostic_artifact["size"])
    terminal_bcd = client["usb_bcd_terminal"]
    client_status = client["status"]
    client_duration = client["duration_ns"]
    if (
        not isinstance(terminal_bcd, str)
        or not isinstance(client_status, str)
        or type(client_duration) is not int
    ):
        raise DiagnosticError("invalid client state")
    status, error_code = classify_boundary(terminal_bcd, event, client_status)
    record: dict[str, object] = {
        "schema": SCHEMA,
        "status": status,
        "error_code": error_code,
        "driver": DRIVER,
        "uefi_execution": UEFI_EXECUTION,
        "duration_ns": max(client_duration, cast(int, event["duration_ns"]), 1),
        "usb_vendor": DIAGNOSTIC_VENDOR,
        "usb_product_id": DIAGNOSTIC_PRODUCT_ID,
        "usb_product": DIAGNOSTIC_PRODUCT,
        "usb_serial": SERIAL,
        "usb_bcd_initial": DIAGNOSTIC_AWAITING_BCD,
        "usb_bcd_terminal": terminal_bcd,
        "usb_speed": USB_SPEED,
        "cdc_interface": CDC_INTERFACE,
        "pico_result": PICO_RESULTS[terminal_bcd],
        "diagnostic_uf2_sha256": uf2_digest,
        "diagnostic_uf2_size": uf2_size,
        "client_status": client_status,
        "server_status": event["status"],
        "server_error_code": event["error_code"],
        "application_octets_expected": APPLICATION_OCTETS,
        "application_octets_observed": client["application_octets_observed"],
        "application_sha256_expected": client["application_sha256_expected"],
        "application_sha256_observed": client["application_sha256_observed"],
        "accept_count": event["accept_count"],
        "clienthello_seen": event["clienthello_seen"],
        "tls_established": event["tls_established"],
        "server_flight_sent": event["server_flight_sent"],
        "application_complete": event["application_complete"],
    }
    locked_diagnostic = locked["diagnostic"]
    if not isinstance(locked_diagnostic, dict):
        raise DiagnosticError("invalid artifact lock")
    _validate_diagnostic_against_lock(
        record, cast(dict[str, object], locked_diagnostic)
    )
    _publish_json(run_directory, "diagnostic.json", record)
    return record


def record_rollback(
    run_directory: pathlib.Path,
    rollback_uf2: pathlib.Path,
    picotool: pathlib.Path,
    duration_ns: int,
    *,
    sysfs_root: pathlib.Path = pathlib.Path("/sys/bus/usb/devices"),
    tty_root: pathlib.Path = pathlib.Path("/sys/class/tty"),
    identity_verifier: Callable[[], dict[str, str]] | None = None,
) -> dict[str, object]:
    if identity_verifier is None:
        loopback = _load_module("pbns_diagnostic_loopback", "pico-loopback.py")
        identity_verifier = lambda: loopback.verify_hardware_identity(
            sysfs_root,
            tty_root,
            cdc0=pathlib.Path("/dev/ttyACM0"),
            cdc1=pathlib.Path("/dev/ttyACM1"),
            expected_serial=SERIAL,
        )
    try:
        identity = identity_verifier()
    except Exception as error:
        raise DiagnosticError("rollback identity mismatch") from error
    required_identity = {
        "vendor": DIAGNOSTIC_VENDOR,
        "product_id": PRODUCTION_PRODUCT_ID,
        "product": PRODUCTION_PRODUCT,
        "serial": SERIAL,
        "bcd_device": PRODUCTION_BCD,
        "speed": USB_SPEED,
        "cdc0_interface": "00",
        "cdc1_interface": "02",
    }
    if any(identity.get(name) != value for name, value in required_identity.items()):
        raise DiagnosticError("rollback identity mismatch")
    uf2_digest, uf2_size = _hash_regular(rollback_uf2)
    tool_digest, _tool_size = _hash_regular(picotool)
    summary = _load_uf2_module().verify_uf2_range(rollback_uf2)
    if (
        not hmac.compare_digest(uf2_digest, STAGE6_SHA256)
        or uf2_size != STAGE6_SIZE
        or summary.target_start != STAGE6_TARGET_START
        or summary.target_end != STAGE6_TARGET_END
        or not hmac.compare_digest(tool_digest, PICOTOOL_SHA256)
        or duration_ns <= 0
    ):
        raise DiagnosticError("rollback artifact mismatch")
    record: dict[str, object] = {
        "schema": ROLLBACK_SCHEMA,
        "status": "passed",
        "error_code": "none",
        "duration_ns": duration_ns,
        "usb_vendor": DIAGNOSTIC_VENDOR,
        "usb_product_id": PRODUCTION_PRODUCT_ID,
        "usb_product": PRODUCTION_PRODUCT,
        "usb_serial": SERIAL,
        "usb_bcd_device": PRODUCTION_BCD,
        "usb_speed": USB_SPEED,
        "cdc0_interface": "00",
        "cdc1_interface": "02",
        "stage6_sha256": uf2_digest,
        "stage6_size": uf2_size,
        "stage6_target_start": summary.target_start,
        "stage6_target_end": summary.target_end,
        "picotool_sha256": tool_digest,
    }
    validate_rollback(record)
    _publish_json(run_directory, "rollback.json", record)
    return record


def _read_sysfs(path: pathlib.Path, name: str) -> str:
    try:
        value = (path / name).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise DiagnosticError("identity unavailable") from error
    if not value or len(value) > 128:
        raise DiagnosticError("invalid identity")
    return value


def diagnostic_identity(sysfs_root: pathlib.Path, tty_root: pathlib.Path, *, terminal_bcd: bool = False) -> dict[str, str]:
    matches = []
    try:
        candidates = list(sysfs_root.iterdir())
    except OSError as error:
        raise DiagnosticError("identity unavailable") from error
    for candidate in candidates:
        try:
            if _read_sysfs(candidate, "idVendor").lower() == DIAGNOSTIC_VENDOR and _read_sysfs(candidate, "idProduct").lower() == DIAGNOSTIC_PRODUCT_ID and _read_sysfs(candidate, "serial") == SERIAL:
                matches.append(candidate)
        except DiagnosticError:
            continue
    if len(matches) != 1:
        raise DiagnosticError("ambiguous identity")
    device = matches[0]
    bcd = _read_sysfs(device, "bcdDevice").lower()
    if (
        _read_sysfs(device, "product") != DIAGNOSTIC_PRODUCT
        or _read_sysfs(device, "speed") != USB_SPEED
        or (bcd not in PICO_RESULTS if terminal_bcd else bcd != DIAGNOSTIC_AWAITING_BCD)
    ):
        raise DiagnosticError("unexpected diagnostic identity")
    try:
        terminal_root = tty_root / "ttyACM0"
        terminal_path = (terminal_root / "device").resolve(strict=True)
        interface = next(item for item in (terminal_path, *terminal_path.parents) if (item / "bInterfaceNumber").is_file())
        interface_number = _read_sysfs(interface, "bInterfaceNumber")
        device_number = _read_sysfs(terminal_root, "dev")
    except (OSError, StopIteration) as error:
        raise DiagnosticError("CDC identity unavailable") from error
    if interface.name.split(":", 1)[0] != device.name or interface_number != CDC_INTERFACE or re.fullmatch(r"[0-9]+:[0-9]+", device_number) is None:
        raise DiagnosticError("unexpected CDC identity")
    associated = []
    try:
        terminals = list(tty_root.glob("ttyACM*"))
    except OSError as error:
        raise DiagnosticError("CDC identity unavailable") from error
    for terminal in terminals:
        try:
            resolved = (terminal / "device").resolve(strict=True)
        except OSError:
            continue
        if any(item.name.split(":", 1)[0] == device.name for item in (resolved, *resolved.parents)):
            associated.append(terminal.name)
    if sorted(associated) != ["ttyACM0"]:
        raise DiagnosticError("unexpected diagnostic CDC count")
    return {"device": device.name, "bcd": bcd, "dev": device_number, "interface": interface_number}


def _client_error_detail(error: Exception) -> str:
    reason = getattr(error, "tls_reason", None)
    if isinstance(reason, str) and re.fullmatch(r"[A-Z0-9_]{1,64}", reason):
        return f"tls-{reason.lower()}"
    current: BaseException | None = error
    for _depth in range(4):
        if current is None:
            break
        reason = getattr(current, "reason", None)
        if isinstance(reason, str) and re.fullmatch(r"[A-Z0-9_]{1,64}", reason):
            return f"tls-{reason.lower()}"
        if current.__class__.__module__.startswith("serial."):
            return "serial"
        if isinstance(current, OSError):
            return f"os-errno-{current.errno}" if isinstance(current.errno, int) else "os"
        if isinstance(current, ValueError):
            return "value"
        current = current.__cause__
    return "exception"


def _write_client_state(path: pathlib.Path, value: dict[str, object]) -> None:
    parent_fd = _directory_fd(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        _write_all(descriptor, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
        os.fsync(descriptor)
        os.close(descriptor)
        os.fsync(parent_fd)
    except OSError as error:
        raise DiagnosticError("cannot write client state") from error
    finally:
        os.close(parent_fd)


def run_client(arguments: argparse.Namespace, *, serial_factory: Callable[..., OpenedSerial] | None = None) -> dict[str, object]:
    started = time.monotonic_ns()
    if arguments.timeout <= 0 or arguments.timeout > 60:
        raise DiagnosticError("invalid timeout")
    deadline_ns = started + int(arguments.timeout * 1_000_000_000)
    initial = diagnostic_identity(arguments.sysfs_root, arguments.tty_root)
    if serial_factory is None:
        try:
            import serial  # type: ignore[import-untyped]
        except ImportError as error:
            raise DiagnosticError("serial unavailable") from error
        serial_factory = lambda **keywords: serial.Serial(**keywords)
    serial_port: OpenedSerial | None = None
    status = "failed"
    error_code = "io"
    observed = bytearray()
    expected_digest = hashlib.sha256(
        _load_module("pbns_tls_diagnostic", "uefi-tls-tunnel.py").deterministic_chunk(0, APPLICATION_OCTETS)
    ).hexdigest()
    observed_digest: str | None = None
    try:
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise DiagnosticError("timeout")
        serial_port = serial_factory(
            port="/dev/ttyACM0", baudrate=115200, timeout=remaining,
            write_timeout=remaining, exclusive=True,
        )
        metadata = os.fstat(serial_port.fileno())
        if not stat.S_ISCHR(metadata.st_mode) or f"{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}" != initial["dev"]:
            raise DiagnosticError("CDC node mismatch")
        after = diagnostic_identity(arguments.sysfs_root, arguments.tty_root)
        if after != initial:
            raise DiagnosticError("CDC identity changed")
        tls_module = _load_module("pbns_tls_diagnostic_client", "uefi-tls-tunnel.py")
        pin = tls_module.load_pin(arguments.pin)
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise DiagnosticError("timeout")
        if hasattr(serial_port, "timeout"):
            setattr(serial_port, "timeout", remaining)
        if hasattr(serial_port, "write_timeout"):
            setattr(serial_port, "write_timeout", remaining)
        tls = tls_module.TlsSerialClient(
            serial_port, expected_san=arguments.expected_san,
            expected_spki=pin, timeout_seconds=remaining,
        )
        observed.extend(tls.read_exact(APPLICATION_OCTETS))
        observed_digest = hashlib.sha256(observed).hexdigest()
        if (
            len(observed) != APPLICATION_OCTETS
            or not hmac.compare_digest(observed_digest, expected_digest)
            or time.monotonic_ns() >= deadline_ns
        ):
            raise DiagnosticError("application mismatch")
        status = "passed"
        error_code = "none"
    except Exception as error:
        status = "failed"
        candidate = getattr(error, "code", None)
        error_code = candidate if isinstance(candidate, str) and candidate in CLIENT_ERRORS else "io"
        detail = _client_error_detail(error)
        print(f"[DIAGNOSTIC CLIENT ERROR] {error_code} {detail}", file=sys.stderr)
    finally:
        for index in range(len(observed)):
            observed[index] = 0
        if serial_port is not None:
            serial_port.close()
    operation_finished_ns = time.monotonic_ns()
    terminal_bcd = ""
    terminal_deadline_ns = operation_finished_ns + TERMINAL_OBSERVATION_NS
    while time.monotonic_ns() < terminal_deadline_ns:
        try:
            terminal_bcd = diagnostic_identity(
                arguments.sysfs_root, arguments.tty_root, terminal_bcd=True
            )["bcd"]
            break
        except DiagnosticError:
            time.sleep(0.05)
    if terminal_bcd not in PICO_RESULTS:
        status = "failed"
        error_code = "timeout"
    state: dict[str, object] = {
        "status": status,
        "error_code": error_code,
        "duration_ns": max(operation_finished_ns - started, 1),
        "usb_bcd_initial": initial["bcd"],
        "usb_bcd_terminal": terminal_bcd,
        "application_octets_observed": APPLICATION_OCTETS if observed_digest is not None else 0,
        "application_sha256_expected": expected_digest,
        "application_sha256_observed": observed_digest,
    }
    _write_client_state(arguments.state_file, state)
    return state


def _artifact_record(path: pathlib.Path) -> dict[str, object]:
    digest, size = _hash_regular(path)
    summary = _load_uf2_module().verify_uf2_range(path)
    return {
        "sha256": digest,
        "size": size,
        "target_start": summary.target_start,
        "target_end": summary.target_end,
    }


def lock_artifacts(uf2: pathlib.Path, rollback: pathlib.Path, production_raw: pathlib.Path) -> dict[str, object]:
    diagnostic = _artifact_record(uf2)
    rollback_record = _artifact_record(rollback)
    production_record = _artifact_record(production_raw)
    record: dict[str, object] = {
        "schema": LOCK_SCHEMA,
        "diagnostic": diagnostic,
        "rollback": rollback_record,
        "production_raw": production_record,
    }
    if (
        rollback_record["sha256"] != STAGE6_SHA256
        or rollback_record["size"] != STAGE6_SIZE
        or production_record["sha256"] != PRODUCTION_RAW_SHA256
        or production_record["size"] != PRODUCTION_RAW_SIZE
    ):
        raise DiagnosticError("locked artifact mismatch")
    return record


def write_lock(output: pathlib.Path, record: dict[str, object]) -> None:
    parent_flags = os.O_RDONLY | os.O_DIRECTORY
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
        file_flags |= os.O_NOFOLLOW
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = os.open(output.parent, parent_flags)
        parent = os.fstat(parent_fd)
        observed_parent = os.stat(output.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) not in (0o700, 0o755)
            or (parent.st_dev, parent.st_ino)
            != (observed_parent.st_dev, observed_parent.st_ino)
        ):
            raise DiagnosticError("unsafe artifact lock directory")
        descriptor = os.open(output.name, file_flags, 0o644, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o644)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(parent_fd)
    except OSError as error:
        raise DiagnosticError("cannot write artifact lock") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def verify_lock(
    lock: pathlib.Path,
    uf2: pathlib.Path,
    rollback: pathlib.Path,
    production_raw: pathlib.Path,
    picotool: pathlib.Path | None = None,
) -> dict[str, object]:
    observed = _read_regular_json(lock, mode=0o644)
    expected = lock_artifacts(uf2, rollback, production_raw)
    _validate_lock_record(observed)
    _validate_lock_record(expected)
    if observed != expected:
        raise DiagnosticError("artifact lock mismatch")
    if picotool is not None and _hash_regular(picotool)[0] != PICOTOOL_SHA256:
        raise DiagnosticError("picotool mismatch")
    return expected


def self_test() -> None:
    base = {
        "schema": EVENT_SCHEMA, "status": "passed", "error_code": "none",
        "ready": True, "process_alive": False, "accept_count": 1,
        "clienthello_seen": True, "tls_established": True,
        "server_flight_sent": True, "application_complete": True,
        "duration_ns": 1,
    }
    if classify_boundary("9298", base, "passed") != ("passed", "none"):
        raise DiagnosticError("self-test failed")
    failed = dict(base)
    failed["status"] = "failed"
    failed["error_code"] = "io"
    failed["tls_established"] = False
    failed["application_complete"] = False
    if classify_boundary("9211", failed, "failed")[1] != "tcp-receive-boundary":
        raise DiagnosticError("self-test failed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PBNS raw tunnel diagnostic evidence driver")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("self-test")
    create = commands.add_parser("create-run")
    create.add_argument("--results-root", required=True, type=pathlib.Path)
    create.add_argument("--timestamp")
    client = commands.add_parser("client")
    client.add_argument("--state-file", required=True, type=pathlib.Path)
    client.add_argument("--pin", required=True, type=pathlib.Path)
    client.add_argument("--expected-san", required=True)
    client.add_argument("--timeout", type=float, default=60.0)
    client.add_argument("--sysfs-root", type=pathlib.Path, default=pathlib.Path("/sys/bus/usb/devices"))
    client.add_argument("--tty-root", type=pathlib.Path, default=pathlib.Path("/sys/class/tty"))
    publish = commands.add_parser("publish-diagnostic")
    publish.add_argument("--run-dir", required=True, type=pathlib.Path)
    publish.add_argument("--client-state", required=True, type=pathlib.Path)
    publish.add_argument("--event-journal", required=True, type=pathlib.Path)
    publish.add_argument("--uf2", required=True, type=pathlib.Path)
    publish.add_argument("--lock", required=True, type=pathlib.Path)
    publish.add_argument("--rollback", required=True, type=pathlib.Path)
    publish.add_argument("--production-raw", required=True, type=pathlib.Path)
    rollback = commands.add_parser("record-rollback")
    rollback.add_argument("--run-dir", required=True, type=pathlib.Path)
    rollback.add_argument("--rollback", required=True, type=pathlib.Path)
    rollback.add_argument("--picotool", required=True, type=pathlib.Path)
    rollback.add_argument("--duration-ns", required=True, type=int)
    rollback.add_argument("--sysfs-root", type=pathlib.Path, default=pathlib.Path("/sys/bus/usb/devices"))
    rollback.add_argument("--tty-root", type=pathlib.Path, default=pathlib.Path("/sys/class/tty"))
    validate = commands.add_parser("validate-evidence")
    validate.add_argument("--run-dir", required=True, type=pathlib.Path)
    lock = commands.add_parser("lock-artifact")
    lock.add_argument("--uf2", required=True, type=pathlib.Path)
    lock.add_argument("--rollback", required=True, type=pathlib.Path)
    lock.add_argument("--production-raw", required=True, type=pathlib.Path)
    lock.add_argument("--output", required=True, type=pathlib.Path)
    verify = commands.add_parser("verify-lock")
    verify.add_argument("--lock", required=True, type=pathlib.Path)
    verify.add_argument("--uf2", required=True, type=pathlib.Path)
    verify.add_argument("--rollback", required=True, type=pathlib.Path)
    verify.add_argument("--production-raw", required=True, type=pathlib.Path)
    verify.add_argument("--picotool", type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "self-test":
            self_test()
            print("RAW TUNNEL DIAGNOSTIC SELF-TEST PASS")
        elif arguments.command == "create-run":
            print(create_run_directory(arguments.results_root, arguments.timestamp))
        elif arguments.command == "client":
            result = run_client(arguments)
            if result["status"] != "passed":
                raise DiagnosticError("client failed")
            print("RAW TUNNEL DIAGNOSTIC CLIENT PASS")
        elif arguments.command == "publish-diagnostic":
            publish_diagnostic(
                arguments.run_dir,
                arguments.client_state,
                arguments.event_journal,
                arguments.uf2,
                arguments.lock,
                arguments.rollback,
                arguments.production_raw,
            )
            print("RAW TUNNEL DIAGNOSTIC PUBLISH PASS")
        elif arguments.command == "record-rollback":
            record_rollback(
                arguments.run_dir,
                arguments.rollback,
                arguments.picotool,
                arguments.duration_ns,
                sysfs_root=arguments.sysfs_root,
                tty_root=arguments.tty_root,
            )
            print("RAW TUNNEL DIAGNOSTIC ROLLBACK PASS")
        elif arguments.command == "validate-evidence":
            validate_evidence(arguments.run_dir)
            print("RAW TUNNEL DIAGNOSTIC EVIDENCE PASS")
        elif arguments.command == "lock-artifact":
            write_lock(arguments.output, lock_artifacts(arguments.uf2, arguments.rollback, arguments.production_raw))
            print("RAW TUNNEL DIAGNOSTIC LOCK PASS")
        else:
            verify_lock(
                arguments.lock,
                arguments.uf2,
                arguments.rollback,
                arguments.production_raw,
                arguments.picotool,
            )
            print("RAW TUNNEL DIAGNOSTIC LOCK PASS")
    except (DiagnosticError, OSError, ValueError):
        print("raw tunnel diagnostic failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
