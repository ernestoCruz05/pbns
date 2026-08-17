#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac
import pathlib
import re
import sys
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Protocol


MAX_RECORD_SIZE = 448
MAX_RESPONSE_SIZE = 96
READY = b"PBNS-PROVISION-v1 READY\n"
FINGERPRINT = re.compile(rb"OK ([0-9a-f]{64})\r?\n")
RECONNECT_DELAY_SECONDS = 0.1
MAX_SESSION_ATTEMPTS = 2


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...

    def flush(self) -> None: ...

    def readline(self, size: int = -1) -> bytes: ...


class ProvisioningError(Exception):
    pass


def _write_all(serial_port: SerialPort, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = serial_port.write(data[offset:])
        if written <= 0 or written > len(data) - offset:
            raise ProvisioningError("serial write failed")
        offset += written
    serial_port.flush()


def _validate_record(record: bytes) -> None:
    if not isinstance(record, bytes) or not 1 <= len(record) <= MAX_RECORD_SIZE:
        raise ProvisioningError("invalid credential record")


def _provision_ready_session(serial_port: SerialPort, record: bytes) -> str:
    _write_all(serial_port, b"SET " + base64.b64encode(record) + b"\n")
    response = serial_port.readline(MAX_RESPONSE_SIZE)
    match = FINGERPRINT.fullmatch(response)
    if match is None:
        if response.startswith(b"ERROR"):
            raise ProvisioningError("device rejected provisioning")
        raise ProvisioningError("invalid device response")

    expected = hashlib.sha256(record).hexdigest()
    received = match.group(1).decode("ascii")
    if not hmac.compare_digest(received, expected):
        raise ProvisioningError("device returned the wrong record fingerprint")
    _write_all(serial_port, b"REBOOT\n")
    return expected


def provision(serial_port: SerialPort, record: bytes) -> str:
    _validate_record(record)
    response = serial_port.readline(MAX_RESPONSE_SIZE)
    if response == b"":
        raise ProvisioningError("device is not in physical provisioning mode")
    if response != READY:
        raise ProvisioningError("unexpected provisioning banner")
    return _provision_ready_session(serial_port, record)


def provision_with_reconnect(
    open_port: Callable[[], AbstractContextManager[SerialPort]],
    record: bytes,
    wait: Callable[[float], None] = time.sleep,
) -> str:
    _validate_record(record)
    for attempt in range(MAX_SESSION_ATTEMPTS):
        with open_port() as serial_port:
            response = serial_port.readline(MAX_RESPONSE_SIZE)
            if response == READY:
                return _provision_ready_session(serial_port, record)
            if response != b"":
                raise ProvisioningError("unexpected provisioning banner")
        if attempt + 1 < MAX_SESSION_ATTEMPTS:
            wait(RECONNECT_DELAY_SECONDS)
    raise ProvisioningError("device is not in physical provisioning mode")


def _read_record(path: pathlib.Path) -> bytes:
    try:
        with path.open("rb") as stream:
            return stream.read(MAX_RECORD_SIZE + 1)
    except OSError as error:
        raise ProvisioningError("cannot read credential record") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision a PBNS Pico through its physical-mode CDC interface"
    )
    parser.add_argument("--port", required=True)
    parser.add_argument("--record", required=True, type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        import serial
    except ImportError:
        print("provisioning failed: pyserial is not installed", file=sys.stderr)
        return 1

    try:
        record = _read_record(args.record)

        def open_port():
            return serial.Serial(
                args.port,
                baudrate=115200,
                timeout=5,
                write_timeout=5,
                exclusive=True,
            )

        fingerprint = provision_with_reconnect(open_port, record)
    except (ProvisioningError, OSError) as error:
        print(f"provisioning failed: {error}", file=sys.stderr)
        return 1
    print(f"provisioned record {fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
