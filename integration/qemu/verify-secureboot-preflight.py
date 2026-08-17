#!/usr/bin/env python3
"""Require exact, bounded SecureBoot and SetupMode dmpstore output."""

import argparse
import pathlib
import re
import sys

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
GLOBAL_GUID = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"
# OVMF dmpstore renders this exact GUID as its canonical namespace label.
GLOBAL_NAMESPACE = "EFIGlobalVariable"
HEADER = re.compile(
    rf"^Variable (?:[A-Z0-9+]+ )?'{GLOBAL_NAMESPACE}:(SecureBoot|SetupMode)' DataSize = 0x01$"
)
ROW = re.compile(r"^\s*00000000:\s+(00|01)(?:\s{2,}\*.*\*)?$")


def normalize(serial: str) -> list[str]:
    serial = ANSI.sub("", serial).replace("\r", "")
    return [CONTROL.sub("", line) for line in serial.split("\n")]


def marker_index(lines: list[str], marker: str) -> int:
    indexes = [index for index, line in enumerate(lines) if line == marker]
    if len(indexes) != 1:
        raise ValueError(f"{marker} count")
    return indexes[0]


def validate_block(lines: list[str], begin: int, end: int, name: str, value: str) -> None:
    if begin >= end:
        raise ValueError(f"{name} marker bounds")
    block = [line for line in lines[begin + 1 : end] if line != ""]
    if len(block) != 2:
        raise ValueError(f"{name} block shape")
    header = HEADER.fullmatch(block[0])
    if header is None or header.group(1) != name:
        raise ValueError(f"{name} header")
    row = ROW.fullmatch(block[1])
    if row is None or row.group(1) != value:
        raise ValueError(f"{name} data")


def validate_serial(serial: str) -> None:
    lines = normalize(serial)
    secure_begin = marker_index(lines, "PBNS-SB-BEGIN-SecureBoot")
    secure_end = marker_index(lines, "PBNS-SB-END-SecureBoot")
    setup_begin = marker_index(lines, "PBNS-SB-BEGIN-SetupMode")
    setup_end = marker_index(lines, "PBNS-SB-END-SetupMode")
    if not secure_begin < secure_end < setup_begin < setup_end:
        raise ValueError("marker global order")
    validate_block(lines, secure_begin, secure_end, "SecureBoot", "01")
    validate_block(lines, setup_begin, setup_end, "SetupMode", "00")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.serial.is_symlink() or not arguments.serial.is_file():
            raise ValueError("serial input")
        validate_serial(arguments.serial.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"secure boot serial oracle failed: {error}", file=sys.stderr)
        return 1
    print("PBNS SECUREBOOT SERIAL ORACLE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
