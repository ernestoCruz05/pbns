#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import sys
from typing import Any


CRC32C_POLYNOMIAL = 0x82F63B78


def crc32c(data: bytes) -> int:
    value = 0xFFFFFFFF
    for octet in data:
        value ^= octet
        for _ in range(8):
            value = (value >> 1) ^ CRC32C_POLYNOMIAL if value & 1 else value >> 1
    return (~value) & 0xFFFFFFFF


def cobs_encode(data: bytes) -> bytes:
    output = bytearray((0,))
    code_index = 0
    code = 1
    for octet in data:
        if octet == 0:
            output[code_index] = code
            code_index = len(output)
            output.append(0)
            code = 1
            continue
        output.append(octet)
        code += 1
        if code == 0xFF:
            output[code_index] = code
            code_index = len(output)
            output.append(0)
            code = 1
    output[code_index] = code
    return bytes(output)


def build_case(
    name: str,
    service: int,
    message_type: int,
    sequence: int,
    request_id: bytes,
    payload: bytes,
) -> dict[str, Any]:
    prefix = (
        b"PBNS"
        + bytes((1, service, message_type, 0))
        + request_id
        + struct.pack(">II", sequence, len(payload))
    )
    header = prefix + struct.pack(">I", crc32c(prefix))
    raw = header + payload
    raw += struct.pack(">I", crc32c(raw))
    encoded = cobs_encode(raw)
    return {
        "name": name,
        "service": service,
        "message_type": message_type,
        "flags": 0,
        "request_id_hex": request_id.hex(),
        "sequence": sequence,
        "payload_hex": payload.hex(),
        "raw_hex": raw.hex(),
        "cobs_hex": encoded.hex(),
        "wire_hex": (encoded + b"\x00").hex(),
    }


def vectors() -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "header_size": 36,
        "trailer_size": 4,
        "control_payload_max": 65536,
        "data_payload_max": 16384,
        "cases": [
            build_case(
                "empty-time-request",
                service=1,
                message_type=1,
                sequence=0,
                request_id=bytes(range(16)),
                payload=b"",
            ),
            build_case(
                "maximum-recovery-data",
                service=2,
                message_type=3,
                sequence=7,
                request_id=bytes(range(0x10, 0x20)),
                payload=bytes(index & 0xFF for index in range(16384)),
            ),
        ],
    }


def encoded_vectors() -> str:
    return json.dumps(vectors(), indent=2, sort_keys=True) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create or verify PBNS frame vectors")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", type=pathlib.Path)
    mode.add_argument("--verify", type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    expected = encoded_vectors()
    if args.write is not None:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(expected, encoding="utf-8")
        print(f"wrote {args.write}")
        return 0

    try:
        actual = args.verify.read_text(encoding="utf-8")
    except OSError as error:
        print(f"cannot read {args.verify}: {error}", file=sys.stderr)
        return 1
    if actual != expected:
        print(f"frame vectors differ: {args.verify}", file=sys.stderr)
        return 1
    print("FRAME VECTOR PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
