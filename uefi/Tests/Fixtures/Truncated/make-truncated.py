#!/usr/bin/env python3

import argparse
import os
import pathlib
import struct


def section_ranges(encoded: bytes) -> list[tuple[int, int]]:
    if len(encoded) < 64 or encoded[:2] != b"MZ":
        raise ValueError("input has no DOS header")
    pe_offset = struct.unpack_from("<I", encoded, 0x3C)[0]
    if pe_offset + 24 > len(encoded) or encoded[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("input has no complete PE signature")
    section_count = struct.unpack_from("<H", encoded, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", encoded, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_size
    if section_count == 0 or section_table + (section_count * 40) > len(encoded):
        raise ValueError("input has no complete section table")
    ranges = []
    for index in range(section_count):
        entry = section_table + (index * 40)
        raw_size, raw_offset = struct.unpack_from("<II", encoded, entry + 16)
        if raw_size > 1 and raw_offset < len(encoded):
            ranges.append((raw_offset, raw_size))
    if not ranges:
        raise ValueError("input has no truncatable section data")
    return ranges


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()

    encoded = args.input.read_bytes()
    raw_offset, raw_size = max(section_ranges(encoded), key=lambda item: item[1])
    cutoff = raw_offset + max(1, raw_size // 2)
    if cutoff >= len(encoded) or cutoff <= raw_offset:
        raise ValueError("selected truncation point is outside section data")
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded[:cutoff])
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
