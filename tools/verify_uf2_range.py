#!/usr/bin/env python3

import argparse
import pathlib
import struct
import sys
from dataclasses import dataclass


UF2_BLOCK_BYTES = 512
UF2_DATA_OFFSET = 32
UF2_END_OFFSET = 508
UF2_MAX_PAYLOAD = UF2_END_OFFSET - UF2_DATA_OFFSET
UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
DEFAULT_START = 0x10000000
DEFAULT_END = 0x101FE000
UINT32_LIMIT = 1 << 32


class Uf2Error(ValueError):
    pass


@dataclass(frozen=True)
class Uf2Summary:
    block_count: int
    target_start: int
    target_end: int


def _read_regular_file(path: pathlib.Path) -> bytes:
    try:
        encoded = path.read_bytes()
    except OSError as error:
        raise Uf2Error("cannot read UF2") from error
    if not encoded or len(encoded) % UF2_BLOCK_BYTES != 0:
        raise Uf2Error("invalid UF2 length")
    return encoded


def verify_uf2_range(
    path: pathlib.Path,
    *,
    allowed_start: int = DEFAULT_START,
    allowed_end: int = DEFAULT_END,
) -> Uf2Summary:
    if not 0 <= allowed_start < allowed_end <= UINT32_LIMIT:
        raise Uf2Error("invalid allowed range")
    encoded = _read_regular_file(path)
    file_blocks = len(encoded) // UF2_BLOCK_BYTES
    expected_count: int | None = None
    seen_numbers: set[int] = set()
    ranges: list[tuple[int, int]] = []
    for offset in range(0, len(encoded), UF2_BLOCK_BYTES):
        block = encoded[offset : offset + UF2_BLOCK_BYTES]
        (
            magic0,
            magic1,
            _flags,
            target,
            payload_size,
            block_number,
            block_count,
            _family_or_size,
        ) = struct.unpack_from("<8I", block)
        (end_magic,) = struct.unpack_from("<I", block, UF2_END_OFFSET)
        if (
            magic0 != UF2_MAGIC_START0
            or magic1 != UF2_MAGIC_START1
            or end_magic != UF2_MAGIC_END
        ):
            raise Uf2Error("invalid UF2 magic")
        if payload_size == 0 or payload_size > UF2_MAX_PAYLOAD:
            raise Uf2Error("invalid UF2 payload size")
        if block_count == 0 or block_count != file_blocks:
            raise Uf2Error("invalid UF2 block count")
        if expected_count is None:
            expected_count = block_count
        elif block_count != expected_count:
            raise Uf2Error("inconsistent UF2 block count")
        if block_number >= block_count or block_number in seen_numbers:
            raise Uf2Error("invalid UF2 block number")
        seen_numbers.add(block_number)
        if target > UINT32_LIMIT - payload_size:
            raise Uf2Error("UF2 target wraps")
        target_end = target + payload_size
        if target < allowed_start or target_end > allowed_end:
            raise Uf2Error("UF2 target outside allowed range")
        ranges.append((target, target_end))
    if seen_numbers != set(range(file_blocks)):
        raise Uf2Error("missing UF2 block number")
    ranges.sort()
    for previous, current in zip(ranges, ranges[1:]):
        if current[0] < previous[1]:
            raise Uf2Error("overlapping UF2 target ranges")
    return Uf2Summary(
        block_count=file_blocks,
        target_start=ranges[0][0],
        target_end=max(end for _start, end in ranges),
    )


def _integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("invalid integer") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a bounded UF2 target range")
    parser.add_argument("uf2", type=pathlib.Path)
    parser.add_argument(
        "--start", "--flash-start", dest="start", type=_integer, default=DEFAULT_START
    )
    parser.add_argument(
        "--end", "--flash-end", dest="end", type=_integer, default=DEFAULT_END
    )
    arguments = parser.parse_args(argv)
    try:
        summary = verify_uf2_range(
            arguments.uf2,
            allowed_start=arguments.start,
            allowed_end=arguments.end,
        )
    except Uf2Error:
        print("UF2 range validation failed", file=sys.stderr)
        return 1
    print(
        "UF2 RANGE PASS "
        f"blocks={summary.block_count} "
        f"start=0x{summary.target_start:08x} end=0x{summary.target_end:08x}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
