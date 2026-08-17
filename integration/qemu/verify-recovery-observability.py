#!/usr/bin/env python3
import argparse
import os
import pathlib
import re
import stat


class VerificationError(Exception):
    pass


HASH = re.compile(r"[0-9a-f]{64}\n?")
STREAM_DURATION = re.compile(r"(?m)^PBNS RECOVERY STREAM DURATION MS=(0|[1-9][0-9]*)\r?$")
STREAM_DURATION_LINE = re.compile(r"(?m)^PBNS RECOVERY STREAM DURATION MS=.*\r?$")
STREAM_DURATION_MAX_MS = 60000
FORBIDDEN = re.compile(
    r"private[ _-]*key|identity[ _-]*(?:material|key|cose)|"
    r"tpm[ _-]*(?:blob|auth|authorization|session|nonce)|auth[ _-]*value|"
    r"session[ _-]*nonce|token|nonce|decrypted[ _-]*transcript|"
    r"policy[ _-]*(?:authorization|internal)|artifact[ _-]*bytes|"
    r"transient[ _-]*crypto|request[ _-]*(?:id|binding)",
    re.IGNORECASE,
)
SERIAL_LIMIT = 8 * 1024 * 1024


def _read_bounded(path: pathlib.Path, maximum: int) -> bytes:
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW
    except AttributeError as error:
        raise VerificationError("O_NOFOLLOW is unavailable") from error
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError("cannot open evidence") from error
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                stat.S_IMODE(before.st_mode) != 0o600):
            raise VerificationError("evidence is not an owned mode-0600 regular file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise VerificationError("evidence size is outside the bound")
        value = bytearray()
        remaining = before.st_size
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise VerificationError("evidence changed while reading")
            value.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise VerificationError("evidence changed while reading")
        after = os.fstat(descriptor)
    except OSError as error:
        raise VerificationError("cannot read evidence") from error
    finally:
        os.close(descriptor)
    metadata = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns)
    final_metadata = (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                      after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns,
                      after.st_ctime_ns)
    if len(value) != before.st_size or metadata != final_metadata:
        raise VerificationError("evidence changed while reading")
    return bytes(value)


def _version(path: pathlib.Path) -> int:
    encoded = _read_bounded(path, 8)
    if len(encoded) != 8:
        raise VerificationError("NV evidence is not exactly eight bytes")
    return int.from_bytes(encoded, "big")


def _disk_hash(path: pathlib.Path) -> str:
    encoded = _read_bounded(path, 65)
    try:
        value = encoded.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError("disk hash is not ASCII") from error
    if HASH.fullmatch(value) is None:
        raise VerificationError("disk hash is not canonical")
    return value.strip()


def _unique_line(text: str, expected: str) -> int:
    matches = list(re.finditer(rf"(?m)^{re.escape(expected)}\r?$", text))
    if len(matches) != 1:
        raise VerificationError("runtime marker is missing or duplicated")
    return matches[0].start()


def _stream_duration_offset(text: str) -> tuple[int, int]:
    lines = list(STREAM_DURATION_LINE.finditer(text))
    matches = list(STREAM_DURATION.finditer(text))
    if (len(lines) != 1 or len(matches) != 1 or
            int(matches[0].group(1)) > STREAM_DURATION_MAX_MS):
        raise VerificationError("stream duration is missing, malformed, or out of bounds")
    return matches[0].start(), int(matches[0].group(1))


def verify(
    serial: pathlib.Path,
    nv_before: pathlib.Path,
    nv_after: pathlib.Path,
    disk_before: pathlib.Path,
    disk_after: pathlib.Path,
    case_root: pathlib.Path,
    *,
    expected_size: int,
    current_version: int,
    target_version: int,
    case: str = "signed-trusted",
) -> int | None:
    production_failures = {
        "unsigned-untrusted", "truncated", "forged-manifest", "downgrade"
    }
    if (expected_size <= 0 or current_version < 0 or
            case not in production_failures | {"signed-trusted"} or
            (case == "signed-trusted" and target_version <= current_version) or
            (case != "signed-trusted" and
             ((case == "downgrade" and target_version != current_version) or
              (case != "downgrade" and target_version <= current_version)))):
        raise VerificationError("invalid expected recovery transition")
    encoded = _read_bounded(serial, SERIAL_LIMIT)
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("serial evidence is not UTF-8") from error
    if FORBIDDEN.search(text):
        raise VerificationError("serial evidence failed the secret audit")
    if case != "signed-trusted":
        failure = {
            "unsigned-untrusted": (
                *(f"PBNS RECOVERY STATE {number}" for number in range(7)),
                f"PBNS RECOVERY MEMORY LOAD BEGIN size={expected_size} version={target_version}",
                "PBNS RECOVERY MEMORY LOAD REJECT",
                f"PBNS RECOVERY FREE BEGIN size={expected_size}", "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9", "PBNS RECOVERY FAILED stage=6",
            ),
            "truncated": (
                *(f"PBNS RECOVERY STATE {number}" for number in range(7)),
                f"PBNS RECOVERY MEMORY LOAD BEGIN size={expected_size} version={target_version}",
                "PBNS RECOVERY MEMORY LOAD REJECT",
                f"PBNS RECOVERY FREE BEGIN size={expected_size}", "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9", "PBNS RECOVERY FAILED stage=6",
            ),
            "forged-manifest": (
                "PBNS RECOVERY STATE 0", "PBNS RECOVERY STATE 1",
                "PBNS RECOVERY STATE 2", "PBNS RECOVERY STATE 9",
                "PBNS RECOVERY FAILED stage=2",
            ),
            "downgrade": (
                *(f"PBNS RECOVERY STATE {number}" for number in range(6)),
                f"PBNS RECOVERY FREE BEGIN size={expected_size}", "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9", "PBNS RECOVERY FAILED stage=5 status=-15",
            ),
        }[case]
        offsets: list[int] = []
        for marker in failure:
            if marker == "PBNS RECOVERY MEMORY LOAD REJECT":
                matches = list(re.finditer(r"(?m)^PBNS RECOVERY MEMORY LOAD REJECT status=0x[0-9A-Fa-f]+\r?$", text))
                if len(matches) != 1:
                    raise VerificationError("runtime marker is missing or duplicated")
                offsets.append(matches[0].start())
            elif marker.startswith("PBNS RECOVERY FAILED stage=") and marker != "PBNS RECOVERY FAILED stage=5 status=-15":
                matches = list(re.finditer(rf"(?m)^{re.escape(marker)} status=-?[0-9]+\r?$", text))
                if len(matches) != 1:
                    raise VerificationError("runtime marker is missing or duplicated")
                offsets.append(matches[0].start())
            else:
                offsets.append(_unique_line(text, marker))
        forbidden = (
            "PBNS RECOVERY MEMORY LOAD PASS", "PBNS RECOVERY ROLLBACK ADVANCE",
            "PBNS RECOVERY STARTIMAGE", "PBNS RECOVERY STATE 7",
            "PBNS RECOVERY STATE 8", "PBNS RECOVERY UNLOAD",
        )
        if (offsets != sorted(offsets) or len(set(offsets)) != len(offsets) or
                any(marker in text for marker in forbidden) or
                len(re.findall(r"(?m)^PBNS RECOVERY FAILED stage=[0-9]+ status=-?[0-9]+\r?$", text)) != 1 or
                (case == "forged-manifest" and
                 (re.search(r"(?m)^PBNS RECOVERY STATE [3-8]\r?$", text) is not None or
                  any(marker in text for marker in ("PBNS RECOVERY FREE", "PBNS RECOVERY MEMORY LOAD")))) or
                _version(nv_before) != current_version or _version(nv_after) != current_version or
                _disk_hash(disk_before) != _disk_hash(disk_after)):
            raise VerificationError("production failure evidence is invalid")
        _assert_no_events(case_root)
        return None
    for forbidden in (
        "PBNS RECOVERY MEMORY LOAD REJECT",
        "PBNS RECOVERY FAILED",
        "PBNS RECOVERY FALLBACK",
        "PBNS RECOVERY STATE 9",
    ):
        if forbidden in text:
            raise VerificationError("signed recovery contains a failure marker")
    expected = (
        "PBNS RECOVERY STATE 0",
        "PBNS RECOVERY STATE 1",
        "PBNS RECOVERY STATE 2",
        "PBNS RECOVERY STATE 3",
        "PBNS RECOVERY STATE 4",
        "PBNS RECOVERY STATE 5",
        "PBNS RECOVERY STATE 6",
        f"PBNS RECOVERY MEMORY LOAD BEGIN size={expected_size} version={target_version}",
        "PBNS RECOVERY MEMORY LOAD PASS",
        "PBNS RECOVERY STATE 7",
        f"PBNS RECOVERY ROLLBACK ADVANCE BEGIN current={current_version} target={target_version}",
        "PBNS RECOVERY ROLLBACK ADVANCE PASS",
        "PBNS RECOVERY STATE 8",
        "PBNS RECOVERY STARTIMAGE BEGIN",
        "PBNS RECOVERY READ-ONLY MODE",
    )
    offsets = [_unique_line(text, marker) for marker in expected]
    stream_duration_offset, stream_duration_ms = _stream_duration_offset(text)
    offsets.insert(expected.index("PBNS RECOVERY STATE 5"), stream_duration_offset)
    if offsets != sorted(offsets) or len(set(offsets)) != len(offsets):
        raise VerificationError("runtime markers are reordered")
    if _version(nv_before) != current_version or _version(nv_after) != target_version:
        raise VerificationError("TPM NV transition does not match the signed target")
    if _disk_hash(disk_before) != _disk_hash(disk_after):
        raise VerificationError("disposable disk changed")
    try:
        root = case_root.resolve(strict=True)
    except OSError as error:
        raise VerificationError("case root is unavailable") from error
    if not root.is_dir() or case_root.is_symlink():
        raise VerificationError("case root is invalid")
    _assert_no_events(case_root)
    return stream_duration_ms


def _assert_no_events(case_root: pathlib.Path) -> None:
    try:
        root = case_root.resolve(strict=True)
    except OSError as error:
        raise VerificationError("case root is unavailable") from error
    if not root.is_dir() or case_root.is_symlink():
        raise VerificationError("case root is invalid")
    event_names = {"recovery-events.jsonl", "evaluation-events.jsonl", "events.jsonl"}
    if any(path.name in event_names for path in root.rglob("*")):
        raise VerificationError("production case contains evaluation events")


def build_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--serial", type=pathlib.Path, required=True)
    result.add_argument("--nv-before", type=pathlib.Path, required=True)
    result.add_argument("--nv-after", type=pathlib.Path, required=True)
    result.add_argument("--disk-before", type=pathlib.Path, required=True)
    result.add_argument("--disk-after", type=pathlib.Path, required=True)
    result.add_argument("--case-root", type=pathlib.Path, required=True)
    result.add_argument("--expected-size", type=int, required=True)
    result.add_argument("--current-version", type=int, required=True)
    result.add_argument("--target-version", type=int, required=True)
    result.add_argument(
        "--case", choices=("signed-trusted", "unsigned-untrusted", "truncated", "forged-manifest", "downgrade"), default="signed-trusted"
    )
    result.add_argument("--print-stream-duration", action="store_true")
    return result


def main() -> int:
    arguments = build_parser().parse_args()
    if arguments.print_stream_duration and arguments.case != "signed-trusted":
        return 1
    try:
        stream_duration_ms = verify(
            arguments.serial,
            arguments.nv_before,
            arguments.nv_after,
            arguments.disk_before,
            arguments.disk_after,
            arguments.case_root,
            expected_size=arguments.expected_size,
            current_version=arguments.current_version,
            target_version=arguments.target_version,
            case=arguments.case,
        )
    except VerificationError:
        return 1
    if arguments.print_stream_duration:
        if stream_duration_ms is None:
            return 1
        print(stream_duration_ms)
    else:
        print("PBNS RECOVERY OBSERVABILITY PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
