#!/usr/bin/env python3
"""Fail-closed validation for private attestation ciphertext captures."""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys

BOUNDARIES = {"usb", "pico-raw-tcp", "tls-records", "dispatcher", "production-logs"}
FORBIDDEN_GROUPS = {"inventory", "eventLog", "activatedCredential", "rawIdentifiers"}
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


class ValidationError(Exception):
    pass


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path):
    data = read_private_file(path, 1024 * 1024)
    try:
        return json.loads(data, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValidationError(f"invalid JSON: {path.name}") from error


def validate_private_directory(path: pathlib.Path) -> pathlib.Path:
    if not path.is_absolute():
        path = path.absolute()
    try:
        info = path.lstat()
    except OSError as error:
        raise ValidationError("private directory unavailable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValidationError("private directory must be owned non-symlink mode 0700")
    return path


def secure_child(root: pathlib.Path, value: str) -> pathlib.Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValidationError("invalid capture path")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or relative.parts != tuple(part for part in relative.parts if part not in ("", ".")):
        raise ValidationError("capture path escapes private directory")
    candidate = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError as error:
            raise ValidationError(f"missing capture: {value}") from error
        if stat.S_ISLNK(info.st_mode):
            raise ValidationError(f"symlink capture path: {value}")
    return candidate


def read_private_file(path: pathlib.Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise ValidationError(f"missing file: {path}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size <= 0 or before.st_size > maximum:
        raise ValidationError(f"unsafe or empty private file: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValidationError(f"file changed before read: {path.name}")
        data = b""
        while len(data) < opened.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, opened.st_size - len(data)))
            if not chunk:
                raise ValidationError(f"short read: {path.name}")
            data += chunk
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            raise ValidationError(f"file changed during read: {path.name}")
        return data
    finally:
        os.close(descriptor)


def parse_time(value, name: str) -> datetime.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError(f"invalid {name}")
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValidationError(f"invalid {name}") from error
    return parsed


def check_fresh(value, file_path: pathlib.Path, now: datetime.datetime, maximum_age: int) -> None:
    captured = parse_time(value, "capturedAt")
    age = (now - captured).total_seconds()
    if age < -300 or age > maximum_age:
        raise ValidationError("stale or future capture")
    file_age = now.timestamp() - file_path.stat(follow_symlinks=False).st_mtime
    if file_age < -300 or file_age > maximum_age:
        raise ValidationError("stale or future capture file")


def strict_keys(document, required: set[str], name: str) -> None:
    if not isinstance(document, dict) or set(document) != required:
        raise ValidationError(f"invalid {name} members")


def decode_forbidden(document) -> list[bytes]:
    strict_keys(document, FORBIDDEN_GROUPS, "forbiddenHex")
    decoded = []
    for group in sorted(FORBIDDEN_GROUPS):
        values = document[group]
        if not isinstance(values, list) or not values:
            raise ValidationError(f"empty forbidden sentinel group: {group}")
        for value in values:
            if not isinstance(value, str) or len(value) < 8 or len(value) % 2:
                raise ValidationError(f"invalid forbidden sentinel: {group}")
            try:
                sentinel = bytes.fromhex(value)
            except ValueError as error:
                raise ValidationError(f"invalid forbidden sentinel: {group}") from error
            if not sentinel or sentinel in decoded:
                raise ValidationError("empty or duplicate forbidden sentinel")
            decoded.append(sentinel)
    return decoded


def inspect_cose(pbns_root: pathlib.Path, envelope: pathlib.Path) -> None:
    completed = subprocess.run(
        ["go", "run", "./cmd/pbns-attestation-cose-inspect", "-file", str(envelope)],
        cwd=pbns_root / "gateway",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0 or "COSE -29/A128GCM PASS" not in completed.stdout:
        raise ValidationError("dispatcher object is not canonical COSE -29/A128GCM")


def validate(arguments) -> None:
    manifest_path = pathlib.Path(arguments.capture_manifest)
    oracle_path = pathlib.Path(arguments.oracle)
    if manifest_path.parent != oracle_path.parent:
        raise ValidationError("manifest and oracle must share one private directory")
    root = validate_private_directory(manifest_path.parent)
    manifest_path = secure_child(root, manifest_path.name)
    oracle_path = secure_child(root, oracle_path.name)
    manifest = load_json(manifest_path)
    oracle = load_json(oracle_path)
    strict_keys(manifest, {"schemaVersion", "captures"}, "capture manifest")
    strict_keys(oracle, {"schemaVersion", "encryptedEnvelope", "forbiddenHex"}, "oracle")
    if manifest["schemaVersion"] != 1 or oracle["schemaVersion"] != 1:
        raise ValidationError("unsupported capture schema")
    envelope_meta = oracle["encryptedEnvelope"]
    strict_keys(envelope_meta, {"path", "sha256"}, "encrypted envelope")
    envelope_path = secure_child(root, envelope_meta["path"])
    envelope = read_private_file(envelope_path, 4_268_800)
    if not isinstance(envelope_meta["sha256"], str) or hashlib.sha256(envelope).hexdigest() != envelope_meta["sha256"]:
        raise ValidationError("encrypted envelope hash mismatch")
    inspect_cose(pathlib.Path(__file__).resolve().parents[2], envelope_path)
    forbidden = decode_forbidden(oracle["forbiddenHex"])

    captures = manifest["captures"]
    if not isinstance(captures, list) or len(captures) != len(BOUNDARIES):
        raise ValidationError("missing or duplicate capture boundaries")
    observed = set()
    now = datetime.datetime.now(datetime.timezone.utc)
    for entry in captures:
        strict_keys(entry, {"boundary", "path", "sha256", "size", "capturedAt", "mediaType"}, "capture")
        boundary = entry["boundary"]
        if boundary not in BOUNDARIES or boundary in observed:
            raise ValidationError("missing, duplicate, or mislabeled capture boundary")
        observed.add(boundary)
        if entry["mediaType"] != "application/octet-stream" or not isinstance(entry["size"], int) or isinstance(entry["size"], bool):
            raise ValidationError("invalid capture metadata")
        path = secure_child(root, entry["path"])
        data = read_private_file(path, MAX_CAPTURE_BYTES)
        if entry["size"] != len(data) or not isinstance(entry["sha256"], str) or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValidationError("capture size or hash mismatch")
        check_fresh(entry["capturedAt"], path, now, arguments.max_age_seconds)
        for sentinel in forbidden:
            if sentinel in data:
                raise ValidationError(f"plaintext sentinel at {boundary}")
        if boundary == "dispatcher" and data.count(envelope) != 1:
            raise ValidationError("dispatcher must contain exactly one encrypted COSE object")
    if observed != BOUNDARIES:
        raise ValidationError("missing capture boundary")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-manifest", required=True)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--max-age-seconds", type=int, default=21600)
    arguments = parser.parse_args()
    if arguments.max_age_seconds < 60 or arguments.max_age_seconds > 86400:
        print("ciphertext capture: invalid maximum age", file=sys.stderr)
        return 2
    try:
        validate(arguments)
    except (ValidationError, OSError, subprocess.SubprocessError) as error:
        print(f"ciphertext capture: {error}", file=sys.stderr)
        return 1
    print("CIPHERTEXT CAPTURE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
