#!/usr/bin/env python3
"""Fail-closed, private evidence derivation for the live QEMU recovery matrix.

This command deliberately consumes retained files only.  It does not launch QEMU,
swtpm, a gateway, Pico hardware, or any physical recovery operation.
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any

CASES = (
    "signed-trusted", "unsigned-untrusted", "truncated", "gateway-interruption",
    "forged-manifest", "forged-digest", "forged-chunk", "downgrade",
    "normal-launcher", "pico-absent",
)
RECOVERY_CASES = CASES[:8]
EVALUATION_FAULTS = {
    "gateway-interruption": "interrupt-after-data-7",
    "forged-digest": "artifact-digest-mismatch",
    "forged-chunk": "chunk-sequence",
}
SUMMARY_NAME = "recovery-matrix-summary.json"
MAX_LOG = 8 * 1024 * 1024
MAX_JSON = 1024 * 1024
MAX_HASH = 65
CHUNK_BYTES = 16 * 1024
ACK_WINDOW = 8
HASH = re.compile(r"^[0-9a-f]{64}$")
REJECT = re.compile(
    r"private[ _-]*key|identity[ _-]*(?:material|key|cose)|"
    r"(?:tpm[ _-]*)?(?:blob|auth(?:orization)?|session|nonce|ticket)|"
    r"(?:private|secret)[ _-]*(?:scalar|material)|auth[ _-]*value|"
    r"session[ _-]*nonce|token|decrypted[ _-]*transcript|"
    r"(?:tls|ssl)[ _-]*(?:plain(?:text)?|transcript|traffic[ _-]*secret)|"
    r"policy[ _-]*(?:authorization|internal)|artifact[ _-]*bytes|"
    r"transient[ _-]*crypto|request[ _-]*(?:id|binding)|host[ _-]*binding",
    re.IGNORECASE,
)
EVENT_NAMES = {"events.jsonl", "events-restart.jsonl", "recovery-events.jsonl", "evaluation-events.jsonl"}
KEY_BLOB_SUFFIXES = (".pem", ".key", ".der", ".blob", ".cbor")
TEXT_SUFFIXES = (".log", ".json", ".jsonl", ".txt", ".ext")
IMMUTABLE_REPOSITORY_METADATA = re.compile(r"^repository/metadata/[0-9a-f]{64}\.json$")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parents[2] / "eval" / "schema" / "recovery-result.schema.json"
_PINNED_ROOTS: dict[str, int] = {}


class EvidenceError(Exception):
    """Intentionally content-free evidence rejection."""


def _absolute(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(path))


def _private_dir(path: pathlib.Path, label: str) -> pathlib.Path:
    try:
        absolute = _absolute(path)
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except OSError as error:
        raise EvidenceError(f"invalid {label}") from error
    if absolute != resolved or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EvidenceError(f"invalid {label}")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise EvidenceError(f"invalid {label}")
    return resolved


def _child_name(path: pathlib.Path, root: pathlib.Path, label: str) -> str:
    # Evidence is deliberately flat: a root descriptor plus a single child name
    # prevents a later parent rename/symlink swap from redirecting a read or write.
    absolute = _absolute(path)
    if absolute.parent != _absolute(root) or absolute.name in ("", ".", ".."):
        raise EvidenceError(f"invalid {label}")
    return absolute.name


def _root_fd(root: pathlib.Path, label: str) -> int:
    pinned = _PINNED_ROOTS.get(str(_absolute(root)))
    if pinned is not None:
        return os.dup(pinned)
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
        info = os.fstat(descriptor)
    except OSError as error:
        raise EvidenceError(f"invalid {label}") from error
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        os.close(descriptor)
        raise EvidenceError(f"invalid {label}")
    return descriptor


@contextlib.contextmanager
def _pin_root(root: pathlib.Path, label: str):
    key = str(_absolute(root))
    if key in _PINNED_ROOTS:
        yield
        return
    descriptor = _root_fd(root, label)
    _PINNED_ROOTS[key] = descriptor
    try:
        yield
    finally:
        _PINNED_ROOTS.pop(key, None)
        os.close(descriptor)


def _read_all(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    left = maximum + 1
    while left:
        piece = os.read(descriptor, min(left, 65536))
        if not piece:
            break
        chunks.append(piece)
        left -= len(piece)
    return b"".join(chunks)


def _read_descriptor(descriptor: int, label: str, maximum: int, expected_mode: int = 0o600, allow_empty: bool = False) -> bytes:
    before = os.fstat(descriptor)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
            stat.S_IMODE(before.st_mode) != expected_mode or (not allow_empty and before.st_size <= 0) or
            before.st_size > maximum):
        raise EvidenceError(f"invalid {label}")
    first = _read_all(descriptor, maximum)
    middle = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    second = _read_all(descriptor, maximum)
    after = os.fstat(descriptor)
    stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    if (len(first) != before.st_size or first != second or
            stable != (middle.st_dev, middle.st_ino, middle.st_size, middle.st_mtime_ns, middle.st_ctime_ns) or
            stable != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise EvidenceError(f"invalid {label}")
    return first


def _read_at(parent_fd: int, name: str, label: str, maximum: int, expected_mode: int = 0o600, allow_empty: bool = False) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        try:
            return _read_descriptor(descriptor, label, maximum, expected_mode, allow_empty)
        finally:
            os.close(descriptor)
    except EvidenceError:
        raise
    except OSError as error:
        raise EvidenceError(f"invalid {label}") from error


def _read_file(path: pathlib.Path, root: pathlib.Path, label: str, maximum: int) -> bytes:
    name = _child_name(path, root, label)
    root_fd = _root_fd(root, label)
    try:
        return _read_at(root_fd, name, label, maximum)
    finally:
        os.close(root_fd)


def _utf8(path: pathlib.Path, root: pathlib.Path, label: str, maximum: int) -> str:
    value = _read_file(path, root, label, maximum)
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"invalid {label}") from error
    if REJECT.search(text):
        raise EvidenceError(f"invalid {label}")
    return text


def _json_object(text: str, keys: set[str], label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"invalid {label}")
            result[key] = value
        return result
    try:
        result = json.loads(text, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError(f"invalid {label}") from error
    if not isinstance(result, dict) or set(result) != keys:
        raise EvidenceError(f"invalid {label}")
    return result


def _version(path: pathlib.Path, root: pathlib.Path, label: str) -> int:
    value = _read_file(path, root, label, 8)
    if len(value) != 8:
        raise EvidenceError(f"invalid {label}")
    return int.from_bytes(value, "big")


def _digest(path: pathlib.Path, root: pathlib.Path, label: str) -> str:
    value = _read_file(path, root, label, MAX_HASH)
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"invalid {label}") from error
    if not text.endswith("\n") or text.endswith("\n\n") or HASH.fullmatch(text[:-1]) is None:
        raise EvidenceError(f"invalid {label}")
    return text[:-1]


def _marker(text: str, pattern: str, label: str) -> int:
    matches = list(re.finditer(rf"(?m)^{pattern}\r?$", text))
    if len(matches) != 1:
        raise EvidenceError(f"invalid {label}")
    return matches[0].start()


def _ordered(text: str, markers: list[tuple[str, str]]) -> None:
    offsets = [_marker(text, pattern, label) for pattern, label in markers]
    if offsets != sorted(offsets) or len(set(offsets)) != len(offsets):
        raise EvidenceError("invalid marker order")


def _no_markers(text: str, patterns: tuple[str, ...]) -> None:
    for pattern in patterns:
        if re.search(pattern, text):
            raise EvidenceError("invalid negative oracle")


def _states(last: int) -> list[tuple[str, str]]:
    return [(rf"PBNS RECOVERY STATE {number}", "state") for number in range(last + 1)]


def _failure(stage: int) -> tuple[str, str]:
    return (rf"PBNS RECOVERY FAILED stage={stage} status=-?[0-9]+", "failure")


def _free(size: int) -> list[tuple[str, str]]:
    return [(rf"PBNS RECOVERY FREE BEGIN size={size}", "free"), (r"PBNS RECOVERY FREE PASS", "free")]


def _failed_state() -> tuple[str, str]:
    return (r"PBNS RECOVERY STATE 9", "failed state")


def _only_failure(text: str, stage: int) -> None:
    matches = re.findall(r"(?m)^PBNS RECOVERY FAILED stage=([0-9]+) status=-?[0-9]+\r?$", text)
    if len(matches) != 1 or matches[0] != str(stage):
        raise EvidenceError("invalid failure marker")


def _serial(case: str, text: str, artifact: dict[str, Any] | None) -> None:
    if case in RECOVERY_CASES and artifact is None:
        raise EvidenceError("missing artifact evidence")
    if case == "signed-trusted":
        _ordered(text, [
            *_states(6),
            (rf"PBNS RECOVERY MEMORY LOAD BEGIN size={artifact['artifact_size']} version={artifact['version']}", "memory load"),
            (r"PBNS RECOVERY MEMORY LOAD PASS", "memory load"),
            (r"PBNS RECOVERY STATE 7", "state"),
            (r"PBNS RECOVERY ROLLBACK ADVANCE BEGIN current=5 target=7", "advance"),
            (r"PBNS RECOVERY ROLLBACK ADVANCE PASS", "advance"),
            (r"PBNS RECOVERY STATE 8", "state"),
            (r"PBNS RECOVERY STARTIMAGE BEGIN", "start"),
            (r"PBNS RECOVERY READ-ONLY MODE", "child"),
        ])
        _no_markers(text, (r"PBNS RECOVERY (?:FAILED|MEMORY LOAD REJECT|FREE|UNLOAD)", r"PBNS RECOVERY STATE 9"))
    elif case in ("unsigned-untrusted", "truncated"):
        _ordered(text, [*_states(6), (rf"PBNS RECOVERY MEMORY LOAD BEGIN size={artifact['artifact_size']} version={artifact['version']}", "memory load"),
                        (r"PBNS RECOVERY MEMORY LOAD REJECT status=0x[0-9A-Fa-f]+", "memory reject"), *_free(artifact["artifact_size"]), _failed_state(), _failure(6)])
        _only_failure(text, 6)
        _no_markers(text, (r"PBNS RECOVERY STATE [7-8]", r"PBNS RECOVERY MEMORY LOAD PASS", r"PBNS RECOVERY ROLLBACK ADVANCE", r"PBNS RECOVERY STARTIMAGE", r"PBNS RECOVERY UNLOAD"))
    elif case == "forged-manifest":
        _ordered(text, [*_states(2), _failed_state(), _failure(2)])
        _only_failure(text, 2)
        _no_markers(text, (r"PBNS RECOVERY STATE [3-8]", r"PBNS RECOVERY (?:MEMORY LOAD|ROLLBACK|FREE|STARTIMAGE|UNLOAD)"))
    elif case in ("gateway-interruption", "forged-chunk"):
        _ordered(text, [*_states(4), *_free(artifact["artifact_size"]), _failed_state(), _failure(4)])
        _only_failure(text, 4)
        _no_markers(text, (r"PBNS RECOVERY STATE [5-8]", r"PBNS RECOVERY (?:MEMORY LOAD|ROLLBACK|STARTIMAGE|UNLOAD)"))
    elif case == "forged-digest":
        _ordered(text, [*_states(5), *_free(artifact["artifact_size"]), _failed_state(), _failure(5)])
        _only_failure(text, 5)
        _no_markers(text, (r"PBNS RECOVERY STATE [6-8]", r"PBNS RECOVERY (?:MEMORY LOAD|ROLLBACK|STARTIMAGE|UNLOAD)"))
    elif case == "downgrade":
        _ordered(text, [*_states(5), *_free(artifact["artifact_size"]), _failed_state(), (r"PBNS RECOVERY FAILED stage=5 status=-15", "failure")])
        _only_failure(text, 5)
        _no_markers(text, (r"PBNS RECOVERY STATE [6-8]", r"PBNS RECOVERY (?:MEMORY LOAD|ROLLBACK|STARTIMAGE|UNLOAD)"))
    else:
        _ordered(text, [(r"PBNS NORMAL FIXTURE PASS", "normal"),
                        (r"PBNS RECOVERY FALLBACK stage=[0-9]+ loader_status=0x[0-9A-Fa-f]+", "fallback"),
                        (r"Type RECOVER to download a RAM-only recovery image: ", "prompt")])
        _no_markers(text, (r"PBNS RECOVERY STATE", r"PBNS RECOVERY MEMORY LOAD", r"PBNS RECOVERY ROLLBACK"))


def _metadata(path: pathlib.Path, root: pathlib.Path, artifact_path: pathlib.Path, expected_version: int) -> dict[str, Any]:
    text = _utf8(path, root, "artifact metadata", MAX_JSON)
    value = _json_object(text, {"artifact_sha256", "artifact_size", "version"}, "artifact metadata")
    if (not isinstance(value["artifact_sha256"], str) or HASH.fullmatch(value["artifact_sha256"]) is None or
            not isinstance(value["artifact_size"], int) or isinstance(value["artifact_size"], bool) or value["artifact_size"] <= 0 or
            not isinstance(value["version"], int) or isinstance(value["version"], bool) or value["version"] != expected_version):
        raise EvidenceError("invalid artifact metadata")
    actual = _read_file(artifact_path, root, "artifact", 256 * 1024 * 1024)
    if len(actual) != value["artifact_size"] or hashlib.sha256(actual).hexdigest() != value["artifact_sha256"]:
        raise EvidenceError("artifact does not match metadata")
    return value


def _valid_event_shape(event: dict[str, Any], fault: str) -> bool:
    if event["operation"] == "manifest":
        return event["frame"] == "RESPONSE" and event["sequence"] == event["next"] == event["window"] == 0 and event["outcome"] == "sent"
    if event["operation"] != "artifact":
        return False
    if event["frame"] == "DATA":
        if event["next"] != 0 or event["window"] != 0:
            return False
        if fault == "artifact-digest-mismatch":
            return (event["sequence"] == 0 and event["outcome"] == "injected") or (event["sequence"] > 0 and event["outcome"] == "sent")
        if fault == "chunk-sequence":
            return (event["sequence"] == 0 and event["outcome"] == "sent") or (event["sequence"] == 2 and event["outcome"] == "injected")
        return (event["sequence"] < 7 and event["outcome"] == "sent") or (event["sequence"] == 7 and event["outcome"] == "interrupt-ready")
    if event["frame"] == "ACK":
        return fault == "artifact-digest-mismatch" and event["sequence"] == 0 and event["next"] > 0 and event["window"] > 0 and event["next"] % event["window"] == 0 and event["outcome"] == "accepted"
    if event["frame"] == "COMPLETE":
        return fault == "artifact-digest-mismatch" and event["next"] == event["window"] == 0 and event["outcome"] == "sent"
    return False


def _event_file(path: pathlib.Path, root: pathlib.Path, case: str, fault: str) -> list[dict[str, Any]]:
    text = _utf8(path, root, "events", MAX_JSON)
    if not text.endswith("\n"):
        raise EvidenceError("invalid events")
    records: list[dict[str, Any]] = []
    for line in text[:-1].split("\n"):
        if not line:
            raise EvidenceError("invalid events")
        event = _json_object(line, {"schema", "case", "connection", "operation", "frame", "sequence", "next", "window", "fault", "outcome"}, "event")
        if (event["schema"] != "pbns-recovery-evaluation-v1" or event["case"] != case or event["fault"] != fault or
                not isinstance(event["connection"], int) or isinstance(event["connection"], bool) or not 0 < event["connection"] <= 2**64 - 1 or
                any(not isinstance(event[key], int) or isinstance(event[key], bool) or not 0 <= event[key] <= 2**32 - 1 for key in ("sequence", "next", "window")) or
                not all(isinstance(event[key], str) for key in ("operation", "frame", "outcome")) or
                not _valid_event_shape(event, fault)):
            raise EvidenceError("invalid event")
        records.append(event)
    if not records:
        raise EvidenceError("invalid events")
    return records


def _event_profile(records: list[dict[str, Any]], chunks: int, fault: str, *, restart: bool = False) -> None:
    if chunks <= 0 or records[0]["connection"] != 1:
        raise EvidenceError("invalid event profile")
    actual = [(item["operation"], item["frame"], item["sequence"], item["next"], item["window"], item["outcome"]) for item in records]
    expected = [("manifest", "RESPONSE", 0, 0, 0, "sent")]
    if restart:
        expected.append(("artifact", "DATA", 0, 0, 0, "sent"))
    elif fault == "interrupt-after-data-7":
        expected.extend(("artifact", "DATA", sequence, 0, 0, "interrupt-ready" if sequence == 7 else "sent") for sequence in range(8))
    elif fault == "chunk-sequence":
        expected.extend((("artifact", "DATA", 0, 0, 0, "sent"), ("artifact", "DATA", 2, 0, 0, "injected")))
    else:
        for sequence in range(chunks):
            expected.append(("artifact", "DATA", sequence, 0, 0, "injected" if sequence == 0 else "sent"))
            if (sequence + 1) % ACK_WINDOW == 0:
                expected.append(("artifact", "ACK", 0, sequence + 1, ACK_WINDOW, "accepted"))
        expected.append(("artifact", "COMPLETE", chunks, 0, 0, "sent"))
    if actual != expected:
        raise EvidenceError("invalid event chronology")
    # Firmware deliberately uses one fresh transport connection per operation:
    # the signed manifest response is connection ordinal 1 and every artifact
    # frame belongs to connection ordinal 2.  Do not accept a same-connection
    # trace as a substitute for the real two-request chronology.
    if records[0]["connection"] != 1 or any(item["connection"] != 2 for item in records[1:]):
        raise EvidenceError("invalid event connection profile")


def _events(case: str, events: pathlib.Path | None, restart: pathlib.Path | None, root: pathlib.Path, artifact: dict[str, Any] | None) -> None:
    if case not in EVALUATION_FAULTS:
        if events is not None or restart is not None:
            raise EvidenceError("unexpected events")
        return
    if artifact is None or events is None or (case == "gateway-interruption") != (restart is not None):
        raise EvidenceError("missing events")
    chunks = (artifact["artifact_size"] + CHUNK_BYTES - 1) // CHUNK_BYTES
    if (case == "forged-chunk" and chunks < 2) or (case == "gateway-interruption" and chunks < 8):
        raise EvidenceError("artifact is too small for evaluation fault")
    fault = EVALUATION_FAULTS[case]
    _event_profile(_event_file(events, root, case, fault), chunks, fault)
    if restart is not None:
        _event_profile(_event_file(restart, root, case, fault), chunks, fault, restart=True)


def _audit_retained_text(root: pathlib.Path, allowed: set[str]) -> None:
    # Walk verified descriptors, including private logs.  Only explicit key/blob
    # suffixes are excluded from text inspection; arbitrary private files do not
    # grant an audit bypass.
    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW

    def audit(directory_fd: int, prefix: str = "") -> None:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                name = entry.name
                relative = f"{prefix}{name}"
                if entry.is_symlink():
                    raise EvidenceError("invalid evidence path")
                if entry.is_dir(follow_symlinks=False):
                    if relative.startswith("repository/metadata/"):
                        raise EvidenceError("unexpected repository metadata")
                    try:
                        child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                        info = os.fstat(child_fd)
                    except OSError as error:
                        raise EvidenceError("invalid evidence path") from error
                    try:
                        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
                            raise EvidenceError("invalid evidence directory")
                        audit(child_fd, f"{relative}/")
                    finally:
                        os.close(child_fd)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise EvidenceError("invalid evidence path")
                immutable_metadata = IMMUTABLE_REPOSITORY_METADATA.fullmatch(relative) is not None
                if relative.startswith("repository/metadata/") and not immutable_metadata:
                    raise EvidenceError("unexpected repository metadata")
                suffix_name = name.lower()
                if not suffix_name.endswith(KEY_BLOB_SUFFIXES) and suffix_name.endswith(TEXT_SUFFIXES):
                    value = _read_at(
                        directory_fd, name, "retained text",
                        MAX_LOG if suffix_name.endswith(".log") else MAX_JSON,
                        0o444 if immutable_metadata else 0o600,
                        allow_empty=relative == "gateway.log",
                    )
                    try:
                        text = value.decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise EvidenceError("invalid retained text") from error
                    if REJECT.search(text):
                        raise EvidenceError("invalid retained text")
                if (name in EVENT_NAMES or name.endswith("events.jsonl")) and relative not in allowed:
                    raise EvidenceError("unexpected events")
                if name == "artifact-publication.json" and relative not in allowed:
                    raise EvidenceError("unexpected artifact metadata")

    root_fd = _root_fd(root, "case root")
    try:
        audit(root_fd)
    finally:
        os.close(root_fd)


def _relative(path: pathlib.Path | None, root: pathlib.Path) -> str | None:
    return None if path is None else _child_name(path, root, "input")


def derive_case(arguments: argparse.Namespace) -> dict[str, Any]:
    root = _private_dir(arguments.case_root, "case root")
    with _pin_root(root, "case root"):
        return _derive_case(arguments, root)


def _derive_case(arguments: argparse.Namespace, root: pathlib.Path) -> dict[str, Any]:
    case = arguments.case
    paths = {name: getattr(arguments, name) for name in ("serial", "serial_restart", "nv_before", "nv_after", "disk_before", "disk_after", "events", "events_restart", "artifact_metadata", "artifact")}
    allowed = {_child_name(path, root, "input") for path in paths.values() if path is not None}
    _audit_retained_text(root, allowed)
    serial = _utf8(paths["serial"], root, "serial", MAX_LOG)
    before = _version(paths["nv_before"], root, "NV before")
    after = _version(paths["nv_after"], root, "NV after")
    if (case == "signed-trusted" and (before, after) != (5, 7)) or (case != "signed-trusted" and (before, after) != (5, 5)):
        raise EvidenceError("invalid NV transition")
    disk_before = _digest(paths["disk_before"], root, "disk before")
    disk_after = _digest(paths["disk_after"], root, "disk after")
    if disk_before != disk_after:
        raise EvidenceError("disk changed")
    if case in RECOVERY_CASES:
        if paths["artifact_metadata"] is None or paths["artifact"] is None:
            raise EvidenceError("missing artifact evidence")
        expected_version = 5 if case == "downgrade" else 7
        artifact = _metadata(paths["artifact_metadata"], root, paths["artifact"], expected_version)
    elif paths["artifact_metadata"] is not None or paths["artifact"] is not None:
        raise EvidenceError("unexpected artifact metadata")
    else:
        artifact = None
    _serial(case, serial, artifact)
    if case == "gateway-interruption":
        if paths["serial_restart"] is None:
            raise EvidenceError("missing restart serial")
        _serial(case, _utf8(paths["serial_restart"], root, "restart serial", MAX_LOG), artifact)
    elif paths["serial_restart"] is not None:
        raise EvidenceError("unexpected restart serial")
    _events(case, paths["events"], paths["events_restart"], root, artifact)
    return {
        "case": case, "status": "passed", "artifact_sha256": None if artifact is None else artifact["artifact_sha256"],
        "artifact_size": None if artifact is None else artifact["artifact_size"], "artifact_version": None if artifact is None else artifact["version"], "nv_version_before": before,
        "nv_version_after": after, "disk_before_sha256": disk_before, "disk_after_sha256": disk_after,
        "inputs": {key: _relative(value, root) for key, value in paths.items()},
    }


def _write_new(path: pathlib.Path, root: pathlib.Path, value: dict[str, Any]) -> None:
    name = _child_name(path, root, "output")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_fd = _root_fd(root, "output parent")
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=root_fd)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("short output write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(root_fd)
    except OSError as error:
        raise EvidenceError("cannot write output") from error
    finally:
        os.close(root_fd)


def _case_command(arguments: argparse.Namespace) -> pathlib.Path:
    root = _private_dir(arguments.case_root, "case root")
    with _pin_root(root, "case root"):
        summary = _derive_case(arguments, root)
        path = root / SUMMARY_NAME
        _write_new(path, root, summary)
        return path


def _summary(root: pathlib.Path, case: str) -> tuple[dict[str, Any], argparse.Namespace]:
    with _pin_root(root, "case root"):
        return _summary_pinned(root, case)


def _summary_pinned(root: pathlib.Path, case: str) -> tuple[dict[str, Any], argparse.Namespace]:
    path = root / SUMMARY_NAME
    value = _json_object(_utf8(path, root, "summary", MAX_JSON), {"case", "status", "artifact_sha256", "artifact_size", "artifact_version", "nv_version_before", "nv_version_after", "disk_before_sha256", "disk_after_sha256", "inputs"}, "summary")
    if value["case"] != case or value["status"] != "passed" or not isinstance(value["inputs"], dict) or set(value["inputs"]) != {"serial", "serial_restart", "nv_before", "nv_after", "disk_before", "disk_after", "events", "events_restart", "artifact_metadata", "artifact"}:
        raise EvidenceError("invalid summary")
    paths: dict[str, pathlib.Path | None] = {}
    for key, relative in value["inputs"].items():
        if relative is None:
            paths[key] = None
        elif isinstance(relative, str) and relative and "/" not in relative and "\\" not in relative:
            paths[key] = root / relative
        else:
            raise EvidenceError("invalid summary")
    namespace = argparse.Namespace(case=case, case_root=root, **paths)
    derived = _derive_case(namespace, root)
    if {key: value[key] for key in value if key != "inputs"} != {key: derived[key] for key in derived if key != "inputs"}:
        raise EvidenceError("summary does not match evidence")
    return derived, namespace


def _sha256(path: pathlib.Path, root: pathlib.Path, label: str) -> str:
    value = _read_file(path, root, label, 256 * 1024 * 1024)
    return hashlib.sha256(value).hexdigest()


def _candidate(state: pathlib.Path, recorded: str) -> dict[str, Any]:
    cases_root = _private_dir(state / "cases", "cases root")
    records: dict[str, dict[str, Any]] = {}
    for case in CASES:
        root = _private_dir(cases_root / case, "case root")
        records[case], _ = _summary(root, case)
    base = _private_dir(state / "recovery-base", "base")
    with _pin_root(base, "base"):
        code = _sha256(base / "OVMF_CODE.fd", base, "OVMF code")
        variables = _sha256(base / "OVMF_VARS.fd", base, "OVMF variables")
    public_cases = {case: {key: ("pass" if key == "status" else records[case][key]) for key in ("status", "artifact_sha256", "nv_version_before", "nv_version_after", "disk_before_sha256", "disk_after_sha256")} for case in CASES}
    return {
        "schema": "pbns-recovery-result-v1", "evidence_class": "emulated-system", "status": "pass",
        "platform": "QEMU TCG with copied OVMF Secure Boot and swtpm",
        "recorded_utc": recorded, "ovmf_code_sha256": code, "ovmf_variables_sha256": variables,
        "artifacts": {case: {"sha256": records[case]["artifact_sha256"], "size": records[case]["artifact_size"]} for case in ("signed-trusted", "unsigned-untrusted", "truncated")},
        "cases": public_cases,
        "checks": {key: ("not-run" if key == "physical-recovery" else "pass") for key in ("launcher", "manifest", "stream", "anti-rollback", "uki-policy", "secureboot-memory-load", "disk-immutability", "normal-pico-absent", "physical-recovery")},
        "disk_before_sha256": records["signed-trusted"]["disk_before_sha256"], "disk_after_sha256": records["signed-trusted"]["disk_after_sha256"],
        "nv_version_before": 5, "nv_version_after": 7, "secure_boot_enabled": True, "setup_mode": False,
        "limitations": ["QEMU TCG and swtpm evidence only", "intentionally public test keys", "physical recovery not-run", "no physical-platform claim"],
    }


def _valid_public(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != set(_candidate_keys()):
        return False
    if value["schema"] != "pbns-recovery-result-v1" or value["evidence_class"] != "emulated-system" or value["status"] != "pass" or not isinstance(value["platform"], str) or not value["platform"] or len(value["platform"]) > 256:
        return False
    if not all(isinstance(value[key], str) and HASH.fullmatch(value[key]) for key in ("ovmf_code_sha256", "ovmf_variables_sha256", "disk_before_sha256", "disk_after_sha256")):
        return False
    if (not isinstance(value["recorded_utc"], str) or not isinstance(value["limitations"], list) or not value["limitations"] or
            not all(isinstance(item, str) and 0 < len(item) <= 512 for item in value["limitations"]) or
            len(set(value["limitations"])) != len(value["limitations"])):
        return False
    try:
        datetime.datetime.strptime(value["recorded_utc"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    if (value["nv_version_before"], value["nv_version_after"], value["secure_boot_enabled"], value["setup_mode"]) != (5, 7, True, False):
        return False
    check_names = {"launcher", "manifest", "stream", "anti-rollback", "uki-policy", "secureboot-memory-load", "disk-immutability", "normal-pico-absent", "physical-recovery"}
    if not isinstance(value["checks"], dict) or set(value["checks"]) != check_names or any(item != "pass" for key, item in value["checks"].items() if key != "physical-recovery") or value["checks"]["physical-recovery"] != "not-run":
        return False
    artifact_cases = {"signed-trusted", "unsigned-untrusted", "truncated"}
    if not isinstance(value["artifacts"], dict) or set(value["artifacts"]) != artifact_cases:
        return False
    for artifact in value["artifacts"].values():
        if not isinstance(artifact, dict) or set(artifact) != {"sha256", "size"} or not isinstance(artifact["sha256"], str) or HASH.fullmatch(artifact["sha256"]) is None or not isinstance(artifact["size"], int) or isinstance(artifact["size"], bool) or artifact["size"] <= 0:
            return False
    if not isinstance(value["cases"], dict) or set(value["cases"]) != set(CASES):
        return False
    case_keys = {"status", "artifact_sha256", "nv_version_before", "nv_version_after", "disk_before_sha256", "disk_after_sha256"}
    for record in value["cases"].values():
        if not isinstance(record, dict) or set(record) != case_keys or record["status"] != "pass" or not isinstance(record["nv_version_before"], int) or isinstance(record["nv_version_before"], bool) or not isinstance(record["nv_version_after"], int) or isinstance(record["nv_version_after"], bool) or not all(isinstance(record[key], str) and HASH.fullmatch(record[key]) for key in ("disk_before_sha256", "disk_after_sha256")) or (record["artifact_sha256"] is not None and (not isinstance(record["artifact_sha256"], str) or HASH.fullmatch(record["artifact_sha256"]) is None)):
            return False
    return not REJECT.search(json.dumps(value, sort_keys=True))


def _committed_schema() -> dict[str, Any]:
    try:
        encoded = SCHEMA_PATH.read_bytes()
        schema = json.loads(encoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError("recovery result schema is unavailable") from error
    if not isinstance(schema, dict) or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise EvidenceError("invalid recovery result schema")
    return schema


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key")
        result[key] = value
    return result


def _json_equal(left: Any, right: Any) -> bool:
    # JSON numbers compare mathematically, but JSON booleans are never numbers.
    if _schema_type(left, "number") and _schema_type(right, "number"):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right))
    return left == right


def _json_unique_key(value: Any) -> str:
    # Canonical number ratios preserve JSON numeric equality (1 == 1.0) while
    # keeping boolean values distinct from their Python integer subclasses.
    if _schema_type(value, "number"):
        numerator, denominator = value.as_integer_ratio() if isinstance(value, float) else (value, 1)
        return f"number:{numerator}/{denominator}"
    if isinstance(value, dict):
        return "object:" + json.dumps({key: _json_unique_key(item) for key, item in sorted(value.items())}, sort_keys=True)
    if isinstance(value, list):
        return "array:" + json.dumps([_json_unique_key(item) for item in value])
    return f"{type(value).__name__}:{value!r}"


def _schema_type(value: Any, name: str) -> bool:
    numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool) or isinstance(value, float) and value.is_integer(),
        "number": numeric,
        "string": isinstance(value, str),
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
    }.get(name, False)


def _schema_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise EvidenceError("unsupported schema reference")
    current: Any = root
    for component in reference[2:].split("/"):
        if not isinstance(current, dict) or component not in current:
            raise EvidenceError("invalid schema reference")
        current = current[component]
    if not isinstance(current, dict):
        raise EvidenceError("invalid schema reference")
    return current


_RFC3339_DATE_TIME = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"[Tt](?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.[0-9]+)?(?P<zone>[Zz]|(?P<sign>[+-])(?P<offset_hour>[0-9]{2}):(?P<offset_minute>[0-9]{2}))$"
)


def _date_time(value: str) -> bool:
    """Accept precisely RFC3339 full date-times, including required offsets."""
    matched = _RFC3339_DATE_TIME.fullmatch(value)
    if matched is None:
        return False
    year, month, day, hour, minute, second = (
        int(matched.group(name)) for name in ("year", "month", "day", "hour", "minute", "second")
    )
    leap_year = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap_year else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if not 1 <= month <= 12 or not 1 <= day <= days[month - 1]:
        return False
    # RFC3339 allows 60 for a leap second; 61+ is never valid.
    if hour > 23 or minute > 59 or second > 60:
        return False
    if matched.group("zone").lower() == "z":
        return True
    return int(matched.group("offset_hour")) <= 23 and int(matched.group("offset_minute")) <= 59


def _validate_schema(value: Any, rule: Any, root: dict[str, Any]) -> bool:
    if not isinstance(rule, dict):
        raise EvidenceError("invalid schema rule")
    if "$ref" in rule:
        if set(rule) != {"$ref"} or not isinstance(rule["$ref"], str):
            raise EvidenceError("invalid schema reference")
        return _validate_schema(value, _schema_ref(root, rule["$ref"]), root)
    if "oneOf" in rule:
        choices = rule["oneOf"]
        if not isinstance(choices, list):
            raise EvidenceError("invalid schema oneOf")
        if sum(_validate_schema(value, item, root) for item in choices) != 1:
            return False
    if "const" in rule and not _json_equal(value, rule["const"]):
        return False
    if "enum" in rule:
        if not isinstance(rule["enum"], list) or not any(_json_equal(value, item) for item in rule["enum"]):
            return False
    if "type" in rule:
        types = rule["type"] if isinstance(rule["type"], list) else [rule["type"]]
        if not all(isinstance(item, str) for item in types) or not any(_schema_type(value, item) for item in types):
            return False
    if isinstance(value, dict):
        required = rule.get("required", [])
        properties = rule.get("properties", {})
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required) or not isinstance(properties, dict):
            raise EvidenceError("invalid object schema")
        if any(item not in value for item in required):
            return False
        if rule.get("additionalProperties") is False and any(item not in properties for item in value):
            return False
        if any(not _validate_schema(item, properties[key], root) for key, item in value.items() if key in properties):
            return False
    if isinstance(value, list):
        if "items" in rule:
            if not all(_validate_schema(item, rule["items"], root) for item in value):
                return False
        if rule.get("uniqueItems") is True:
            encoded = [_json_unique_key(item) for item in value]
            if len(encoded) != len(set(encoded)):
                return False
    if isinstance(value, str):
        if "minLength" in rule and (not isinstance(rule["minLength"], int) or len(value) < rule["minLength"]):
            return False
        if "maxLength" in rule and (not isinstance(rule["maxLength"], int) or len(value) > rule["maxLength"]):
            return False
        if "pattern" in rule:
            if not isinstance(rule["pattern"], str) or re.search(rule["pattern"], value) is None:
                return False
        if rule.get("format") == "date-time" and not _date_time(value):
            return False
    if _schema_type(value, "number") and "minimum" in rule:
        if not isinstance(rule["minimum"], (int, float)) or isinstance(rule["minimum"], bool) or value < rule["minimum"]:
            return False
    return True


def validate_schema_equivalent(value: Any) -> bool:
    """Unconditional generic validator driven solely by the loaded schema."""
    try:
        schema = _committed_schema()
        return _validate_schema(value, schema, schema)
    except (EvidenceError, TypeError, ValueError, re.error):
        return False

def _result_command(arguments: argparse.Namespace) -> pathlib.Path:
    state = _private_dir(arguments.state_root, "state root")
    recorded = datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    candidate = _candidate(state, recorded)
    if not validate_schema_equivalent(candidate) or not _valid_public(candidate):
        raise EvidenceError("invalid candidate")
    output = pathlib.Path(arguments.output)
    _write_new(output, state, candidate)
    return output


def _read_public_result(path: pathlib.Path) -> str:
    # The supplied result can be public (unlike retained state), but it still
    # gets a no-follow, descriptor-relative, stable double read.
    parent = _absolute(path).parent
    name = _absolute(path).name
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = os.open(parent, flags)
        read_flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
        descriptor = os.open(name, read_flags, dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_JSON:
            raise EvidenceError("invalid result")
        first = _read_all(descriptor, MAX_JSON)
        middle = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_all(descriptor, MAX_JSON)
        after = os.fstat(descriptor)
        stable = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if len(first) != info.st_size or first != second or stable != (middle.st_dev, middle.st_ino, middle.st_size, middle.st_mtime_ns, middle.st_ctime_ns) or stable != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise EvidenceError("invalid result")
        return first.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("invalid result") from error
    except OSError as error:
        raise EvidenceError("invalid result") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _verify_command(arguments: argparse.Namespace) -> None:
    state = _private_dir(arguments.state_root, "state root")
    result_path = pathlib.Path(arguments.result)
    result = _json_object(_read_public_result(result_path), set(_candidate_keys()), "result")
    recorded = result.get("recorded_utc")
    if not isinstance(recorded, str):
        raise EvidenceError("invalid result")
    try:
        datetime.datetime.strptime(recorded, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise EvidenceError("invalid result") from error
    expected = _candidate(state, recorded)
    if not validate_schema_equivalent(result) or not _valid_public(result) or result != expected:
        raise EvidenceError("result does not match evidence")


def _candidate_keys() -> tuple[str, ...]:
    return ("schema", "evidence_class", "status", "platform", "recorded_utc", "ovmf_code_sha256", "ovmf_variables_sha256", "artifacts", "cases", "checks", "disk_before_sha256", "disk_after_sha256", "nv_version_before", "nv_version_after", "secure_boot_enabled", "setup_mode", "limitations")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    case = commands.add_parser("case")
    case.add_argument("--case", choices=CASES, required=True)
    for name in ("case-root", "serial", "nv-before", "nv-after", "disk-before", "disk-after"):
        case.add_argument(f"--{name}", type=pathlib.Path, required=True)
    case.add_argument("--serial-restart", type=pathlib.Path)
    case.add_argument("--events", type=pathlib.Path)
    case.add_argument("--events-restart", type=pathlib.Path)
    case.add_argument("--artifact-metadata", type=pathlib.Path)
    case.add_argument("--artifact", type=pathlib.Path)
    candidate = commands.add_parser("result")
    candidate.add_argument("--state-root", type=pathlib.Path, required=True)
    candidate.add_argument("--output", type=pathlib.Path, required=True)
    verify = commands.add_parser("verify-result")
    verify.add_argument("--state-root", type=pathlib.Path, required=True)
    verify.add_argument("--result", type=pathlib.Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "case":
            print(_case_command(arguments))
        elif arguments.command == "result":
            print(_result_command(arguments))
        else:
            _verify_command(arguments)
    except EvidenceError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
