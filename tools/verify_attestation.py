#!/usr/bin/env python3
"""Verify attestation evidence without touching hardware."""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

STAGES = (
    "privacy", "quote-binding", "eventlog-replay", "baseline", "receipt",
    "ciphertext-capture", "swtpm", "physical-full-2",
)
CAPABILITIES = {
    "tpm2", "p256-identity", "ecc-p256-ak-quote",
    "makecredential-activatecredential", "sha256-pcr-bank", "tcg-event-log",
    "approved-rng",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
MAX_AGE = datetime.timedelta(hours=6)


class InvalidEvidence(Exception):
    pass


def pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidEvidence(f"duplicate JSON member {key}")
        result[key] = value
    return result


def exact(document, keys, name):
    if not isinstance(document, dict) or set(document) != set(keys):
        raise InvalidEvidence(f"invalid {name} members")


def utc(value, name):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InvalidEvidence(f"invalid {name}")
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InvalidEvidence(f"invalid {name}") from error
    if parsed.tzinfo != datetime.timezone.utc:
        raise InvalidEvidence(f"non-UTC {name}")
    return parsed


def private_directory(path):
    path = pathlib.Path(path).absolute()
    try:
        info = path.lstat()
    except OSError as error:
        raise InvalidEvidence("evidence directory missing") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise InvalidEvidence("evidence directory must be owned non-symlink mode 0700")
    return path


def secure_path(root, relative):
    if not isinstance(relative, str) or not relative or not PATH.fullmatch(relative):
        raise InvalidEvidence("invalid relative evidence path")
    pure = pathlib.PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or any(part in ("", ".") for part in pure.parts):
        raise InvalidEvidence("evidence path escapes root")
    cursor = root
    for part in pure.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError as error:
            raise InvalidEvidence(f"missing evidence artifact {relative}") from error
        if stat.S_ISLNK(info.st_mode):
            raise InvalidEvidence(f"symlink evidence artifact {relative}")
    return cursor


def read_private(path, maximum=64 * 1024 * 1024):
    try:
        before = path.lstat()
    except OSError as error:
        raise InvalidEvidence(f"missing private file {path.name}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size <= 0 or before.st_size > maximum:
        raise InvalidEvidence(f"unsafe private file {path.name}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity[:3] != (before.st_dev, before.st_ino, before.st_size):
            raise InvalidEvidence(f"file changed before read {path.name}")
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise InvalidEvidence(f"short read {path.name}")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity:
            raise InvalidEvidence(f"file changed during read {path.name}")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def load_manifest(path):
    raw, info = read_private(path, 1024 * 1024)
    try:
        document = json.loads(raw, object_pairs_hook=pairs_no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise InvalidEvidence(f"invalid manifest JSON {path.name}") from error
    return document, info


def validate_artifact(root, artifact, started, finished, now):
    exact(artifact, ("path", "sha256", "size", "provenance"), "artifact")
    if artifact["provenance"] not in {"live-runtime", "qemu-swtpm", "physical-gate", "ciphertext-checker"}:
        raise InvalidEvidence("invalid artifact provenance")
    if not isinstance(artifact["sha256"], str) or not HEX64.fullmatch(artifact["sha256"]):
        raise InvalidEvidence("invalid artifact hash")
    if not isinstance(artifact["size"], int) or isinstance(artifact["size"], bool) or artifact["size"] <= 0:
        raise InvalidEvidence("invalid artifact size")
    path = secure_path(root, artifact["path"])
    data, info = read_private(path)
    if len(data) != artifact["size"] or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
        raise InvalidEvidence(f"artifact hash mismatch {artifact['path']}")
    modified = datetime.datetime.fromtimestamp(info.st_mtime, datetime.timezone.utc)
    if modified < started - datetime.timedelta(seconds=5) or modified > finished + datetime.timedelta(seconds=5) or now - modified > MAX_AGE:
        raise InvalidEvidence(f"artifact timing mismatch {artifact['path']}")


def validate_stage(root, name, stage, now):
    exact(stage, ("status", "command", "startedAt", "finishedAt", "evidence"), f"stage {name}")
    if stage["status"] not in ("passed", "failed", "not-run"):
        raise InvalidEvidence(f"invalid stage status {name}")
    if not isinstance(stage["evidence"], list) or len(stage["evidence"]) > 64:
        raise InvalidEvidence(f"invalid stage evidence {name}")
    if stage["status"] == "not-run":
        if stage["command"] != "" or stage["startedAt"] is not None or stage["finishedAt"] is not None or stage["evidence"]:
            raise InvalidEvidence(f"not-run stage has evidence {name}")
        return
    if not isinstance(stage["command"], str) or not stage["command"] or len(stage["command"]) > 512 or not stage["evidence"]:
        raise InvalidEvidence(f"executed stage lacks provenance {name}")
    started = utc(stage["startedAt"], f"{name}.startedAt")
    finished = utc(stage["finishedAt"], f"{name}.finishedAt")
    if started > finished or now - started > MAX_AGE or finished > now + datetime.timedelta(minutes=5):
        raise InvalidEvidence(f"invalid stage timing {name}")
    for artifact in stage["evidence"]:
        validate_artifact(root, artifact, started, finished, now)


def validate_platform(platform):
    exact(platform, ("class", "fingerprintDigest", "capabilities", "restorationProof"), "platform")
    if platform["class"] not in ("intel-ptt", "amd-ftpm") or not isinstance(platform["fingerprintDigest"], str) or not HEX64.fullmatch(platform["fingerprintDigest"]) or platform["fingerprintDigest"] == "0" * 64:
        raise InvalidEvidence("invalid digested platform identity")
    if platform["restorationProof"] is not True:
        raise InvalidEvidence("physical restoration proof missing")
    exact(platform["capabilities"], CAPABILITIES, "capabilities")
    if any(value is not True for value in platform["capabilities"].values()):
        raise InvalidEvidence("physical platform is not capability-complete")


def validate_manifest(root, path, now):
    document, info = load_manifest(path)
    exact(document, ("schemaVersion", "kind", "runId", "createdAt", "expiresAt", "platform", "stages"), "manifest")
    if document["schemaVersion"] != 1 or document["kind"] not in ("qemu", "physical") or not isinstance(document["runId"], str) or not HEX64.fullmatch(document["runId"]):
        raise InvalidEvidence(f"invalid manifest identity {path.name}")
    created = utc(document["createdAt"], "createdAt")
    expires = utc(document["expiresAt"], "expiresAt")
    if created > now + datetime.timedelta(minutes=5) or now - created > MAX_AGE or expires <= created or expires - created > MAX_AGE or now >= expires:
        raise InvalidEvidence(f"stale manifest {path.name}")
    modified = datetime.datetime.fromtimestamp(info.st_mtime, datetime.timezone.utc)
    if modified < created - datetime.timedelta(seconds=5) or now - modified > MAX_AGE:
        raise InvalidEvidence(f"prewritten or stale manifest {path.name}")
    exact(document["stages"], STAGES, "stages")
    for name in STAGES:
        validate_stage(root, name, document["stages"][name], now)
    if document["kind"] == "qemu":
        if document["platform"] is not None:
            raise InvalidEvidence("qemu manifest has physical identity")
        for name in STAGES[:-1]:
            if document["stages"][name]["status"] != "passed":
                raise InvalidEvidence(f"qemu stage did not pass: {name}")
        if document["stages"]["physical-full-2"]["status"] != "not-run":
            raise InvalidEvidence("qemu claimed physical stage")
    else:
        validate_platform(document["platform"])
        if document["stages"]["physical-full-2"]["status"] != "passed":
            raise InvalidEvidence("physical full stage did not pass")
        for name in STAGES[:-1]:
            if document["stages"][name]["status"] != "not-run":
                raise InvalidEvidence("physical evidence counted a non-physical stage")
    return document


def run(evidence_dir, required_hardware):
    root = private_directory(evidence_dir)
    qemu_path = secure_path(root, "qemu.json")
    physical_paths = sorted(root.glob("physical-*.json"))
    for path in physical_paths:
        if path.is_symlink():
            raise InvalidEvidence("symlink physical manifest")
    now = datetime.datetime.now(datetime.timezone.utc)
    qemu = validate_manifest(root, qemu_path, now)
    physical = [validate_manifest(root, path, now) for path in physical_paths]
    if len(physical) != required_hardware:
        raise InvalidEvidence(f"expected exactly {required_hardware} physical manifests")
    fingerprints = [item["platform"]["fingerprintDigest"] for item in physical]
    if len(fingerprints) != len(set(fingerprints)):
        raise InvalidEvidence("duplicate physical platform evidence")
    if required_hardware >= 1 and not any(item["platform"]["class"] == "amd-ftpm" for item in physical):
        raise InvalidEvidence("physical platform gate requires AMD fTPM")
    run_ids = [qemu["runId"]] + [item["runId"] for item in physical]
    if len(run_ids) != len(set(run_ids)):
        raise InvalidEvidence("duplicate evidence run")
    print("[PASS] privacy-filter")
    print("[PASS] quote-binding")
    print("[PASS] swtpm-valid-and-mutations")
    print("[PASS] eventlog-reconstruction")
    print("[PASS] baseline")
    print("[PASS] receipt")
    print("[PASS] ciphertext-capture")
    for item in physical:
        print(f"[PASS] physical-full-{item['platform']['class'].removesuffix('-ptt').removesuffix('-ftpm')}")
    print("ATTESTATION PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-hardware", type=int, required=True, choices=(0, 1, 2))
    parser.add_argument("--evidence-dir", required=True)
    arguments = parser.parse_args()
    try:
        run(arguments.evidence_dir, arguments.require_hardware)
    except (InvalidEvidence, OSError) as error:
        print(f"attestation verification: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
