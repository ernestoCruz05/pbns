#!/usr/bin/env python3
"""Validate a copied OVMF Secure Boot store without modifying it."""

import argparse
import filecmp
import os
import pathlib
import re
import subprocess
import sys
import tempfile

OWNER_GUID = "a0baa8a3-041d-48a8-bc87-c36d121b5e3d"
CERT_STEM = "PBNSTESTONLYRecoveryImage"
DATABASES = ("PK", "KEK", "db")
DATABASE_GUIDS = {
    "PK": "guid:EfiGlobalVariable",
    "KEK": "guid:EfiGlobalVariable",
    "db": "guid:EfiImageSecurityDatabase",
}
SECURE_BOOT_HEADER = "name=SecureBootEnable guid=guid:EfiSecureBootEnableDisable size=1"
SUBJECT = "    subject CN=PBNS TEST ONLY Recovery Image"
ISSUER = "    issuer CN=PBNS TEST ONLY Recovery Image"
X509 = "  siglist type=guid:EfiCertX509 count=1"


def regular_file(path: pathlib.Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("input is not a regular file")


def validate_scratch_parent(path: pathlib.Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("scratch parent is not a directory")
    metadata = path.stat()
    if metadata.st_mode & 0o777 != 0o700 or metadata.st_uid != os.geteuid():
        raise ValueError("scratch parent protection")


def decoded_blocks(report: str) -> dict[str, list[list[str]]]:
    blocks: dict[str, list[list[str]]] = {}
    current: list[str] = []
    for line in report.splitlines():
        if line.startswith("name="):
            if current:
                name = current[0].split(" ", 1)[0][5:]
                blocks.setdefault(name, []).append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        name = current[0].split(" ", 1)[0][5:]
        blocks.setdefault(name, []).append(current)
    return blocks


def validate_decoded(report: str) -> None:
    blocks = decoded_blocks(report)
    secure_blocks = blocks.get("SecureBootEnable", [])
    if secure_blocks != [[SECURE_BOOT_HEADER, "  bool: ON", ""]]:
        raise ValueError("SecureBootEnable shape")
    for database in DATABASES:
        entries = blocks.get(database, [])
        if len(entries) != 1:
            raise ValueError(f"{database} block count")
        header = rf"name={re.escape(database)} guid={re.escape(DATABASE_GUIDS[database])} size=[0-9]+(?: time=[^\n]+)?"
        block = entries[0]
        if not block or re.fullmatch(header, block[0]) is None:
            raise ValueError(f"{database} header")
        if block != [block[0], X509, SUBJECT, ISSUER, ""]:
            raise ValueError(f"{database} shape")


def command(arguments: list[str], cwd: pathlib.Path | None = None, stdout=None) -> None:
    subprocess.run(arguments, cwd=cwd, stdout=stdout, stderr=subprocess.PIPE, check=True)


def expected_certificate_names() -> set[str]:
    return {f"{database}-{OWNER_GUID}-{CERT_STEM}.pem" for database in DATABASES}


def validate_extraction_inventory(extract: pathlib.Path) -> list[pathlib.Path]:
    if extract.is_symlink() or not extract.is_dir():
        raise ValueError("certificate extraction directory")
    entries = list(extract.iterdir())
    expected = expected_certificate_names()
    if {entry.name for entry in entries} != expected or len(entries) != len(expected):
        raise ValueError("extracted certificate inventory")
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise ValueError("extracted certificate type")
    return sorted(entries)


def validate_certificates(vars_path: pathlib.Path, fixture_cert: pathlib.Path, scratch: pathlib.Path) -> None:
    expected = scratch / "fixture.der"
    command(["openssl", "x509", "-in", str(fixture_cert), "-outform", "DER", "-out", str(expected)])
    expected.chmod(0o600)
    extract = scratch / "extract"
    extract.mkdir(mode=0o700)
    command(["virt-fw-vars", "--input", str(vars_path), "--extract-certs"], cwd=extract)
    for certificate in validate_extraction_inventory(extract):
        certificate.chmod(0o600)
        actual = scratch / f"{certificate.stem}.der"
        command(["openssl", "x509", "-in", str(certificate), "-outform", "DER", "-out", str(actual)])
        actual.chmod(0o600)
        if not filecmp.cmp(expected, actual, shallow=False):
            raise ValueError("extracted certificate does not equal fixture")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vars", type=pathlib.Path, required=True)
    parser.add_argument("--fixture-cert", type=pathlib.Path, required=True)
    parser.add_argument("--decoded", type=pathlib.Path, required=True)
    parser.add_argument("--scratch-parent", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    try:
        regular_file(arguments.vars)
        regular_file(arguments.fixture_cert)
        if arguments.decoded.exists() or arguments.decoded.is_symlink():
            raise ValueError("decoded output already exists")
        validate_scratch_parent(arguments.scratch_parent)
        with tempfile.TemporaryDirectory(prefix=".secureboot-store.", dir=arguments.scratch_parent) as directory:
            scratch = pathlib.Path(directory)
            scratch.chmod(0o700)
            descriptor = os.open(
                arguments.decoded,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as report:
                command(["virt-fw-vars", "--input", str(arguments.vars), "--print", "--verbose"], stdout=report)
            arguments.decoded.chmod(0o600)
            decoded = arguments.decoded.read_text(encoding="utf-8")
            validate_decoded(decoded)
            validate_certificates(arguments.vars, arguments.fixture_cert, scratch)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"secure boot variable validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
