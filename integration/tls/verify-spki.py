#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import pathlib
import re
import subprocess
import sys


PIN_PATTERN = re.compile(rb"[0-9a-f]{64}\n?")


class VerificationError(Exception):
    pass


def _read_pin(path: pathlib.Path) -> bytes:
    try:
        encoded = path.read_bytes()
    except OSError as error:
        raise VerificationError from error
    if PIN_PATTERN.fullmatch(encoded) is None:
        raise VerificationError
    try:
        return bytes.fromhex(encoded.strip().decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise VerificationError from error


def _subject_public_key_info(certificate: pathlib.Path) -> bytes:
    try:
        public_key = subprocess.run(
            ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
            check=True,
            capture_output=True,
        ).stdout
        return subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=public_key,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise VerificationError from error


def verify(certificate: pathlib.Path, pin_path: pathlib.Path) -> bool:
    expected = _read_pin(pin_path)
    actual = hashlib.sha256(_subject_public_key_info(certificate)).digest()
    return hmac.compare_digest(actual, expected)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify a certificate SPKI pin")
    parser.add_argument("certificate", type=pathlib.Path)
    parser.add_argument("pin", type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        valid = verify(args.certificate, args.pin)
    except VerificationError:
        valid = False
    if not valid:
        print("SPKI verification failed", file=sys.stderr)
        return 1
    print("SPKI PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
