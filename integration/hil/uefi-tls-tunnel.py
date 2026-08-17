#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import signal
import socket
import ssl
import stat
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID


TLS_VERSION = "TLSv1.2"
TLS_CIPHER = "ECDHE-ECDSA-AES128-GCM-SHA256"
TLS_ALPN = "pbns/1"
EXPECTED_SAN = "192.168.1.180"
DRIVER = "host-python-ssl-memorybio"
UEFI_EXECUTION = "not-run"
MAX_EMPTY_COMPLETIONS = 4
MAX_SERIAL_COMPLETIONS = 524288
MAX_COMMAND_BYTES = 512
STREAM_CHUNK = 16384
DIRECT_BYTES = 1024 * 1024
WARMUP_BYTES = 64 * 1024
ARTIFACT_BYTES = 26_553_920
ARTIFACT_SHA256 = "d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3"
CIPHER_PROOF = b"wrong-cipher:no-shared-cipher\n"
PIN_PATTERN = re.compile(rb"[0-9a-f]{64}\n?")
PATTERN = b"PBNS-RAW-TUNNEL-V1\x00"
ERROR_CODES = frozenset(
    (
        "wrong-san",
        "wrong-spki",
        "wrong-alpn",
        "wrong-cipher",
        "wrong-version",
        "tls-handshake",
        "timeout",
        "zero-progress",
        "io",
        "cancelled",
        "truncated",
        "byte-count",
        "digest-mismatch",
        "internal",
    )
)


class ByteStream(Protocol):
    def write(self, data: bytes | memoryview) -> int: ...

    def read(self, size: int) -> bytes: ...

    def flush(self) -> None: ...


class OpenedSerial(ByteStream, Protocol):
    def fileno(self) -> int: ...

    def close(self) -> None: ...

    def __enter__(self) -> "OpenedSerial": ...

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None: ...


class TunnelError(Exception):
    def __init__(self, code: str, *, tls_reason: str | None = None) -> None:
        if code not in ERROR_CODES:
            code = "internal"
        super().__init__(code)
        self.code = code
        self.tls_reason = tls_reason


@dataclass
class CipherProofExpectation:
    directory_fd: int
    name: str
    staging_name: str
    closed: bool = False

    def close(self) -> None:
        if not self.closed:
            os.close(self.directory_fd)
            self.closed = True


@dataclass
class CompletionCanary:
    durations_ns: list[int] = field(default_factory=list)
    status_count: int = 0

    def record(self, duration_ns: int, success: bool) -> None:
        if len(self.durations_ns) >= MAX_SERIAL_COMPLETIONS:
            raise TunnelError("internal")
        self.durations_ns.append(max(duration_ns, 0))
        if not success:
            self.status_count += 1

    @staticmethod
    def _percentile(values: list[int], percentile: int) -> int:
        if not values:
            return 0
        ordered = sorted(values)
        index = ((len(ordered) - 1) * percentile + 99) // 100
        return ordered[index]

    def metadata(self) -> dict[str, int]:
        return {
            "completion_count": len(self.durations_ns),
            "completion_status_count": self.status_count,
            "completion_p50_ns": self._percentile(self.durations_ns, 50),
            "completion_p95_ns": self._percentile(self.durations_ns, 95),
            "completion_p99_ns": self._percentile(self.durations_ns, 99),
        }


def _deadline_expired(deadline_ns: int, monotonic_ns: Callable[[], int]) -> bool:
    return monotonic_ns() >= deadline_ns


def write_all(
    stream: ByteStream,
    data: bytes | memoryview,
    *,
    deadline_ns: int,
    canary: CompletionCanary | None = None,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> None:
    view = memoryview(data)
    while view:
        if _deadline_expired(deadline_ns, monotonic_ns):
            raise TunnelError("timeout")
        started = monotonic_ns()
        try:
            written = stream.write(view)
        except (OSError, ValueError) as error:
            if canary is not None:
                canary.record(monotonic_ns() - started, False)
            raise TunnelError("io") from error
        if canary is not None:
            canary.record(monotonic_ns() - started, written > 0)
        if written <= 0 or written > len(view):
            raise TunnelError("zero-progress")
        view = view[written:]
    try:
        stream.flush()
    except (OSError, ValueError) as error:
        raise TunnelError("io") from error


def stream_read_size(stream: ByteStream) -> int:
    try:
        waiting = getattr(stream, "in_waiting")
    except AttributeError:
        return STREAM_CHUNK
    except (OSError, ValueError) as error:
        raise TunnelError("io") from error
    if type(waiting) is not int or waiting < 0:
        raise TunnelError("io")
    return max(1, min(waiting, STREAM_CHUNK))


def read_some(
    stream: ByteStream,
    size: int,
    *,
    deadline_ns: int,
    canary: CompletionCanary | None = None,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
    max_empty_completions: int = MAX_EMPTY_COMPLETIONS,
) -> bytes:
    if size <= 0 or max_empty_completions < 0:
        raise TunnelError("internal")
    empty = 0
    while True:
        if _deadline_expired(deadline_ns, monotonic_ns):
            raise TunnelError("timeout")
        started = monotonic_ns()
        try:
            fragment = stream.read(size)
        except (OSError, ValueError) as error:
            if canary is not None:
                canary.record(monotonic_ns() - started, False)
            raise TunnelError("io") from error
        if canary is not None:
            canary.record(monotonic_ns() - started, bool(fragment))
        if fragment:
            if len(fragment) > size:
                raise TunnelError("io")
            return fragment
        if _deadline_expired(deadline_ns, monotonic_ns):
            raise TunnelError("timeout")
        empty += 1
        if empty > max_empty_completions:
            raise TunnelError("zero-progress")


def _require_extension(certificate: x509.Certificate, extension_type: type) -> x509.Extension:
    try:
        return certificate.extensions.get_extension_for_class(extension_type)
    except x509.ExtensionNotFound as error:
        raise TunnelError("wrong-spki") from error


def validate_peer_certificate(
    der: bytes, *, expected_san: str, expected_spki: bytes
) -> None:
    if len(expected_spki) != 32:
        raise TunnelError("wrong-spki")
    try:
        expected_address = ipaddress.ip_address(expected_san)
        certificate = x509.load_der_x509_certificate(der)
        public_key = certificate.public_key()
    except (ValueError, TypeError) as error:
        raise TunnelError("wrong-san") from error
    if (
        certificate.version is not x509.Version.v3
        or certificate.issuer != certificate.subject
        or not isinstance(public_key, ec.EllipticCurvePublicKey)
    ):
        raise TunnelError("wrong-spki")
    if not isinstance(public_key.curve, ec.SECP256R1) or not isinstance(
        certificate.signature_hash_algorithm, hashes.SHA256
    ):
        raise TunnelError("wrong-spki")
    try:
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
    except (InvalidSignature, ValueError) as error:
        raise TunnelError("wrong-spki") from error
    basic = _require_extension(certificate, x509.BasicConstraints)
    usage = _require_extension(certificate, x509.KeyUsage)
    extended = _require_extension(certificate, x509.ExtendedKeyUsage)
    san = _require_extension(certificate, x509.SubjectAlternativeName)
    if (
        not basic.critical
        or basic.value.ca
        or not usage.critical
        or not usage.value.digital_signature
        or usage.value.content_commitment
        or usage.value.key_encipherment
        or usage.value.data_encipherment
        or usage.value.key_agreement
        or usage.value.key_cert_sign
        or usage.value.crl_sign
        or ExtendedKeyUsageOID.SERVER_AUTH not in extended.value
    ):
        raise TunnelError("wrong-spki")
    addresses = san.value.get_values_for_type(x509.IPAddress)
    if expected_address not in addresses:
        raise TunnelError("wrong-san")
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    observed = hashlib.sha256(spki).digest()
    if not hmac.compare_digest(observed, expected_spki):
        raise TunnelError("wrong-spki")


def validate_negotiated_profile(
    *, version: str | None, cipher: str | None, alpn: str | None
) -> None:
    if version != TLS_VERSION:
        raise TunnelError("wrong-version")
    if cipher != TLS_CIPHER:
        raise TunnelError("wrong-cipher")
    if alpn != TLS_ALPN:
        raise TunnelError("wrong-alpn")


def validate_stream_result(
    *,
    expected_bytes: int,
    observed_bytes: int,
    expected_sha256: str,
    observed_sha256: str,
) -> None:
    if expected_bytes <= 0 or observed_bytes != expected_bytes:
        raise TunnelError("byte-count")
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", observed_sha256) is None
        or not hmac.compare_digest(expected_sha256, observed_sha256)
    ):
        raise TunnelError("digest-mismatch")


def load_pin(path: pathlib.Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TunnelError("wrong-spki") from error
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or (information.st_mode & 0o777) not in (0o444, 0o644)
            or information.st_size not in (64, 65)
        ):
            raise TunnelError("wrong-spki")
        encoded = os.read(descriptor, 66)
    except OSError as error:
        raise TunnelError("wrong-spki") from error
    finally:
        os.close(descriptor)
    if PIN_PATTERN.fullmatch(encoded) is None:
        raise TunnelError("wrong-spki")
    return bytes.fromhex(encoded.strip().decode("ascii"))


def build_client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(TLS_CIPHER)
    context.set_alpn_protocols([TLS_ALPN])
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "OP_NO_TICKET"):
        context.options |= ssl.OP_NO_TICKET
    return context


class TlsSerialClient:
    def __init__(
        self,
        stream: ByteStream,
        *,
        expected_san: str,
        expected_spki: bytes,
        timeout_seconds: float,
        canary: CompletionCanary | None = None,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if expected_san != EXPECTED_SAN or timeout_seconds <= 0:
            raise TunnelError("wrong-san")
        self.stream = stream
        self.expected_san = expected_san
        self.expected_spki = bytes(expected_spki)
        self.canary = canary if canary is not None else CompletionCanary()
        self.monotonic_ns = monotonic_ns
        self.deadline_ns = monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls: ssl.SSLObject = build_client_context().wrap_bio(
            self.incoming,
            self.outgoing,
            server_side=False,
            server_hostname=expected_san,
        )
        self._handshake()

    def _flush(self) -> None:
        while self.outgoing.pending:
            ciphertext = self.outgoing.read(min(self.outgoing.pending, STREAM_CHUNK))
            write_all(
                self.stream,
                ciphertext,
                deadline_ns=self.deadline_ns,
                canary=self.canary,
                monotonic_ns=self.monotonic_ns,
            )

    def _feed(self) -> None:
        ciphertext = read_some(
            self.stream,
            stream_read_size(self.stream),
            deadline_ns=self.deadline_ns,
            canary=self.canary,
            monotonic_ns=self.monotonic_ns,
        )
        self.incoming.write(ciphertext)

    def _handshake(self) -> None:
        while True:
            try:
                self.tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLWantWriteError:
                self._flush()
            except ssl.SSLError as error:
                raise TunnelError(
                    "tls-handshake", tls_reason=getattr(error, "reason", None)
                ) from error
        self._flush()
        cipher = self.tls.cipher()
        validate_negotiated_profile(
            version=self.tls.version(),
            cipher=None if cipher is None else cipher[0],
            alpn=self.tls.selected_alpn_protocol(),
        )
        certificate = self.tls.getpeercert(binary_form=True)
        if not certificate:
            raise TunnelError("wrong-spki")
        validate_peer_certificate(
            certificate,
            expected_san=self.expected_san,
            expected_spki=self.expected_spki,
        )

    def write(self, data: bytes | memoryview) -> None:
        view = memoryview(data)
        while view:
            if _deadline_expired(self.deadline_ns, self.monotonic_ns):
                raise TunnelError("timeout")
            try:
                amount = self.tls.write(view[:STREAM_CHUNK])
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
                continue
            except ssl.SSLWantWriteError:
                self._flush()
                continue
            except ssl.SSLError as error:
                raise TunnelError(
                    "io", tls_reason=getattr(error, "reason", None)
                ) from error
            if amount <= 0 or amount > len(view):
                raise TunnelError("zero-progress")
            view = view[amount:]
            self._flush()

    def read(self, maximum: int) -> bytes:
        while True:
            if _deadline_expired(self.deadline_ns, self.monotonic_ns):
                raise TunnelError("timeout")
            try:
                data = self.tls.read(maximum)
                if not data:
                    raise TunnelError("truncated")
                return data
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLWantWriteError:
                self._flush()
            except ssl.SSLZeroReturnError as error:
                raise TunnelError("truncated") from error
            except ssl.SSLError as error:
                raise TunnelError(
                    "io", tls_reason=getattr(error, "reason", None)
                ) from error

    def read_exact(self, amount: int) -> bytes:
        output = bytearray()
        while len(output) < amount:
            output.extend(self.read(min(STREAM_CHUNK, amount - len(output))))
        return bytes(output)

    def read_line(self) -> bytes:
        output = bytearray()
        while len(output) < MAX_COMMAND_BYTES:
            value = self.read(1)
            output.extend(value)
            if value == b"\n":
                return bytes(output)
        raise TunnelError("io")


def deterministic_chunk(offset: int, amount: int) -> bytes:
    if offset < 0 or amount < 0:
        raise TunnelError("internal")
    start = offset % len(PATTERN)
    needed = start + amount
    repeated = PATTERN * ((needed + len(PATTERN) - 1) // len(PATTERN))
    return repeated[start : start + amount]


def deterministic_digest(total_bytes: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < total_bytes:
        amount = min(STREAM_CHUNK, total_bytes - offset)
        digest.update(deterministic_chunk(offset, amount))
        offset += amount
    return digest.hexdigest()


def _command(mode: str, total_bytes: int, expected_sha256: str) -> bytes:
    if (
        mode not in ("upstream", "downstream", "artifact")
        or not 0 < total_bytes <= ARTIFACT_BYTES
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or (
            mode == "artifact"
            and (total_bytes != ARTIFACT_BYTES or expected_sha256 != ARTIFACT_SHA256)
        )
    ):
        raise TunnelError("internal")
    command = json.dumps(
        {"bytes": total_bytes, "mode": mode, "sha256": expected_sha256},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    if len(command) > MAX_COMMAND_BYTES:
        raise TunnelError("internal")
    return command


def run_upstream(client: TlsSerialClient, total_bytes: int) -> tuple[int, str, int]:
    expected = deterministic_digest(total_bytes)
    client.write(_command("upstream", total_bytes, expected))
    started = time.monotonic_ns()
    offset = 0
    while offset < total_bytes:
        amount = min(STREAM_CHUNK, total_bytes - offset)
        client.write(deterministic_chunk(offset, amount))
        offset += amount
    response = client.read_line()
    duration = max(time.monotonic_ns() - started, 1)
    try:
        decoded = json.loads(response)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TunnelError("io") from error
    if decoded != {"bytes": total_bytes, "sha256": expected, "status": "ok"}:
        raise TunnelError("digest-mismatch")
    return total_bytes, expected, duration


def run_downstream(
    client: TlsSerialClient,
    *,
    mode: str,
    total_bytes: int,
    expected_sha256: str,
) -> tuple[int, str, int]:
    started = time.monotonic_ns()
    client.write(_command(mode, total_bytes, expected_sha256))
    digest = hashlib.sha256()
    observed = 0
    while observed < total_bytes:
        try:
            fragment = client.read(min(STREAM_CHUNK, total_bytes - observed))
        except TunnelError as error:
            if observed > 0 and error.code in (
                "zero-progress",
                "timeout",
                "io",
                "truncated",
            ):
                raise TunnelError("truncated") from error
            raise
        digest.update(fragment)
        observed += len(fragment)
    duration = max(time.monotonic_ns() - started, 1)
    observed_digest = digest.hexdigest()
    validate_stream_result(
        expected_bytes=total_bytes,
        observed_bytes=observed,
        expected_sha256=expected_sha256,
        observed_sha256=observed_digest,
    )
    return observed, observed_digest, duration


def _read_command(connection: ssl.SSLSocket) -> dict[str, object]:
    encoded = bytearray()
    while len(encoded) < MAX_COMMAND_BYTES:
        value = connection.recv(1)
        if not value:
            raise TunnelError("truncated")
        encoded.extend(value)
        if value == b"\n":
            break
    else:
        raise TunnelError("io")
    try:
        command = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TunnelError("io") from error
    if set(command) != {"bytes", "mode", "sha256"}:
        raise TunnelError("io")
    if (
        type(command["bytes"]) is not int
        or not 0 < command["bytes"] <= ARTIFACT_BYTES
        or command["mode"] not in ("upstream", "downstream", "artifact")
        or not isinstance(command["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", command["sha256"]) is None
        or (
            command["mode"] == "artifact"
            and (
                command["bytes"] != ARTIFACT_BYTES
                or command["sha256"] != ARTIFACT_SHA256
            )
        )
    ):
        raise TunnelError("io")
    return command


def _serve_connection(
    connection: ssl.SSLSocket,
    *,
    artifact: pathlib.Path,
    variant: str,
) -> None:
    command = _read_command(connection)
    total_bytes = cast(int, command["bytes"])
    expected = str(command["sha256"])
    if command["mode"] == "upstream":
        digest = hashlib.sha256()
        observed = 0
        while observed < total_bytes:
            fragment = connection.recv(min(STREAM_CHUNK, total_bytes - observed))
            if not fragment:
                raise TunnelError("truncated")
            digest.update(fragment)
            observed += len(fragment)
        validate_stream_result(
            expected_bytes=total_bytes,
            observed_bytes=observed,
            expected_sha256=expected,
            observed_sha256=digest.hexdigest(),
        )
        response = json.dumps(
            {"bytes": observed, "sha256": digest.hexdigest(), "status": "ok"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        connection.sendall(response)
        return
    limit = total_bytes // 2 if variant == "truncation" else total_bytes
    digest = hashlib.sha256()
    offset = 0
    with _open_artifact(artifact) if command["mode"] == "artifact" else _NullContext() as stream:
        while offset < limit:
            amount = min(STREAM_CHUNK, limit - offset)
            if command["mode"] == "artifact":
                fragment = stream.read(amount)
                if len(fragment) != amount:
                    raise TunnelError("byte-count")
            else:
                fragment = deterministic_chunk(offset, amount)
            if variant == "digest-mismatch" and offset == 0:
                changed = bytearray(fragment)
                changed[0] ^= 1
                fragment = bytes(changed)
            digest.update(fragment)
            connection.sendall(fragment)
            offset += len(fragment)
    if variant == "truncation":
        return
    validate_stream_result(
        expected_bytes=total_bytes,
        observed_bytes=offset,
        expected_sha256=expected,
        observed_sha256=digest.hexdigest(),
    )


def _open_artifact(path: pathlib.Path):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TunnelError("internal") from error
    try:
        information = os.fstat(descriptor)
        if (
            path.name != ARTIFACT_SHA256
            or not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or (information.st_mode & 0o777) != 0o444
            or information.st_size != ARTIFACT_BYTES
        ):
            raise TunnelError("internal")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


class _NullContext:
    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        return None


def _parse_address(address: str) -> tuple[str, int]:
    host, separator, port_text = address.rpartition(":")
    if not separator or not host:
        raise TunnelError("internal")
    try:
        port = int(port_text, 10)
    except ValueError as error:
        raise TunnelError("internal") from error
    if not 1 <= port <= 65535:
        raise TunnelError("internal")
    return host, port


def _cleanup_cipher_proof(
    parent_fd: int,
    *,
    final_name: str,
    final_published: bool,
    staging_name: str,
    staging_created: bool,
) -> None:
    cleanup_failed = False
    if final_published:
        try:
            os.chmod(
                final_name,
                0,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_failed = True
    entries = (
        (final_name, final_published),
        (staging_name, staging_created),
    )
    for name, owned in entries:
        if not owned:
            continue
        try:
            os.unlink(name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_failed = True
    try:
        os.fsync(parent_fd)
    except OSError:
        cleanup_failed = True
    if cleanup_failed:
        raise TunnelError("internal")


def _publish_cipher_proof(path: pathlib.Path) -> None:
    parent_flags = os.O_RDONLY | os.O_DIRECTORY
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
        file_flags |= os.O_NOFOLLOW
    parent_fd = -1
    descriptor = -1
    staging_created = False
    final_published = False
    staging_name = f".{path.name}.staging"
    try:
        parent_fd = os.open(path.parent, parent_flags)
        information = os.fstat(parent_fd)
        path_information = os.stat(path.parent, follow_symlinks=False)
        if (
            path.name in ("", ".", "..")
            or not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != 0o700
            or (information.st_dev, information.st_ino)
            != (path_information.st_dev, path_information.st_ino)
        ):
            raise TunnelError("internal")
        descriptor = os.open(staging_name, file_flags, 0o600, dir_fd=parent_fd)
        staging_created = True
        staged_information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(staged_information.st_mode)
            or staged_information.st_uid != os.getuid()
            or stat.S_IMODE(staged_information.st_mode) != 0o600
        ):
            raise TunnelError("internal")
        remaining = memoryview(CIPHER_PROOF)
        while remaining:
            amount = os.write(descriptor, remaining)
            if amount <= 0 or amount > len(remaining):
                raise TunnelError("internal")
            remaining = remaining[amount:]
        os.fsync(descriptor)
        closing = descriptor
        descriptor = -1
        os.close(closing)
        os.link(
            staging_name,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        final_published = True
        os.fsync(parent_fd)
        os.unlink(staging_name, dir_fd=parent_fd)
        staging_created = False
        os.fsync(parent_fd)
    except (OSError, TunnelError) as error:
        if descriptor >= 0:
            closing = descriptor
            descriptor = -1
            try:
                os.close(closing)
            except OSError:
                pass
        if parent_fd >= 0:
            try:
                _cleanup_cipher_proof(
                    parent_fd,
                    final_name=path.name,
                    final_published=final_published,
                    staging_name=staging_name,
                    staging_created=staging_created,
                )
            except TunnelError:
                pass
        if isinstance(error, TunnelError):
            raise
        raise TunnelError("internal") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def prepare_cipher_proof(path: pathlib.Path) -> CipherProofExpectation:
    parent_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    directory_fd = -1
    try:
        directory_fd = os.open(path.parent, parent_flags)
        information = os.fstat(directory_fd)
        path_information = os.stat(path.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != 0o700
            or (information.st_dev, information.st_ino)
            != (path_information.st_dev, path_information.st_ino)
            or path.name in ("", ".", "..")
        ):
            raise TunnelError("wrong-cipher")
        try:
            os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise TunnelError("wrong-cipher")
        return CipherProofExpectation(
            directory_fd=directory_fd,
            name=path.name,
            staging_name=f".{path.name}.staging",
        )
    except (OSError, ValueError) as error:
        if directory_fd >= 0:
            os.close(directory_fd)
        raise TunnelError("wrong-cipher") from error
    except TunnelError:
        if directory_fd >= 0:
            os.close(directory_fd)
        raise


def _read_cipher_proof(expectation: CipherProofExpectation) -> bool:
    if expectation.closed:
        raise TunnelError("wrong-cipher")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        os.stat(
            expectation.staging_name,
            dir_fd=expectation.directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        pass
    except OSError as error:
        raise TunnelError("wrong-cipher") from error
    else:
        return False
    try:
        descriptor = os.open(
            expectation.name, flags, dir_fd=expectation.directory_fd
        )
    except FileNotFoundError:
        return False
    except OSError as error:
        raise TunnelError("wrong-cipher") from error
    try:
        information = os.fstat(descriptor)
        encoded = os.read(descriptor, 64)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o600
        or information.st_size != len(CIPHER_PROOF)
        or encoded != CIPHER_PROOF
    ):
        raise TunnelError("wrong-cipher")
    return True


def _wait_for_cipher_proof(
    expectation: CipherProofExpectation, *, deadline_ns: int
) -> None:
    while True:
        if time.monotonic_ns() >= deadline_ns:
            raise TunnelError("timeout")
        if _read_cipher_proof(expectation):
            return
        time.sleep(0.005)


def classify_expected_rejection(
    actual_error: TunnelError | None,
    expected_rejection: str,
    cipher_proof: CipherProofExpectation | None,
    *,
    deadline_ns: int | None = None,
) -> str:
    if expected_rejection == "wrong-cipher":
        if (
            actual_error is None
            or actual_error.code != "tls-handshake"
            or actual_error.tls_reason != "SSLV3_ALERT_HANDSHAKE_FAILURE"
            or cipher_proof is None
            or deadline_ns is None
        ):
            raise TunnelError(
                actual_error.code if actual_error is not None else "wrong-cipher"
            )
        _wait_for_cipher_proof(cipher_proof, deadline_ns=deadline_ns)
        return "wrong-cipher"
    if actual_error is None or actual_error.code != expected_rejection:
        raise TunnelError(actual_error.code if actual_error is not None else "internal")
    return actual_error.code


DIAGNOSTIC_EVENT_SCHEMA = "pbns-raw-tunnel-server-events-v1"
DIAGNOSTIC_EVENT_KEYS = frozenset(
    (
        "schema",
        "status",
        "error_code",
        "ready",
        "process_alive",
        "accept_count",
        "clienthello_seen",
        "tls_established",
        "server_flight_sent",
        "application_complete",
        "duration_ns",
    )
)
DIAGNOSTIC_EVENT_ERRORS = frozenset(
    (
        "none",
        "timeout",
        "io",
        "tls-handshake",
        "tls-profile",
        "application",
        "internal",
        "signal",
    )
)
DIAGNOSTIC_APPLICATION_BYTES = 4096
DIAGNOSTIC_OBSERVER_BYTES = 4096


class DiagnosticEventJournal:
    def __init__(self, path: pathlib.Path) -> None:
        self.started_ns = time.monotonic_ns()
        self.lock = threading.Lock()
        self.parent_fd = -1
        self.descriptor = -1
        parent_flags = os.O_RDONLY | os.O_DIRECTORY
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            parent_flags |= os.O_NOFOLLOW
            file_flags |= os.O_NOFOLLOW
        try:
            self.parent_fd = os.open(path.parent, parent_flags)
            parent = os.fstat(self.parent_fd)
            path_parent = os.stat(path.parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) != 0o700
                or (parent.st_dev, parent.st_ino)
                != (path_parent.st_dev, path_parent.st_ino)
            ):
                raise TunnelError("internal")
            self.descriptor = os.open(
                path.name, file_flags, 0o600, dir_fd=self.parent_fd
            )
            information = os.fstat(self.descriptor)
            if (
                not stat.S_ISREG(information.st_mode)
                or information.st_uid != os.getuid()
                or stat.S_IMODE(information.st_mode) != 0o600
            ):
                raise TunnelError("internal")
            os.fsync(self.parent_fd)
        except BaseException:
            self.close()
            raise
        self.snapshot: dict[str, object] = {
            "schema": DIAGNOSTIC_EVENT_SCHEMA,
            "status": "not-run",
            "error_code": "none",
            "ready": False,
            "process_alive": True,
            "accept_count": 0,
            "clienthello_seen": False,
            "tls_established": False,
            "server_flight_sent": False,
            "application_complete": False,
            "duration_ns": 0,
        }
        self.record()

    def record(self, **updates: object) -> None:
        with self.lock:
            if self.descriptor < 0 or not set(updates).issubset(DIAGNOSTIC_EVENT_KEYS):
                raise TunnelError("internal")
            self.snapshot.update(updates)
            self.snapshot["duration_ns"] = max(
                time.monotonic_ns() - self.started_ns, 1
            )
            if (
                set(self.snapshot) != DIAGNOSTIC_EVENT_KEYS
                or self.snapshot["status"] not in ("passed", "failed", "not-run")
                or self.snapshot["error_code"] not in DIAGNOSTIC_EVENT_ERRORS
                or not isinstance(self.snapshot["accept_count"], int)
                or not 0 <= self.snapshot["accept_count"] <= 1
            ):
                raise TunnelError("internal")
            encoded = (
                json.dumps(self.snapshot, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("ascii")
            if len(encoded) > 2048:
                raise TunnelError("internal")
            view = memoryview(encoded)
            while view:
                written = os.write(self.descriptor, view)
                if written <= 0 or written > len(view):
                    raise TunnelError("internal")
                view = view[written:]
            os.fsync(self.descriptor)

    def value(self, name: str) -> object:
        with self.lock:
            if name not in DIAGNOSTIC_EVENT_KEYS:
                raise TunnelError("internal")
            return self.snapshot[name]

    def close(self) -> None:
        with self.lock:
            if self.descriptor >= 0:
                os.close(self.descriptor)
                self.descriptor = -1
            if self.parent_fd >= 0:
                os.close(self.parent_fd)
                self.parent_fd = -1


class ClientHelloObserver:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.seen = False

    def feed(self, fragment: memoryview) -> bool:
        if self.seen:
            return True
        if len(fragment) > DIAGNOSTIC_OBSERVER_BYTES - len(self.buffer):
            raise TunnelError("tls-handshake")
        self.buffer.extend(fragment)
        offset = 0
        while len(self.buffer) - offset >= 5:
            content_type = self.buffer[offset]
            record_length = (self.buffer[offset + 3] << 8) | self.buffer[offset + 4]
            if record_length == 0 or record_length > DIAGNOSTIC_OBSERVER_BYTES - 5:
                raise TunnelError("tls-handshake")
            record_end = offset + 5 + record_length
            if record_end > len(self.buffer):
                break
            if content_type == 22 and self.buffer[offset + 5] == 1:
                self.seen = True
                self.wipe()
                return True
            offset = record_end
        if offset:
            del self.buffer[:offset]
        return False

    def wipe(self) -> None:
        for index in range(len(self.buffer)):
            self.buffer[index] = 0
        self.buffer.clear()


def _diagnostic_server_context(
    certificate: pathlib.Path, private_key: pathlib.Path
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(TLS_CIPHER)
    context.set_alpn_protocols([TLS_ALPN])
    if hasattr(ssl, "OP_NO_TICKET"):
        context.options |= ssl.OP_NO_TICKET
    try:
        context.load_cert_chain(certificate, private_key)
    except (OSError, ssl.SSLError) as error:
        raise TunnelError("internal") from error
    return context


def _diagnostic_set_deadline(
    connection: socket.socket,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> None:
    now_ns = monotonic_ns()
    if now_ns >= deadline_ns:
        raise TunnelError("timeout")
    connection.settimeout((deadline_ns - now_ns) / 1_000_000_000)


def _diagnostic_flush(
    connection: socket.socket,
    outgoing: ssl.MemoryBIO,
    journal: DiagnosticEventJournal,
    *,
    handshake: bool,
    deadline_ns: int,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> None:
    while outgoing.pending:
        _diagnostic_set_deadline(connection, deadline_ns, monotonic_ns)
        immutable = outgoing.read(min(outgoing.pending, STREAM_CHUNK))
        ciphertext = bytearray(immutable)
        immutable = b""
        try:
            connection.sendall(ciphertext)
        except TimeoutError as error:
            raise TunnelError("timeout") from error
        except OSError as error:
            raise TunnelError("io") from error
        finally:
            for index in range(len(ciphertext)):
                ciphertext[index] = 0
        if monotonic_ns() >= deadline_ns:
            raise TunnelError("timeout")
        if (
            handshake
            and journal.value("clienthello_seen") is True
            and journal.value("server_flight_sent") is False
        ):
            journal.record(server_flight_sent=True)


def _diagnostic_feed(
    connection: socket.socket,
    incoming: ssl.MemoryBIO,
    observer: ClientHelloObserver,
    journal: DiagnosticEventJournal,
    *,
    deadline_ns: int,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> None:
    ciphertext = bytearray(STREAM_CHUNK)
    try:
        _diagnostic_set_deadline(connection, deadline_ns, monotonic_ns)
        received = connection.recv_into(ciphertext)
        if received <= 0:
            raise TunnelError("io")
        view = memoryview(ciphertext)[:received]
        if observer.feed(view) and journal.value("clienthello_seen") is False:
            journal.record(clienthello_seen=True)
        incoming.write(view)
        if monotonic_ns() >= deadline_ns:
            raise TunnelError("timeout")
    except TimeoutError as error:
        raise TunnelError("timeout") from error
    except (OSError, ssl.SSLError) as error:
        raise TunnelError("io") from error
    finally:
        for index in range(len(ciphertext)):
            ciphertext[index] = 0


def _diagnostic_serve_connection(
    connection: socket.socket,
    context: ssl.SSLContext,
    journal: DiagnosticEventJournal,
    *,
    deadline_ns: int,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> None:
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=True)
    observer = ClientHelloObserver()
    try:
        while True:
            if monotonic_ns() >= deadline_ns:
                raise TunnelError("timeout")
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                _diagnostic_flush(
                    connection,
                    outgoing,
                    journal,
                    handshake=True,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
                _diagnostic_feed(
                    connection,
                    incoming,
                    observer,
                    journal,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
            except ssl.SSLWantWriteError:
                _diagnostic_flush(
                    connection,
                    outgoing,
                    journal,
                    handshake=True,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
            except ssl.SSLError as error:
                raise TunnelError("tls-handshake") from error
        _diagnostic_flush(
            connection,
            outgoing,
            journal,
            handshake=True,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )
        cipher = tls.cipher()
        try:
            validate_negotiated_profile(
                version=tls.version(),
                cipher=None if cipher is None else cipher[0],
                alpn=tls.selected_alpn_protocol(),
            )
        except TunnelError as error:
            raise TunnelError("tls-profile") from error
        if monotonic_ns() >= deadline_ns:
            raise TunnelError("timeout")
        journal.record(tls_established=True)

        application = bytearray(
            deterministic_chunk(0, DIAGNOSTIC_APPLICATION_BYTES)
        )
        try:
            view = memoryview(application)
            while view:
                if monotonic_ns() >= deadline_ns:
                    raise TunnelError("timeout")
                try:
                    written = tls.write(view)
                except ssl.SSLWantReadError:
                    _diagnostic_flush(
                        connection,
                        outgoing,
                        journal,
                        handshake=False,
                        deadline_ns=deadline_ns,
                        monotonic_ns=monotonic_ns,
                    )
                    _diagnostic_feed(
                        connection,
                        incoming,
                        observer,
                        journal,
                        deadline_ns=deadline_ns,
                        monotonic_ns=monotonic_ns,
                    )
                    continue
                except ssl.SSLWantWriteError:
                    _diagnostic_flush(
                        connection,
                        outgoing,
                        journal,
                        handshake=False,
                        deadline_ns=deadline_ns,
                        monotonic_ns=monotonic_ns,
                    )
                    continue
                except ssl.SSLError as error:
                    raise TunnelError("application") from error
                if written <= 0 or written > len(view):
                    raise TunnelError("application")
                view = view[written:]
                _diagnostic_flush(
                    connection,
                    outgoing,
                    journal,
                    handshake=False,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
        finally:
            for index in range(len(application)):
                application[index] = 0
        if monotonic_ns() >= deadline_ns:
            raise TunnelError("timeout")
        journal.record(application_complete=True)
    finally:
        observer.wipe()


def diagnostic_serve(
    *,
    listen: str,
    certificate: pathlib.Path,
    private_key: pathlib.Path,
    event_journal: pathlib.Path,
    timeout_seconds: float,
) -> None:
    if timeout_seconds <= 0 or timeout_seconds > 60:
        raise TunnelError("internal")
    journal = DiagnosticEventJournal(event_journal)
    stopping = False

    def stop(_signal: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    previous_term = signal.signal(signal.SIGTERM, stop)
    previous_int = signal.signal(signal.SIGINT, stop)
    failure = "internal"
    try:
        context = _diagnostic_server_context(certificate, private_key)
        host, port = _parse_address(listen)
        deadline_ns = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, port))
            listener.listen(1)
            listener.settimeout(0.1)
            journal.record(ready=True)
            connection: socket.socket | None = None
            while connection is None:
                if stopping:
                    failure = "signal"
                    raise TunnelError("cancelled")
                if time.monotonic_ns() >= deadline_ns:
                    failure = "timeout"
                    raise TunnelError("timeout")
                try:
                    connection, _peer = listener.accept()
                except TimeoutError:
                    continue
            journal.record(accept_count=1)
            with connection:
                _diagnostic_serve_connection(
                    connection, context, journal, deadline_ns=deadline_ns
                )
        if time.monotonic_ns() >= deadline_ns:
            raise TunnelError("timeout")
        journal.record(
            status="passed", error_code="none", process_alive=False
        )
    except TunnelError as error:
        if failure == "internal":
            if error.code == "timeout":
                failure = "timeout"
            elif error.code == "tls-handshake":
                failure = "tls-handshake"
            elif error.code == "tls-profile":
                failure = "tls-profile"
            elif error.code == "application":
                failure = "application"
            elif error.code == "io":
                failure = "io"
        journal.record(
            status="failed", error_code=failure, process_alive=False
        )
        raise
    except (OSError, ValueError) as error:
        journal.record(
            status="failed", error_code="io", process_alive=False
        )
        raise TunnelError("io") from error
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        journal.close()


def serve(
    *,
    listen: str,
    certificate: pathlib.Path,
    private_key: pathlib.Path,
    artifact: pathlib.Path,
    ready_file: pathlib.Path,
    variant: str,
    cipher_proof: pathlib.Path | None = None,
) -> None:
    _load_loopback_module().verify_digest_artifact(
        artifact,
        expected_sha256=ARTIFACT_SHA256,
        expected_size=ARTIFACT_BYTES,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384" if variant == "wrong-cipher" else TLS_CIPHER
    )
    context.set_alpn_protocols(["wrong/1"] if variant == "wrong-alpn" else [TLS_ALPN])
    if hasattr(ssl, "OP_NO_TICKET"):
        context.options |= ssl.OP_NO_TICKET
    try:
        context.load_cert_chain(certificate, private_key)
    except (OSError, ssl.SSLError) as error:
        raise TunnelError("internal") from error
    if (variant == "wrong-cipher") != (cipher_proof is not None):
        raise TunnelError("internal")
    host, port = _parse_address(listen)
    stopping = False

    def stop(_signal: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(4)
        listener.settimeout(0.5)
        ready_file.write_text("ready\n", encoding="ascii")
        ready_file.chmod(0o600)
        while not stopping:
            try:
                connection, _peer = listener.accept()
            except TimeoutError:
                continue
            with connection:
                connection.settimeout(5.0)
                try:
                    with context.wrap_socket(connection, server_side=True) as tls_connection:
                        _serve_connection(
                            tls_connection,
                            artifact=artifact,
                            variant=variant,
                        )
                except ssl.SSLError as error:
                    if variant == "wrong-cipher":
                        if (
                            cipher_proof is not None
                            and getattr(error, "reason", None) == "NO_SHARED_CIPHER"
                        ):
                            _publish_cipher_proof(cipher_proof)
                            return
                        raise TunnelError("wrong-cipher") from error
                    continue
                except (OSError, TunnelError) as error:
                    if variant == "wrong-cipher":
                        raise TunnelError("wrong-cipher") from error
                    continue
                if variant == "wrong-cipher":
                    raise TunnelError("wrong-cipher")


def _load_loopback_module():
    path = pathlib.Path(__file__).with_name("pico-loopback.py")
    specification = importlib.util.spec_from_file_location("pbns_pico_loopback", path)
    if specification is None or specification.loader is None:
        raise TunnelError("internal")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _open_serial(
    port: pathlib.Path,
    timeout_seconds: float,
    *,
    sysfs_root: pathlib.Path = pathlib.Path("/sys/bus/usb/devices"),
    tty_root: pathlib.Path = pathlib.Path("/sys/class/tty"),
    expected_serial: str = "E66130100F527A26",
    identity_verifier: Callable[[], dict[str, str]] | None = None,
    serial_factory: Callable[..., OpenedSerial] | None = None,
    fstat: Callable[[int], object] = os.fstat,
) -> OpenedSerial:
    if port != pathlib.Path("/dev/ttyACM0"):
        raise TunnelError("io")
    loopback = _load_loopback_module()
    verifier = identity_verifier
    if verifier is None:
        verifier = lambda: loopback.verify_hardware_identity(
            sysfs_root, tty_root, cdc0=port, cdc1=pathlib.Path("/dev/ttyACM1"),
            expected_serial=expected_serial,
        )
    try:
        before = verifier()
    except (OSError, ValueError, KeyError, loopback.LoopbackError) as error:
        raise TunnelError("io") from error
    if serial_factory is None:
        try:
            import serial
        except ImportError as error:
            raise TunnelError("io") from error
        serial_factory = lambda **kwargs: serial.Serial(**kwargs)
    serial_port: OpenedSerial | None = None
    try:
        serial_port = serial_factory(
            port=str(port), baudrate=115200, timeout=timeout_seconds,
            write_timeout=timeout_seconds, exclusive=True,
        )
        descriptor_information = fstat(serial_port.fileno())
        loopback.verify_cdc_node_metadata(descriptor_information, before["cdc0_dev"])
        after = verifier()
        for name in ("device", "cdc0_interface", "cdc0_dev"):
            if before[name] != after[name]:
                raise TunnelError("io")
        loopback.verify_cdc_node_metadata(descriptor_information, after["cdc0_dev"])
        return serial_port
    except (OSError, ValueError, KeyError, loopback.LoopbackError) as error:
        if serial_port is not None:
            serial_port.close()
        raise TunnelError("io") from error
    except TunnelError:
        if serial_port is not None:
            serial_port.close()
        raise


def _rate_mib_s(byte_count: int, duration_ns: int) -> float:
    return round((byte_count * 1_000_000_000) / (duration_ns * 1024 * 1024), 6)


def _run_client(arguments: argparse.Namespace) -> None:
    loopback = _load_loopback_module()
    pin = load_pin(arguments.pin)
    canary = CompletionCanary()
    actual_error: TunnelError | None = None
    observed_bytes = 0
    observed_digest: str | None = None
    duration_ns = 1
    expected_digest = arguments.expected_sha256
    expected_rejection = arguments.expected_rejection
    proof_expectation: CipherProofExpectation | None = None
    if arguments.timeout <= 0:
        raise TunnelError("internal")
    trial_deadline_ns = time.monotonic_ns() + int(
        arguments.timeout * 1_000_000_000
    )
    try:
        if expected_rejection == "wrong-cipher":
            if arguments.cipher_proof is None:
                raise TunnelError("wrong-cipher")
            proof_expectation = prepare_cipher_proof(arguments.cipher_proof)
        elif arguments.cipher_proof is not None:
            raise TunnelError("internal")
        with _open_serial(
            arguments.port, arguments.timeout, sysfs_root=arguments.sysfs_root,
            tty_root=arguments.tty_root, expected_serial=arguments.expected_serial,
        ) as serial_port:
            if not 0 <= arguments.connect_delay <= 30:
                raise TunnelError("internal")
            time.sleep(arguments.connect_delay)
            client = TlsSerialClient(
                serial_port,
                expected_san=arguments.expected_san,
                expected_spki=pin,
                timeout_seconds=arguments.timeout,
                canary=canary,
            )
            if arguments.cancel_after > 0:
                client.write(
                    _command(
                        "upstream",
                        arguments.total_bytes,
                        deterministic_digest(arguments.total_bytes),
                    )
                )
                client.write(deterministic_chunk(0, arguments.cancel_after))
                observed_bytes = arguments.cancel_after
                observed_digest = hashlib.sha256(
                    deterministic_chunk(0, arguments.cancel_after)
                ).hexdigest()
                raise TunnelError("cancelled")
            if arguments.mode == "upstream":
                observed_bytes, observed_digest, duration_ns = run_upstream(
                    client, arguments.total_bytes
                )
                expected_digest = deterministic_digest(arguments.total_bytes)
            else:
                observed_bytes, observed_digest, duration_ns = run_downstream(
                    client,
                    mode=arguments.mode,
                    total_bytes=arguments.total_bytes,
                    expected_sha256=expected_digest,
                )
    except TunnelError as error:
        actual_error = error
    try:
        if expected_rejection is None:
            passed = actual_error is None
            error_code = (
                "none"
                if passed
                else actual_error.code if actual_error is not None else "internal"
            )
        else:
            try:
                error_code = classify_expected_rejection(
                    actual_error,
                    expected_rejection,
                    proof_expectation,
                    deadline_ns=trial_deadline_ns,
                )
                passed = True
            except TunnelError as classification_error:
                passed = False
                error_code = classification_error.code
    finally:
        if proof_expectation is not None:
            proof_expectation.close()
    result = loopback._base_result(
        trial=arguments.trial,
        status="passed" if passed else "failed",
        error_code=error_code,
        warmup=arguments.warmup,
        bytes_expected=arguments.total_bytes,
        bytes_observed=observed_bytes,
        sha256_expected=expected_digest,
        sha256_observed=observed_digest,
        duration_ns=duration_ns,
        rate_mib_s=_rate_mib_s(observed_bytes, duration_ns) if observed_bytes else 0.0,
        artifact_id=ARTIFACT_SHA256 if arguments.mode == "artifact" else None,
        rollback_needed=not passed,
    )
    result.update(canary.metadata())
    loopback.write_result(arguments.results_dir, result, filename=arguments.filename)
    if not passed:
        raise TunnelError(error_code)


def _add_client_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--port", required=True, type=pathlib.Path)
    parser.add_argument("--mode", choices=("upstream", "downstream", "artifact"), required=True)
    parser.add_argument("--total-bytes", required=True, type=int)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-san", required=True)
    parser.add_argument("--pin", required=True, type=pathlib.Path)
    parser.add_argument("--results-dir", required=True, type=pathlib.Path)
    parser.add_argument("--filename", required=True)
    parser.add_argument("--trial", required=True)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--connect-delay", type=float, default=3.0)
    parser.add_argument("--warmup", action="store_true")
    parser.add_argument("--expected-rejection", choices=tuple(sorted(ERROR_CODES)))
    parser.add_argument("--cancel-after", type=int, default=0)
    parser.add_argument("--cipher-proof", type=pathlib.Path)
    parser.add_argument("--expected-serial", default="E66130100F527A26")
    parser.add_argument("--sysfs-root", type=pathlib.Path, default=pathlib.Path("/sys/bus/usb/devices"))
    parser.add_argument("--tty-root", type=pathlib.Path, default=pathlib.Path("/sys/class/tty"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Host-side UEFI TLS profile feasibility driver over raw Pico CDC0"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("self-test")
    server = commands.add_parser("server")
    server.add_argument("--listen", required=True)
    server.add_argument("--certificate", required=True, type=pathlib.Path)
    server.add_argument("--private-key", required=True, type=pathlib.Path)
    server.add_argument("--artifact", required=True, type=pathlib.Path)
    server.add_argument("--ready-file", required=True, type=pathlib.Path)
    server.add_argument("--cipher-proof", type=pathlib.Path)
    server.add_argument(
        "--variant",
        choices=("normal", "wrong-alpn", "wrong-cipher", "truncation", "digest-mismatch"),
        default="normal",
    )
    diagnostic_server = commands.add_parser("diagnostic-server")
    diagnostic_server.add_argument("--listen", required=True)
    diagnostic_server.add_argument("--certificate", required=True, type=pathlib.Path)
    diagnostic_server.add_argument("--private-key", required=True, type=pathlib.Path)
    diagnostic_server.add_argument("--event-journal", required=True, type=pathlib.Path)
    diagnostic_server.add_argument("--timeout", type=float, default=60.0)
    client = commands.add_parser("client")
    _add_client_arguments(client)
    validate = commands.add_parser("validate-results")
    validate.add_argument("--results-dir", required=True, type=pathlib.Path)
    digest = commands.add_parser("deterministic-digest")
    digest.add_argument("--bytes", required=True, type=int)
    return parser


def self_test() -> None:
    validate_negotiated_profile(version=TLS_VERSION, cipher=TLS_CIPHER, alpn=TLS_ALPN)
    digest = deterministic_digest(4096)
    validate_stream_result(
        expected_bytes=4096,
        observed_bytes=4096,
        expected_sha256=digest,
        observed_sha256=digest,
    )
    if CompletionCanary._percentile([1, 2, 3, 4], 95) != 4:
        raise TunnelError("internal")


def _validate_results(directory: pathlib.Path) -> None:
    loopback = _load_loopback_module()
    records = []
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = -1
    try:
        directory_fd = os.open(directory, flags)
        information = os.fstat(directory_fd)
        path_information = os.stat(directory, follow_symlinks=False)
        if (
            not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != 0o700
            or (information.st_dev, information.st_ino)
            != (path_information.st_dev, path_information.st_ino)
        ):
            raise TunnelError("internal")
        names = set(os.listdir(directory_fd))
        if names != set(loopback.EXPECTED_RESULT_FILES):
            raise TunnelError("internal")
        for name in sorted(names):
            file_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            descriptor = os.open(name, file_flags, dir_fd=directory_fd)
            try:
                file_information = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(file_information.st_mode)
                    or file_information.st_uid != os.getuid()
                    or stat.S_IMODE(file_information.st_mode) != 0o600
                    or not 0 < file_information.st_size <= 65536
                ):
                    raise TunnelError("internal")
                chunks = []
                remaining = file_information.st_size
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 16384))
                    if not chunk:
                        raise TunnelError("internal")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                encoded = b"".join(chunks)
            finally:
                os.close(descriptor)
            record = json.loads(encoded)
            loopback.validate_result(record)
            expected_trial, expected_warmup = loopback.EXPECTED_RESULT_TRIALS[name]
            if (
                record["trial"] != expected_trial
                or record["warmup"] is not expected_warmup
            ):
                raise TunnelError("internal")
            records.append(record)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        loopback.LoopbackError,
    ) as error:
        raise TunnelError("internal") from error
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
    try:
        loopback.validate_performance_gate(
            records, expected_artifact_sha256=ARTIFACT_SHA256
        )
    except loopback.LoopbackError as error:
        raise TunnelError("internal") from error


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "self-test":
            self_test()
            print("UEFI TLS RAW TUNNEL SELF-TEST PASS")
        elif arguments.command == "server":
            serve(
                listen=arguments.listen,
                certificate=arguments.certificate,
                private_key=arguments.private_key,
                artifact=arguments.artifact,
                ready_file=arguments.ready_file,
                variant=arguments.variant,
                cipher_proof=arguments.cipher_proof,
            )
        elif arguments.command == "diagnostic-server":
            diagnostic_serve(
                listen=arguments.listen,
                certificate=arguments.certificate,
                private_key=arguments.private_key,
                event_journal=arguments.event_journal,
                timeout_seconds=arguments.timeout,
            )
            print("RAW TUNNEL DIAGNOSTIC SERVER PASS")
        elif arguments.command == "client":
            _run_client(arguments)
            print(f"HIL TRIAL PASS {arguments.trial}")
        elif arguments.command == "deterministic-digest":
            if not 0 < arguments.bytes <= ARTIFACT_BYTES:
                raise TunnelError("internal")
            print(deterministic_digest(arguments.bytes))
        else:
            _validate_results(arguments.results_dir)
            print("UEFI TLS RAW PERFORMANCE GATE PASS")
    except (TunnelError, OSError, ValueError):
        print("UEFI TLS raw tunnel failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
