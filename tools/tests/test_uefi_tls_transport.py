#!/usr/bin/env python3

from collections.abc import Callable

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from types import SimpleNamespace
from unittest import mock


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
LIBRARY_DIR = PBNS_ROOT / "uefi" / "Library" / "PbnsTlsTransportLib"
PROBE_DIR = PBNS_ROOT / "uefi" / "Applications" / "PbnsTlsProbe"
OBSERVER_HEADER = PBNS_ROOT / "include" / "pbns" / "tls_handshake_observer.h"
FIXTURE_PIN = PBNS_ROOT / "tests" / "fixtures" / "keys" / "tls-gateway-test-spki.sha256"
HIL_DRIVER = PBNS_ROOT / "integration" / "hil" / "uefi-tls-tunnel.py"


class UefiTlsTransportTests(unittest.TestCase):
    hil: types.ModuleType

    @classmethod
    def setUpClass(cls) -> None:
        if not HIL_DRIVER.is_file():
            raise AssertionError("missing UEFI TLS raw-tunnel feasibility driver")
        specification = importlib.util.spec_from_file_location(
            "uefi_tls_tunnel", HIL_DRIVER
        )
        assert specification is not None and specification.loader is not None
        cls.hil = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(cls.hil)

    def test_uefi_adapter_has_required_dependencies_and_no_trust_shortcuts(self) -> None:
        manifest = (LIBRARY_DIR / "PbnsTlsTransportLib.inf").read_text(
            encoding="utf-8"
        )
        source = (LIBRARY_DIR / "PbnsTlsTransportLib.c").read_text(
            encoding="utf-8"
        )
        crt_source = (LIBRARY_DIR / "PbnsTlsCrt.c").read_text(encoding="utf-8")
        header = (LIBRARY_DIR / "PbnsTlsTransportLib.h").read_text(
            encoding="utf-8"
        )
        observer = OBSERVER_HEADER.read_text(encoding="utf-8")
        for required in (
            "MbedTlsLib",
            "PbnsIdentityLib",
            "PbnsUefiPlatformLib",
            "MemoryAllocationLib",
            "BaseMemoryLib",
            "PbnsTlsTransportCoreLib",
            "-fstack-usage",
        ):
            self.assertIn(required, manifest)
        for required in (
            "PBNS_TLS_UEFI_TRANSPORT",
            "PbnsTlsTransportCreate",
            "PbnsTlsTransportAsTransport",
            "PbnsTlsTransportDestroy",
            "PbnsIdentityRandomFill",
            "PbnsUefiMonotonicMs",
            "AllocatePool",
            "FreePool",
            "RaiseTPL(TPL_NOTIFY)",
            "RaiseTPL(TPL_HIGH_LEVEL)",
            "TPL_APPLICATION",
            "operation_active",
            "uefi_transport_ops",
            "RestoreTPL",
            "PBNS_TLS_UEFI_POOL_CAP",
            "PBNS_TLS_UEFI_PLATFORM_ALLOCATION_MAX",
            "PBNS_TLS_CERTIFICATE_DER_MAX",
            "PBNS_TLS_OBSERVER_ACCEPTED_CERTIFICATE_COUNT",
            "MBEDTLS_SSL_IN_CONTENT_LEN",
            "MBEDTLS_SSL_OUT_CONTENT_LEN",
            "PBNS_TPM_RANDOM_SOURCE",
            "volatile",
            "pending_allocations",
        ):
            self.assertIn(required, source + header)
        for required in (
            "PbnsTlsCrt.c",
            "mbedtls_ms_time",
            "time(time_t *timer)",
        ):
            self.assertIn(required, manifest + crt_source)
        self.assertIn("#define PBNS_TLS_OBSERVER_ACCEPTED_CERTIFICATE_COUNT 1U", observer)
        self.assertNotIn("pbns_tls_transport **result", source + header)
        self.assertNotIn("PBNS_TLS_UEFI_TRANSPORT *next", source)
        for forbidden in (
            "RngLib",
            "GetTime",
            "gRT->",
            "pico",
            "credentials.h",
            "tls_client.h",
        ):
            self.assertNotIn(forbidden, source + header + manifest + crt_source)

    def test_context_region_helper_declarations_and_build_policy(self) -> None:
        public_header = (LIBRARY_DIR / "PbnsTlsTransportLib.h").read_text(
            encoding="utf-8"
        )
        core_header = (
            LIBRARY_DIR / "PbnsTlsTransportContextRegionCore.h"
        ).read_text(encoding="utf-8")
        manifest = (LIBRARY_DIR / "PbnsTlsTransportLib.inf").read_text(
            encoding="utf-8"
        )
        cmake = (LIBRARY_DIR.parents[2] / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("EFI_STATUS EFIAPI PbnsTlsTransportContextRegion(", public_header)
        self.assertIn("PBNS_TLS_UEFI_TRANSPORT *Transport, pbns_view *Region", public_header)
        self.assertIn("pbns_tls_transport_context_region_core(", core_header)
        self.assertIn("PbnsTlsTransportContextRegionCore.c", manifest)
        self.assertIn("pbns-test-tls-context-region", cmake)
        self.assertIn("NAME tls-context-region", cmake)

    def test_probe_uses_local_lower_transport_and_exact_fixture_profile(self) -> None:
        source = (PROBE_DIR / "PbnsTlsProbe.c").read_text(encoding="utf-8")
        manifest = (PROBE_DIR / "PbnsTlsProbe.inf").read_text(encoding="utf-8")
        for required in (
            "PbnsTlsTransportCreate",
            "PbnsTlsTransportAsTransport",
            "PbnsTlsTransportDestroy",
            "192.168.1.180",
            "local_transport_ops",
            "probe_allocate_pool",
            "probe_free_pool",
            "PBNS_ERR_BUSY",
            "TPL_CALLBACK",
            "fail_free_call_count = 2U",
            "null_pin_config",
            "zero_pin_config",
            "PBNS UEFI TLS POOL PEAK",
            "PBNS UEFI TLS LINK PROBE PASS",
            "PBNS UEFI TLS LINK PROBE FAIL",
        ):
            self.assertIn(required, source)
        match = re.search(
            r"FIXTURE_SPKI_SHA256\[32\]\s*=\s*\{(.*?)\};", source, re.DOTALL
        )
        self.assertIsNotNone(match)
        assert match is not None
        actual_pin = bytes(
            int(token, 16)
            for token in re.findall(r"0x([0-9a-fA-F]{2})U", match.group(1))
        )
        expected_pin = bytes.fromhex(FIXTURE_PIN.read_text(encoding="ascii").strip())
        self.assertEqual(actual_pin, expected_pin)
        self.assertIn("PbnsTlsTransportLib", manifest)
        self.assertIn("-fstack-usage", manifest)
        for forbidden in (
            "PbnsUsb",
            "Protocol/Usb",
            "Protocol/Tcp",
            "LocateProtocol",
            "gRT->",
            "GetTime",
            "Print(L\"PBNS UEFI TLS LINK PROBE FAIL status=",
        ):
            self.assertNotIn(forbidden, source + manifest)

    def test_platform_registers_adapter_and_probe_dependencies(self) -> None:
        platform = (PBNS_ROOT / "PbnsPkg.dsc").read_text(encoding="utf-8")
        package = (PBNS_ROOT / "PbnsPkg.dec").read_text(encoding="utf-8")
        probe_manifest = (PROBE_DIR / "PbnsTlsProbe.inf").read_text(
            encoding="utf-8"
        )
        platform_manifest = (
            PBNS_ROOT / "uefi" / "Library" / "PbnsUefiPlatformLib" / "PbnsUefiPlatformLib.inf"
        ).read_text(encoding="utf-8")
        platform_source = (
            PBNS_ROOT / "uefi" / "Library" / "PbnsUefiPlatformLib" / "PbnsUefiPlatformLib.c"
        ).read_text(encoding="utf-8")
        portable_source = (PBNS_ROOT / "src" / "transport" / "tls_transport.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("PbnsTlsTransportLib|", platform)
        self.assertIn("PbnsTlsTransportLib|", package)
        self.assertIn("IntrinsicLib", platform_manifest)
        for removed in ("PBNS_UEFI_COMPAT_WEAK", "void *\nmemcpy", "void *\nmemmove"):
            self.assertNotIn(removed, platform_source)
        for required in (
            "PbnsTlsTransportLib",
            "PbnsIdentityLib",
            "PbnsUefiPlatformLib",
        ):
            self.assertIn(required, probe_manifest)
        self.assertIn("MBEDTLS_SSL_SESSION_TICKETS_DISABLED", portable_source)

    def test_hil_driver_names_feasibility_boundary_and_exact_profile(self) -> None:
        source = HIL_DRIVER.read_text(encoding="utf-8")
        for required in (
            "host-python-ssl-memorybio",
            "not-run",
            "TLSv1.2",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "pbns/1",
            "192.168.1.180",
            "SSLContext",
            "MemoryBIO",
            "SSLObject",
            "hmac.compare_digest",
            "SubjectAlternativeName",
            "SubjectPublicKeyInfo",
            "certificate.issuer != certificate.subject",
            "usage.value.key_cert_sign",
            "connection.settimeout(5.0)",
            "time.sleep(arguments.connect_delay)",
            "OP_NO_TICKET",
            "MAX_EMPTY_COMPLETIONS",
            "time.monotonic_ns",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "CERT_NONE  # trust",
            "check_hostname = False  # trust",
            "payload_capture",
            "tls_record_capture",
            "usbmon",
        ):
            self.assertNotIn(forbidden, source)

    def test_peer_certificate_requires_exact_ip_san_and_constant_time_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            subprocess.run(
                [
                    str(PBNS_ROOT / "integration" / "tls" / "make-test-pki.sh"),
                    str(output),
                    "192.168.1.180",
                ],
                check=True,
                capture_output=True,
            )
            certificate = ssl.PEM_cert_to_DER_cert(
                (output / "gateway-reissued-cert.pem").read_text(encoding="ascii")
            )
            der = certificate if isinstance(certificate, bytes) else bytes.fromhex(certificate)
            expected_pin = bytes.fromhex(FIXTURE_PIN.read_text(encoding="ascii").strip())
            self.hil.validate_peer_certificate(
                der, expected_san="192.168.1.180", expected_spki=expected_pin
            )
            with self.assertRaises(self.hil.TunnelError) as wrong_san:
                self.hil.validate_peer_certificate(
                    der, expected_san="192.168.1.181", expected_spki=expected_pin
                )
            self.assertEqual(wrong_san.exception.code, "wrong-san")
            with self.assertRaises(self.hil.TunnelError) as wrong_pin:
                self.hil.validate_peer_certificate(
                    der, expected_san="192.168.1.180", expected_spki=b"\x00" * 32
                )
            self.assertEqual(wrong_pin.exception.code, "wrong-spki")

    def test_negotiated_profile_rejects_version_cipher_and_alpn_mismatch(self) -> None:
        self.hil.validate_negotiated_profile(
            version="TLSv1.2",
            cipher="ECDHE-ECDSA-AES128-GCM-SHA256",
            alpn="pbns/1",
        )
        for values, code in (
            (("TLSv1.3", "ECDHE-ECDSA-AES128-GCM-SHA256", "pbns/1"), "wrong-version"),
            (("TLSv1.2", "ECDHE-ECDSA-CHACHA20-POLY1305", "pbns/1"), "wrong-cipher"),
            (("TLSv1.2", "ECDHE-ECDSA-AES128-GCM-SHA256", "http/1.1"), "wrong-alpn"),
        ):
            with self.subTest(code=code), self.assertRaises(self.hil.TunnelError) as error:
                self.hil.validate_negotiated_profile(
                    version=values[0], cipher=values[1], alpn=values[2]
                )
            self.assertEqual(error.exception.code, code)

    def test_handshake_transport_exhaustion_preserves_zero_progress(self) -> None:
        class EmptyStream:
            def write(self, data: bytes | memoryview) -> int:
                return len(data)

            def read(self, _size: int) -> bytes:
                return b""

            def flush(self) -> None:
                return None

        with self.assertRaises(self.hil.TunnelError) as error:
            self.hil.TlsSerialClient(
                EmptyStream(),
                expected_san="192.168.1.180",
                expected_spki=b"\x00" * 32,
                timeout_seconds=1,
            )
        self.assertEqual(error.exception.code, "zero-progress")

    def test_serial_read_size_uses_available_bytes_without_waiting_for_chunk(self) -> None:
        class SerialLike:
            def __init__(self, waiting: int) -> None:
                self.in_waiting = waiting

        self.assertEqual(self.hil.stream_read_size(SerialLike(0)), 1)
        self.assertEqual(self.hil.stream_read_size(SerialLike(37)), 37)
        self.assertEqual(
            self.hil.stream_read_size(SerialLike(self.hil.STREAM_CHUNK + 1)),
            self.hil.STREAM_CHUNK,
        )
        self.assertEqual(self.hil.stream_read_size(object()), self.hil.STREAM_CHUNK)

    def test_serial_completion_bounds_zero_progress_and_absolute_deadline(self) -> None:
        class ZeroWrite:
            def write(self, _data: bytes) -> int:
                return 0

            def read(self, _size: int) -> bytes:
                return b""

            def flush(self) -> None:
                return None

        with self.assertRaises(self.hil.TunnelError) as zero:
            self.hil.write_all(ZeroWrite(), b"ciphertext", deadline_ns=10**18)
        self.assertEqual(zero.exception.code, "zero-progress")

        ticks = iter((0, 2, 11, 12, 13, 14))
        with self.assertRaises(self.hil.TunnelError) as timeout:
            self.hil.read_some(
                ZeroWrite(),
                32,
                deadline_ns=10,
                monotonic_ns=lambda: next(ticks),
                max_empty_completions=100,
            )
        self.assertEqual(timeout.exception.code, "timeout")

    def test_diagnostic_clienthello_observer_is_bounded_and_wiped(self) -> None:
        observer = self.hil.ClientHelloObserver()
        self.assertFalse(observer.feed(memoryview(b"\x16\x03\x03\x00")))
        self.assertTrue(observer.feed(memoryview(b"\x04\x01\x00\x00\x00")))
        self.assertTrue(observer.seen)
        self.assertEqual(observer.buffer, bytearray())
        oversized = self.hil.ClientHelloObserver()
        with self.assertRaises(self.hil.TunnelError) as error:
            oversized.feed(memoryview(b"x" * 4097))
        self.assertEqual(error.exception.code, "tls-handshake")
        oversized.wipe()
        self.assertEqual(oversized.buffer, bytearray())

    def test_diagnostic_server_journals_only_bounded_milestones(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            output.chmod(0o700)
            subprocess.run(
                [
                    str(PBNS_ROOT / "integration" / "tls" / "make-test-pki.sh"),
                    str(output),
                    "192.168.1.180",
                ],
                check=True,
                capture_output=True,
            )
            journal_path = output / "events.jsonl"
            journal = self.hil.DiagnosticEventJournal(journal_path)
            journal.record(ready=True, accept_count=1)
            server_context = self.hil._diagnostic_server_context(
                output / "gateway-reissued-cert.pem",
                PBNS_ROOT / "tests" / "fixtures" / "keys" / "tls-gateway-test-key.pem",
            )
            client_context = self.hil.build_client_context()
            server_socket, client_socket = socket.socketpair()
            server_socket.settimeout(5.0)
            client_socket.settimeout(5.0)
            failures: list[BaseException] = []

            def run_server() -> None:
                try:
                    with server_socket:
                        self.hil._diagnostic_serve_connection(
                            server_socket,
                            server_context,
                            journal,
                            deadline_ns=time.monotonic_ns() + 5_000_000_000,
                        )
                except BaseException as error:
                    failures.append(error)

            thread = threading.Thread(target=run_server)
            thread.start()
            try:
                with client_socket:
                    with client_context.wrap_socket(
                        client_socket,
                        server_side=False,
                        server_hostname="192.168.1.180",
                    ) as tls_client:
                        observed = bytearray()
                        while len(observed) < self.hil.DIAGNOSTIC_APPLICATION_BYTES:
                            fragment = tls_client.recv(
                                self.hil.DIAGNOSTIC_APPLICATION_BYTES - len(observed)
                            )
                            self.assertTrue(fragment)
                            observed.extend(fragment)
                thread.join(timeout=5.0)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])
                self.assertEqual(
                    bytes(observed),
                    self.hil.deterministic_chunk(
                        0, self.hil.DIAGNOSTIC_APPLICATION_BYTES
                    ),
                )
                snapshot = journal.snapshot
                for name in (
                    "clienthello_seen",
                    "server_flight_sent",
                    "tls_established",
                    "application_complete",
                ):
                    self.assertIs(snapshot[name], True)
            finally:
                if thread.is_alive():
                    server_socket.close()
                    thread.join(timeout=1.0)
                journal.close()
            self.assertEqual(stat.S_IMODE(journal_path.stat().st_mode), 0o600)
            records = [
                json.loads(line)
                for line in journal_path.read_text(encoding="ascii").splitlines()
            ]
            self.assertGreaterEqual(len(records), 6)
            for record in records:
                self.assertEqual(set(record), self.hil.DIAGNOSTIC_EVENT_KEYS)
                self.assertIn(record["status"], ("passed", "failed", "not-run"))
                self.assertIn(record["error_code"], self.hil.DIAGNOSTIC_EVENT_ERRORS)
            encoded = journal_path.read_bytes()
            self.assertNotIn(self.hil.PATTERN, encoded)
            self.assertNotIn(b"192.168.1", encoded)

    def test_diagnostic_journal_serializes_concurrent_updates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            output.chmod(0o700)
            journal_path = output / "concurrent-events.jsonl"
            journal = self.hil.DiagnosticEventJournal(journal_path)
            failures: list[BaseException] = []
            barrier = threading.Barrier(9)

            def update() -> None:
                try:
                    barrier.wait()
                    journal.record(ready=True)
                except BaseException as error:
                    failures.append(error)

            threads = [threading.Thread(target=update) for _index in range(8)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=2.0)
            journal.close()
            self.assertEqual(failures, [])
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            records = [
                json.loads(line)
                for line in journal_path.read_text(encoding="ascii").splitlines()
            ]
            self.assertEqual(len(records), 9)
            self.assertTrue(all(set(record) == self.hil.DIAGNOSTIC_EVENT_KEYS for record in records))
            self.assertTrue(all(record["process_alive"] is True for record in records))

    def test_diagnostic_server_command_completes_one_loopback_handshake(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            output.chmod(0o700)
            subprocess.run(
                [
                    str(PBNS_ROOT / "integration" / "tls" / "make-test-pki.sh"),
                    str(output),
                    "192.168.1.180",
                ],
                check=True,
                capture_output=True,
            )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            journal = output / "command-events.jsonl"
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(HIL_DRIVER),
                    "diagnostic-server",
                    "--listen",
                    f"127.0.0.1:{port}",
                    "--certificate",
                    str(output / "gateway-reissued-cert.pem"),
                    "--private-key",
                    str(PBNS_ROOT / "tests" / "fixtures" / "keys" / "tls-gateway-test-key.pem"),
                    "--event-journal",
                    str(journal),
                    "--timeout",
                    "10",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(lambda: process.poll() is None and process.kill())
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if journal.exists() and '"ready":true' in journal.read_text(encoding="ascii"):
                    break
                if process.poll() is not None:
                    self.fail("diagnostic server exited before readiness")
                time.sleep(0.01)
            else:
                self.fail("diagnostic server did not become ready")
            context = self.hil.build_client_context()
            with socket.create_connection(("127.0.0.1", port), timeout=5.0) as connection:
                with context.wrap_socket(
                    connection,
                    server_hostname="192.168.1.180",
                ) as tls_client:
                    observed = bytearray()
                    while len(observed) < self.hil.DIAGNOSTIC_APPLICATION_BYTES:
                        fragment = tls_client.recv(
                            self.hil.DIAGNOSTIC_APPLICATION_BYTES - len(observed)
                        )
                        self.assertTrue(fragment)
                        observed.extend(fragment)
            stdout, stderr = process.communicate(timeout=5.0)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn("RAW TUNNEL DIAGNOSTIC SERVER PASS", stdout)
            self.assertEqual(
                bytes(observed),
                self.hil.deterministic_chunk(0, self.hil.DIAGNOSTIC_APPLICATION_BYTES),
            )
            records = [
                json.loads(line)
                for line in journal.read_text(encoding="ascii").splitlines()
            ]
            self.assertEqual(records[-1]["status"], "passed")
            self.assertIs(records[-1]["process_alive"], False)
            self.assertEqual(records[-1]["accept_count"], 1)
            self.assertIs(records[-1]["application_complete"], True)

    def test_diagnostic_server_absolute_deadline_rejects_trickle_peer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            output.chmod(0o700)
            subprocess.run(
                [
                    str(PBNS_ROOT / "integration" / "tls" / "make-test-pki.sh"),
                    str(output),
                    "192.168.1.180",
                ],
                check=True,
                capture_output=True,
            )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            journal = output / "trickle-events.jsonl"
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(HIL_DRIVER),
                    "diagnostic-server",
                    "--listen",
                    f"127.0.0.1:{port}",
                    "--certificate",
                    str(output / "gateway-reissued-cert.pem"),
                    "--private-key",
                    str(PBNS_ROOT / "tests" / "fixtures" / "keys" / "tls-gateway-test-key.pem"),
                    "--event-journal",
                    str(journal),
                    "--timeout",
                    "0.3",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            def stop_process() -> None:
                if process.poll() is None:
                    process.kill()

            self.addCleanup(stop_process)
            readiness_deadline = time.monotonic() + 2.0
            while time.monotonic() < readiness_deadline:
                if journal.exists() and '"ready":true' in journal.read_text(encoding="ascii"):
                    break
                if process.poll() is not None:
                    self.fail("diagnostic server exited before trickle connection")
                time.sleep(0.01)
            else:
                self.fail("diagnostic server did not become ready")
            started = time.monotonic()
            with socket.create_connection(("127.0.0.1", port), timeout=1.0) as connection:
                connection.sendall(b"\x16\x03\x03\x0f\xfb")
                while process.poll() is None:
                    try:
                        connection.sendall(b"\x00")
                    except OSError:
                        break
                    time.sleep(0.03)
            _stdout, _stderr = process.communicate(timeout=2.0)
            self.assertNotEqual(process.returncode, 0)
            self.assertLess(time.monotonic() - started, 1.0)
            records = [
                json.loads(line)
                for line in journal.read_text(encoding="ascii").splitlines()
            ]
            self.assertEqual(records[-1]["status"], "failed")
            self.assertEqual(records[-1]["error_code"], "timeout")
            self.assertIs(records[-1]["process_alive"], False)

    def test_memory_bio_client_drives_short_tls_io_without_plaintext_fallback(self) -> None:
        class ShortSocketStream:
            def __init__(self, connection: socket.socket) -> None:
                self.connection = connection

            def write(self, data: bytes | memoryview) -> int:
                return self.connection.send(bytes(data[:7]))

            def read(self, size: int) -> bytes:
                return self.connection.recv(min(size, 5))

            def flush(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            subprocess.run(
                [
                    str(PBNS_ROOT / "integration" / "tls" / "make-test-pki.sh"),
                    str(output),
                    "192.168.1.180",
                ],
                check=True,
                capture_output=True,
            )
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context.maximum_version = ssl.TLSVersion.TLSv1_2
            server_context.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
            server_context.set_alpn_protocols(["pbns/1"])
            server_context.load_cert_chain(
                output / "gateway-reissued-cert.pem",
                PBNS_ROOT / "tests" / "fixtures" / "keys" / "tls-gateway-test-key.pem",
            )
            client_socket, server_socket = socket.socketpair()
            client_socket.settimeout(2)
            server_socket.settimeout(2)
            expected = b"short-memory-bio" * 64
            failures: list[BaseException] = []

            def serve() -> None:
                try:
                    with server_socket:
                        with server_context.wrap_socket(
                            server_socket, server_side=True
                        ) as connection:
                            received = bytearray()
                            while len(received) < len(expected):
                                fragment = connection.recv(len(expected) - len(received))
                                if not fragment:
                                    raise AssertionError("truncated client stream")
                                received.extend(fragment)
                            connection.sendall(received)
                except BaseException as error:
                    failures.append(error)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                canary = self.hil.CompletionCanary()
                client = self.hil.TlsSerialClient(
                    ShortSocketStream(client_socket),
                    expected_san="192.168.1.180",
                    expected_spki=bytes.fromhex(
                        FIXTURE_PIN.read_text(encoding="ascii").strip()
                    ),
                    timeout_seconds=2,
                    canary=canary,
                )
                client.write(expected)
                self.assertEqual(client.read_exact(len(expected)), expected)
                self.assertGreater(canary.metadata()["completion_count"], 10)
            finally:
                client_socket.close()
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])

    def test_purpose_built_server_streams_independent_directions(self) -> None:
        class SocketStream:
            def __init__(self, connection: socket.socket) -> None:
                self.connection = connection

            def write(self, data: bytes | memoryview) -> int:
                return self.connection.send(data)

            def read(self, size: int) -> bytes:
                return self.connection.recv(size)

            def flush(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            subprocess.run(
                [
                    str(PBNS_ROOT / "integration" / "tls" / "make-test-pki.sh"),
                    str(state / "pki"),
                    "192.168.1.180",
                ],
                check=True,
                capture_output=True,
            )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            ready = state / "ready"
            artifact = (
                PBNS_ROOT
                / "integration"
                / "state"
                / "task14c-signed-final-20260810T022831Z.DBx3aC"
                / "cases"
                / "signed-trusted"
                / "repository"
                / "artifacts"
                / "d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3"
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(HIL_DRIVER),
                    "server",
                    "--listen",
                    f"127.0.0.1:{port}",
                    "--certificate",
                    str(state / "pki" / "gateway-reissued-cert.pem"),
                    "--private-key",
                    str(PBNS_ROOT / "tests" / "fixtures" / "keys" / "tls-gateway-test-key.pem"),
                    "--artifact",
                    str(artifact),
                    "--ready-file",
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            def cleanup() -> None:
                if process.poll() is None:
                    process.terminate()
                process.communicate(timeout=3)

            self.addCleanup(cleanup)
            for _attempt in range(100):
                if ready.is_file():
                    break
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    self.fail(f"server stopped: {stdout} {stderr}")
                time.sleep(0.01)
            else:
                self.fail("server readiness timed out")
            pin = bytes.fromhex(FIXTURE_PIN.read_text(encoding="ascii").strip())
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                client = self.hil.TlsSerialClient(
                    SocketStream(connection),
                    expected_san="192.168.1.180",
                    expected_spki=pin,
                    timeout_seconds=3,
                )
                observed, digest, _duration = self.hil.run_upstream(client, 65536)
                self.assertEqual(observed, 65536)
                self.assertEqual(digest, self.hil.deterministic_digest(65536))
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                client = self.hil.TlsSerialClient(
                    SocketStream(connection),
                    expected_san="192.168.1.180",
                    expected_spki=pin,
                    timeout_seconds=3,
                )
                expected = self.hil.deterministic_digest(65536)
                observed, digest, _duration = self.hil.run_downstream(
                    client,
                    mode="downstream",
                    total_bytes=65536,
                    expected_sha256=expected,
                )
                self.assertEqual(observed, 65536)
                self.assertEqual(digest, expected)

    def test_bound_serial_uses_full_trial_deadline_for_io_timeouts(self) -> None:
        class Serial:
            closed = False

            def fileno(self) -> int:
                return 7

            def close(self) -> None:
                self.closed = True

        serial_port = Serial()
        received: dict[str, object] = {}
        identity = {"device": "1-3", "cdc0_interface": "00", "cdc0_dev": "1:3"}

        def serial_factory(**kwargs: object) -> Serial:
            received.update(kwargs)
            return serial_port

        opened = self.hil._open_serial(
            pathlib.Path("/dev/ttyACM0"),
            120.0,
            identity_verifier=lambda: identity,
            serial_factory=serial_factory,
            fstat=lambda _fd: SimpleNamespace(
                st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 3)
            ),
        )
        self.assertIs(opened, serial_port)
        self.assertEqual(received["timeout"], 120.0)
        self.assertEqual(received["write_timeout"], 120.0)
        opened.close()
        self.assertTrue(serial_port.closed)

    def test_completion_capacity_covers_full_artifact_usb_packets(self) -> None:
        artifact_packets = (self.hil.ARTIFACT_BYTES + 63) // 64
        self.assertGreaterEqual(
            self.hil.MAX_SERIAL_COMPLETIONS, artifact_packets + 4096
        )
        self.assertLessEqual(self.hil.MAX_SERIAL_COMPLETIONS, 1 << 19)

    def test_empty_completion_at_absolute_deadline_is_timeout(self) -> None:
        class EmptyStream:
            def read(self, _size: int) -> bytes:
                return b""

        ticks = iter((0, 0, 10))
        with self.assertRaises(self.hil.TunnelError) as error:
            self.hil.read_some(
                EmptyStream(),
                16,
                deadline_ns=10,
                monotonic_ns=lambda: next(ticks),
            )
        self.assertEqual(error.exception.code, "timeout")

    def test_true_empty_completions_keep_the_four_zlp_bound(self) -> None:
        class EmptyStream:
            def __init__(self) -> None:
                self.read_calls = 0

            def read(self, _size: int) -> bytes:
                self.read_calls += 1
                return b""

        stream = EmptyStream()
        canary = self.hil.CompletionCanary()
        with self.assertRaises(self.hil.TunnelError) as error:
            self.hil.read_some(
                stream,
                16,
                deadline_ns=10,
                canary=canary,
                monotonic_ns=lambda: 0,
            )
        self.assertEqual(error.exception.code, "zero-progress")
        self.assertEqual(stream.read_calls, self.hil.MAX_EMPTY_COMPLETIONS + 1)
        self.assertEqual(
            canary.metadata()["completion_count"], self.hil.MAX_EMPTY_COMPLETIONS + 1
        )
        self.assertEqual(
            canary.metadata()["completion_status_count"],
            self.hil.MAX_EMPTY_COMPLETIONS + 1,
        )

    def test_bound_serial_revalidates_after_open_and_rejects_swap(self) -> None:
        class Serial:
            def fileno(self) -> int:
                return 7
            def close(self) -> None:
                self.closed = True
        serial_port = Serial()
        identities = iter((
            {"device": "1-3", "cdc0_interface": "00", "cdc0_dev": "1:3"},
            {"device": "1-4", "cdc0_interface": "00", "cdc0_dev": "1:3"},
        ))
        with self.assertRaises(self.hil.TunnelError):
            self.hil._open_serial(
                pathlib.Path('/dev/ttyACM0'), 1,
                identity_verifier=lambda: next(identities),
                serial_factory=lambda **_kwargs: serial_port,
                fstat=lambda _fd: SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 3)),
            )
        self.assertTrue(serial_port.closed)

    def test_wrong_cipher_requires_fresh_synchronized_exact_server_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            proof = root / "proof"
            proof.write_text("wrong-cipher:no-shared-cipher\n", encoding="ascii")
            proof.chmod(0o600)
            with self.assertRaises(self.hil.TunnelError):
                self.hil.prepare_cipher_proof(proof)
            proof.unlink()

            expectation = self.hil.prepare_cipher_proof(proof)
            try:
                publisher = threading.Thread(
                    target=lambda: (time.sleep(0.05), self.hil._publish_cipher_proof(proof))
                )
                publisher.start()
                self.assertEqual(
                    self.hil.classify_expected_rejection(
                        self.hil.TunnelError(
                            "tls-handshake",
                            tls_reason="SSLV3_ALERT_HANDSHAKE_FAILURE",
                        ),
                        "wrong-cipher",
                        expectation,
                        deadline_ns=time.monotonic_ns() + 1_000_000_000,
                    ),
                    "wrong-cipher",
                )
                publisher.join(timeout=1)
                self.assertFalse(publisher.is_alive())
            finally:
                expectation.close()

    def test_cipher_proof_is_absent_until_staging_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proof = pathlib.Path(directory) / "proof"
            expectation = self.hil.prepare_cipher_proof(proof)
            staged = threading.Event()
            release = threading.Event()
            publication_errors: list[BaseException] = []
            classification: list[str] = []
            real_write = self.hil.os.write

            def paused_short_write(descriptor: int, data: bytes | memoryview) -> int:
                amount = real_write(descriptor, memoryview(data)[:1])
                staged.set()
                if not release.wait(timeout=1):
                    raise OSError("staging release timed out")
                return amount

            def publish() -> None:
                try:
                    self.hil._publish_cipher_proof(proof)
                except BaseException as error:
                    publication_errors.append(error)

            def classify() -> None:
                classification.append(
                    self.hil.classify_expected_rejection(
                        self.hil.TunnelError(
                            "tls-handshake",
                            tls_reason="SSLV3_ALERT_HANDSHAKE_FAILURE",
                        ),
                        "wrong-cipher",
                        expectation,
                        deadline_ns=time.monotonic_ns() + 1_000_000_000,
                    )
                )

            try:
                with mock.patch.object(
                    self.hil.os, "write", side_effect=paused_short_write
                ):
                    publisher = threading.Thread(target=publish)
                    publisher.start()
                    self.assertTrue(staged.wait(timeout=1))
                    classifier = threading.Thread(target=classify)
                    classifier.start()
                    time.sleep(0.05)
                    self.assertFalse(proof.exists())
                    self.assertTrue(classifier.is_alive())
                    release.set()
                    publisher.join(timeout=1)
                    classifier.join(timeout=1)
                self.assertFalse(publisher.is_alive())
                self.assertFalse(classifier.is_alive())
                self.assertEqual(publication_errors, [])
                self.assertEqual(classification, ["wrong-cipher"])
                self.assertEqual(
                    proof.read_text(encoding="ascii"),
                    "wrong-cipher:no-shared-cipher\n",
                )
                self.assertFalse((proof.parent / ".proof.staging").exists())
            finally:
                release.set()
                expectation.close()

    def test_cipher_proof_staging_failure_never_exposes_final_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proof = pathlib.Path(directory) / "proof"
            expectation = self.hil.prepare_cipher_proof(proof)
            try:
                with mock.patch.object(
                    self.hil.os, "write", side_effect=OSError("injected write")
                ):
                    with self.assertRaises(self.hil.TunnelError):
                        self.hil._publish_cipher_proof(proof)
                self.assertFalse(proof.exists())
                self.assertFalse((proof.parent / ".proof.staging").exists())
            finally:
                expectation.close()

    def test_cipher_proof_transaction_failures_are_not_acceptable(self) -> None:
        def exercise_failure(
            patch_factory: Callable[[types.ModuleType], object],
        ) -> None:
            with tempfile.TemporaryDirectory() as directory:
                proof = pathlib.Path(directory) / "proof"
                expectation = self.hil.prepare_cipher_proof(proof)
                try:
                    with patch_factory(self.hil):
                        with self.assertRaises(self.hil.TunnelError):
                            self.hil._publish_cipher_proof(proof)
                    self.assertFalse(proof.exists())
                    self.assertFalse(self.hil._read_cipher_proof(expectation))
                finally:
                    expectation.close()

        real_fsync = self.hil.os.fsync
        real_close = self.hil.os.close
        fsync_calls = 0
        close_calls = 0

        def fail_file_fsync(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 1:
                raise OSError("injected file fsync")
            real_fsync(descriptor)

        exercise_failure(
            lambda module: mock.patch.object(
                module.os, "fsync", side_effect=fail_file_fsync
            )
        )

        def fail_staging_close(descriptor: int) -> None:
            nonlocal close_calls
            close_calls += 1
            real_close(descriptor)
            if close_calls == 1:
                raise OSError("injected staging close")

        exercise_failure(
            lambda module: mock.patch.object(
                module.os, "close", side_effect=fail_staging_close
            )
        )
        exercise_failure(
            lambda module: mock.patch.object(
                module.os, "link", side_effect=OSError("injected link")
            )
        )

        fsync_calls = 0

        def fail_publish_fsync(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise OSError("injected directory fsync")
            real_fsync(descriptor)

        exercise_failure(
            lambda module: mock.patch.object(
                module.os, "fsync", side_effect=fail_publish_fsync
            )
        )

        fsync_calls = 0

        def fail_cleanup_fsync(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 3:
                raise OSError("injected cleanup fsync")
            real_fsync(descriptor)

        exercise_failure(
            lambda module: mock.patch.object(
                module.os, "fsync", side_effect=fail_cleanup_fsync
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            proof = pathlib.Path(directory) / "proof"
            expectation = self.hil.prepare_cipher_proof(proof)
            real_unlink = self.hil.os.unlink
            unlink_calls = 0

            def fail_staging_cleanup(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> None:
                nonlocal unlink_calls
                unlink_calls += 1
                if unlink_calls == 1:
                    raise OSError("injected staging cleanup")
                real_unlink(path, dir_fd=dir_fd)

            try:
                with mock.patch.object(
                    self.hil.os, "unlink", side_effect=fail_staging_cleanup
                ):
                    with self.assertRaises(self.hil.TunnelError):
                        self.hil._publish_cipher_proof(proof)
                self.assertFalse(proof.exists())
                self.assertFalse(self.hil._read_cipher_proof(expectation))
            finally:
                expectation.close()

    def test_wrong_cipher_rejects_generic_or_missing_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            proof = root / "proof"
            expectation = self.hil.prepare_cipher_proof(proof)
            try:
                self.hil._publish_cipher_proof(proof)
                with self.assertRaises(self.hil.TunnelError) as generic:
                    self.hil.classify_expected_rejection(
                        self.hil.TunnelError("tls-handshake"),
                        "wrong-cipher",
                        expectation,
                        deadline_ns=time.monotonic_ns() + 1_000_000_000,
                    )
                self.assertEqual(generic.exception.code, "tls-handshake")
            finally:
                expectation.close()

        with tempfile.TemporaryDirectory() as directory:
            proof = pathlib.Path(directory) / "proof"
            expectation = self.hil.prepare_cipher_proof(proof)
            try:
                with self.assertRaises(self.hil.TunnelError) as absent:
                    self.hil.classify_expected_rejection(
                        self.hil.TunnelError(
                            "tls-handshake",
                            tls_reason="SSLV3_ALERT_HANDSHAKE_FAILURE",
                        ),
                        "wrong-cipher",
                        expectation,
                        deadline_ns=time.monotonic_ns() + 20_000_000,
                    )
                self.assertEqual(absent.exception.code, "timeout")
            finally:
                expectation.close()

    def test_wrong_cipher_server_emits_exact_no_shared_cipher_proof(self) -> None:
        class SocketStream:
            def __init__(self, connection: socket.socket) -> None:
                self.connection = connection

            def write(self, data: bytes | memoryview) -> int:
                return self.connection.send(data)

            def read(self, size: int) -> bytes:
                return self.connection.recv(size)

            def flush(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            subprocess.run(
                [str(PBNS_ROOT / 'integration' / 'tls' / 'make-test-pki.sh'),
                 str(state / 'pki'), '192.168.1.180'],
                check=True, capture_output=True,
            )
            artifact = PBNS_ROOT / 'integration/state/task14c-signed-final-20260810T022831Z.DBx3aC/cases/signed-trusted/repository/artifacts/d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3'
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            ready, proof = state / 'ready', state / 'proof'
            expectation = self.hil.prepare_cipher_proof(proof)
            self.addCleanup(expectation.close)
            process = subprocess.Popen([
                sys.executable, str(HIL_DRIVER), 'server', '--listen', f'127.0.0.1:{port}',
                '--certificate', str(state / 'pki/gateway-reissued-cert.pem'),
                '--private-key', str(PBNS_ROOT / 'tests/fixtures/keys/tls-gateway-test-key.pem'),
                '--artifact', str(artifact), '--ready-file', str(ready),
                '--variant', 'wrong-cipher', '--cipher-proof', str(proof),
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            def cleanup_process() -> None:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)

            self.addCleanup(cleanup_process)
            for _ in range(200):
                if ready.exists(): break
                time.sleep(0.01)
            pin = bytes.fromhex(FIXTURE_PIN.read_text(encoding="ascii").strip())
            with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
                with self.assertRaises(self.hil.TunnelError) as client_error:
                    self.hil.TlsSerialClient(
                        SocketStream(connection),
                        expected_san="192.168.1.180",
                        expected_spki=pin,
                        timeout_seconds=2,
                    )
            self.assertEqual(client_error.exception.code, "tls-handshake")
            self.assertEqual(
                client_error.exception.tls_reason,
                "SSLV3_ALERT_HANDSHAKE_FAILURE",
            )
            for _ in range(200):
                if proof.exists(): break
                time.sleep(0.01)
            self.assertEqual(proof.read_text(encoding='ascii'), 'wrong-cipher:no-shared-cipher\n')
            _stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(
                self.hil.classify_expected_rejection(
                    client_error.exception,
                    "wrong-cipher",
                    expectation,
                    deadline_ns=time.monotonic_ns() + 1_000_000_000,
                ),
                "wrong-cipher",
            )
            with self.assertRaises(OSError):
                socket.create_connection(('127.0.0.1', port), timeout=0.2)
            with self.assertRaises(self.hil.TunnelError) as later:
                self.hil.classify_expected_rejection(
                    self.hil.TunnelError("io"),
                    "wrong-cipher",
                    expectation,
                    deadline_ns=time.monotonic_ns() + 1_000_000_000,
                )
            self.assertEqual(later.exception.code, "io")

    def test_initial_identity_failure_is_a_bounded_io_error(self) -> None:
        loopback = self.hil._load_loopback_module()

        def rejected_identity():
            raise loopback.LoopbackError("identity changed")

        with mock.patch.object(self.hil, "_load_loopback_module", return_value=loopback):
            with self.assertRaises(self.hil.TunnelError) as error:
                self.hil._open_serial(
                    pathlib.Path("/dev/ttyACM0"),
                    1,
                    identity_verifier=rejected_identity,
                    serial_factory=lambda **_kwargs: self.fail("serial must not open"),
                )
        self.assertEqual(error.exception.code, "io")

    def test_partial_downstream_disconnect_is_classified_as_truncation(self) -> None:
        class PartialClient:
            def __init__(self) -> None:
                self.sent = False

            def write(self, _data: bytes) -> None:
                return None

            def read(self, _maximum: int) -> bytes:
                if not self.sent:
                    self.sent = True
                    return b"partial"
                raise self_error("zero-progress")

        self_error = self.hil.TunnelError
        with self.assertRaises(self.hil.TunnelError) as error:
            self.hil.run_downstream(
                PartialClient(),
                mode="downstream",
                total_bytes=32,
                expected_sha256=hashlib.sha256(b"x" * 32).hexdigest(),
            )
        self.assertEqual(error.exception.code, "truncated")

    def test_digest_and_count_validation_fails_closed(self) -> None:
        expected = hashlib.sha256(b"artifact").hexdigest()
        self.hil.validate_stream_result(
            expected_bytes=8,
            observed_bytes=8,
            expected_sha256=expected,
            observed_sha256=expected,
        )
        for count, digest, code in (
            (7, expected, "byte-count"),
            (8, "0" * 64, "digest-mismatch"),
        ):
            with self.subTest(code=code), self.assertRaises(self.hil.TunnelError) as error:
                self.hil.validate_stream_result(
                    expected_bytes=8,
                    observed_bytes=count,
                    expected_sha256=expected,
                    observed_sha256=digest,
                )
            self.assertEqual(error.exception.code, code)


if __name__ == "__main__":
    unittest.main()
