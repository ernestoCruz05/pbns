import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import struct
import subprocess
import tempfile
import time
import types
import unittest
from types import SimpleNamespace
from typing import cast
from unittest import mock


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER = PBNS_ROOT / "integration" / "hil" / "raw-tunnel-diagnostic.py"
RUNNER = PBNS_ROOT / "integration" / "hil" / "raw-tunnel-diagnostic.sh"


def load_module() -> types.ModuleType:
    specification = importlib.util.spec_from_file_location("raw_tunnel_diagnostic", DRIVER)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RAW = load_module()
LOCK_RECORD = json.loads(
    (PBNS_ROOT / "integration" / "hil" / "raw-tunnel-diagnostic-lock.json").read_text(
        encoding="ascii"
    )
)


def event(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": RAW.EVENT_SCHEMA,
        "status": "failed",
        "error_code": "io",
        "ready": True,
        "process_alive": False,
        "accept_count": 1,
        "clienthello_seen": True,
        "tls_established": False,
        "server_flight_sent": True,
        "application_complete": False,
        "duration_ns": 1,
    }
    value.update(changes)
    return value


def diagnostic_record() -> dict[str, object]:
    locked = LOCK_RECORD["diagnostic"]
    return {
        "schema": RAW.SCHEMA,
        "status": "passed",
        "error_code": "none",
        "driver": RAW.DRIVER,
        "uefi_execution": RAW.UEFI_EXECUTION,
        "duration_ns": 1,
        "usb_vendor": RAW.DIAGNOSTIC_VENDOR,
        "usb_product_id": RAW.DIAGNOSTIC_PRODUCT_ID,
        "usb_product": RAW.DIAGNOSTIC_PRODUCT,
        "usb_serial": RAW.SERIAL,
        "usb_bcd_initial": RAW.DIAGNOSTIC_AWAITING_BCD,
        "usb_bcd_terminal": "9298",
        "usb_speed": RAW.USB_SPEED,
        "cdc_interface": RAW.CDC_INTERFACE,
        "pico_result": "complete",
        "diagnostic_uf2_sha256": locked["sha256"],
        "diagnostic_uf2_size": locked["size"],
        "client_status": "passed",
        "server_status": "passed",
        "server_error_code": "none",
        "application_octets_expected": RAW.APPLICATION_OCTETS,
        "application_octets_observed": RAW.APPLICATION_OCTETS,
        "application_sha256_expected": RAW.APPLICATION_SHA256,
        "application_sha256_observed": RAW.APPLICATION_SHA256,
        "accept_count": 1,
        "clienthello_seen": True,
        "tls_established": True,
        "server_flight_sent": True,
        "application_complete": True,
    }


def write_uf2(path: pathlib.Path, target: int, payload: bytes) -> None:
    block = bytearray(512)
    struct.pack_into(
        "<8I",
        block,
        0,
        0x0A324655,
        0x9E5D5157,
        0,
        target,
        len(payload),
        0,
        1,
        0,
    )
    block[32 : 32 + len(payload)] = payload
    struct.pack_into("<I", block, 508, 0x0AB16F30)
    path.write_bytes(block)


def rollback_record() -> dict[str, object]:
    return {
        "schema": RAW.ROLLBACK_SCHEMA,
        "status": "passed",
        "error_code": "none",
        "duration_ns": 1,
        "usb_vendor": RAW.DIAGNOSTIC_VENDOR,
        "usb_product_id": RAW.PRODUCTION_PRODUCT_ID,
        "usb_product": RAW.PRODUCTION_PRODUCT,
        "usb_serial": RAW.SERIAL,
        "usb_bcd_device": RAW.PRODUCTION_BCD,
        "usb_speed": RAW.USB_SPEED,
        "cdc0_interface": "00",
        "cdc1_interface": "02",
        "stage6_sha256": RAW.STAGE6_SHA256,
        "stage6_size": RAW.STAGE6_SIZE,
        "stage6_target_start": RAW.STAGE6_TARGET_START,
        "stage6_target_end": RAW.STAGE6_TARGET_END,
        "picotool_sha256": RAW.PICOTOOL_SHA256,
    }


class RawTunnelDiagnosticTests(unittest.TestCase):
    def private_root(self) -> tuple[tempfile.TemporaryDirectory[str], pathlib.Path]:
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        root.chmod(0o700)
        return temporary, root

    def test_cross_layer_decision_table(self) -> None:
        cases = (
            ("9204", event(accept_count=0, clienthello_seen=False, server_flight_sent=False), "failed", "credential-wifi-boundary"),
            ("9207", event(accept_count=0, clienthello_seen=False, server_flight_sent=False), "failed", "endpoint-boundary"),
            ("9208", event(clienthello_seen=False, server_flight_sent=False), "failed", "cdc-to-tcp-boundary"),
            ("9211", event(), "failed", "tcp-receive-boundary"),
            ("9212", event(), "failed", "cdc-enqueue-boundary"),
            ("9213", event(), "failed", "cdc-flush-boundary"),
            ("9215", event(), "failed", "usb-transfer-boundary"),
            ("9214", event(), "failed", "usb-downstream-boundary"),
            ("9298", event(status="passed", error_code="none", tls_established=True, application_complete=True), "passed", "none"),
        )
        for pico, server, client, expected in cases:
            with self.subTest(pico=pico):
                self.assertEqual(RAW.classify_boundary(pico, server, client)[1], expected)
        self.assertEqual(RAW.classify_boundary("9299", event(), "failed"), ("failed", "internal"))
        inconsistent = event(accept_count=0, clienthello_seen=True)
        self.assertEqual(RAW.classify_boundary("9208", inconsistent, "failed"), ("failed", "internal"))
        passed_server = event(
            status="passed",
            error_code="none",
            tls_established=True,
            application_complete=True,
        )
        self.assertEqual(
            RAW.classify_boundary("9201", passed_server, "failed"),
            ("failed", "internal"),
        )
        self.assertEqual(
            RAW.classify_boundary(
                "9212",
                event(accept_count=0, clienthello_seen=False, server_flight_sent=False),
                "failed",
            ),
            ("failed", "internal"),
        )

    def test_diagnostic_identity_requires_one_cdc_and_exact_terminal_profile(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        sysfs = root / "usb"
        tty = root / "tty"
        device = sysfs / "1-3"
        interface = sysfs / "1-3:1.0"
        terminal = tty / "ttyACM0"
        for directory in (device, interface, terminal):
            directory.mkdir(parents=True, exist_ok=True)
        values = {
            "idVendor": RAW.DIAGNOSTIC_VENDOR,
            "idProduct": RAW.DIAGNOSTIC_PRODUCT_ID,
            "serial": RAW.SERIAL,
            "product": RAW.DIAGNOSTIC_PRODUCT,
            "speed": RAW.USB_SPEED,
            "bcdDevice": RAW.DIAGNOSTIC_AWAITING_BCD,
        }
        for name, value in values.items():
            (device / name).write_text(value + "\n", encoding="ascii")
        (interface / "bInterfaceNumber").write_text("00\n", encoding="ascii")
        (terminal / "dev").write_text("166:0\n", encoding="ascii")
        (terminal / "device").symlink_to(interface)
        identity = RAW.diagnostic_identity(sysfs, tty)
        self.assertEqual(identity["bcd"], RAW.DIAGNOSTIC_AWAITING_BCD)
        (device / "bcdDevice").write_text("9211\n", encoding="ascii")
        terminal_identity = RAW.diagnostic_identity(sysfs, tty, terminal_bcd=True)
        self.assertEqual(terminal_identity["bcd"], "9211")
        second = tty / "ttyACM1"
        second.mkdir()
        (second / "device").symlink_to(interface)
        with self.assertRaises(RAW.DiagnosticError):
            RAW.diagnostic_identity(sysfs, tty, terminal_bcd=True)

    def test_run_creation_is_exclusive_private_and_rejects_symlink_root(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        run = RAW.create_run_directory(root, "20260811T150000Z")
        self.assertEqual(run.name, "20260811T150000Z-raw-tunnel-diagnostic")
        self.assertEqual(stat.S_IMODE(run.stat().st_mode), 0o700)
        with self.assertRaises(RAW.DiagnosticError):
            RAW.create_run_directory(root, "20260811T150000Z")
        link = root.parent / f"{root.name}-link"
        link.symlink_to(root, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(RAW.DiagnosticError):
            RAW.create_run_directory(link, "20260811T150001Z")

    def test_publication_is_exclusive_synchronized_and_final_schema_exact(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        run = RAW.create_run_directory(root, "20260811T150002Z")
        RAW._publish_json(run, "diagnostic.json", diagnostic_record())
        self.assertEqual(stat.S_IMODE((run / "diagnostic.json").stat().st_mode), 0o600)
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_evidence(run)
        RAW._publish_json(run, "rollback.json", rollback_record())
        diagnostic, rollback = RAW.validate_evidence(run)
        self.assertEqual(set(diagnostic), RAW.DIAGNOSTIC_KEYS)
        self.assertEqual(set(rollback), RAW.ROLLBACK_KEYS)
        self.assertEqual(set(path.name for path in run.iterdir()), {"diagnostic.json", "rollback.json"})
        with self.assertRaises(RAW.DiagnosticError):
            RAW._publish_json(run, "diagnostic.json", diagnostic_record())

    def test_retained_validation_rejects_unlocked_pass_and_contradictory_failure(self) -> None:
        unlocked = diagnostic_record()
        unlocked["diagnostic_uf2_sha256"] = "1" * 64
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_diagnostic(unlocked)

        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        run = RAW.create_run_directory(root, "20260811T150007Z")
        RAW._publish_json(run, "diagnostic.json", unlocked)
        RAW._publish_json(run, "rollback.json", rollback_record())
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_evidence(run)

        contradictory = diagnostic_record()
        contradictory.update(
            {
                "status": "failed",
                "error_code": "credential-wifi-boundary",
                "usb_bcd_terminal": "9201",
                "pico_result": "credential-failure",
                "client_status": "failed",
            }
        )
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_diagnostic(contradictory)
        contradictory["error_code"] = "internal"
        RAW.validate_diagnostic(contradictory)

        ambiguous = diagnostic_record()
        ambiguous.update(
            {
                "status": "failed",
                "error_code": "credential-wifi-boundary",
                "usb_bcd_terminal": "9201",
                "pico_result": "credential-failure",
                "client_status": "failed",
                "server_status": "failed",
                "server_error_code": "internal",
                "accept_count": 0,
                "clienthello_seen": False,
                "tls_established": False,
                "server_flight_sent": False,
                "application_complete": False,
            }
        )
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_diagnostic(ambiguous)
        ambiguous_run = RAW.create_run_directory(root, "20260811T150010Z")
        RAW._publish_json(ambiguous_run, "diagnostic.json", ambiguous)
        RAW._publish_json(ambiguous_run, "rollback.json", rollback_record())
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_evidence(ambiguous_run)
        ambiguous["error_code"] = "internal"
        RAW.validate_diagnostic(ambiguous)

        impossible_tls_phase = diagnostic_record()
        impossible_tls_phase.update(
            {
                "status": "failed",
                "error_code": "tls-application",
                "client_status": "failed",
                "server_status": "failed",
                "server_error_code": "tls-handshake",
                "application_complete": False,
            }
        )
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_diagnostic(impossible_tls_phase)

        profile_boundary = diagnostic_record()
        profile_boundary.update(
            {
                "status": "failed",
                "error_code": "tcp-receive-boundary",
                "usb_bcd_terminal": "9211",
                "pico_result": "no-tcp-rx",
                "client_status": "failed",
                "server_status": "failed",
                "server_error_code": "tls-profile",
                "tls_established": False,
                "application_complete": False,
            }
        )
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_diagnostic(profile_boundary)
        profile_run = RAW.create_run_directory(root, "20260811T150011Z")
        RAW._publish_json(profile_run, "diagnostic.json", profile_boundary)
        RAW._publish_json(profile_run, "rollback.json", rollback_record())
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_evidence(profile_run)

    def test_directory_replacement_cannot_substitute_retained_evidence(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        run = RAW.create_run_directory(root, "20260811T150008Z")
        replacement = RAW.create_run_directory(root, "20260811T150009Z")
        for directory in (run, replacement):
            RAW._publish_json(directory, "diagnostic.json", diagnostic_record())
            RAW._publish_json(directory, "rollback.json", rollback_record())
        moved = root / "moved-original"
        listdir = os.listdir

        def replace_after_list(descriptor: int) -> list[str]:
            names = listdir(descriptor)
            run.rename(moved)
            replacement.rename(run)
            return names

        with (
            mock.patch.object(RAW.os, "listdir", side_effect=replace_after_list),
            self.assertRaises(RAW.DiagnosticError),
        ):
            RAW.validate_evidence(run)

    def test_failed_publication_is_quarantined(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        run = RAW.create_run_directory(root, "20260811T150004Z")
        stage = run / ".diagnostic.json.stage"
        stage.write_text("occupied\n", encoding="ascii")
        stage.chmod(0o600)
        with self.assertRaises(RAW.DiagnosticError):
            RAW._publish_json(run, "diagnostic.json", diagnostic_record())
        marker = run / ".run.invalid"
        self.assertTrue(marker.is_file())
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_evidence(run)

    def test_validation_rejects_extra_symlink_mode_and_unsafe_values(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        run = RAW.create_run_directory(root, "20260811T150003Z")
        RAW._publish_json(run, "diagnostic.json", diagnostic_record())
        RAW._publish_json(run, "rollback.json", rollback_record())
        extra = run / "capture.bin"
        extra.write_bytes(b"x")
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_evidence(run)
        extra.unlink()
        (run / "diagnostic.json").chmod(0o644)
        with self.assertRaises(RAW.DiagnosticError):
            RAW.validate_evidence(run)
        unsafe = diagnostic_record()
        unsafe["payload_capture"] = b"secret"
        with self.assertRaises(RAW.DiagnosticError):
            RAW._require_safe_object(unsafe)
        for forbidden in ("/dev/ttyACM0", "relative/capture.json", "10.2.3.4"):
            unsafe = diagnostic_record()
            unsafe["usb_product"] = forbidden
            with self.subTest(forbidden=forbidden), self.assertRaises(RAW.DiagnosticError):
                RAW._require_safe_object(unsafe)

    def test_event_journal_requires_exact_monotonic_payload_free_records(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        journal = root / "events.jsonl"
        records = [
            event(status="not-run", error_code="none", ready=False, process_alive=True, accept_count=0, clienthello_seen=False, server_flight_sent=False),
            event(status="passed", error_code="none", tls_established=True, application_complete=True),
        ]
        journal.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="ascii")
        journal.chmod(0o600)
        self.assertEqual(RAW.read_event_journal(journal), records[-1])
        regressed = dict(records[-1])
        regressed["clienthello_seen"] = False
        records.append(regressed)
        journal.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="ascii")
        with self.assertRaises(RAW.DiagnosticError):
            RAW.read_event_journal(journal)

    def test_client_success_and_failure_publish_exact_bounded_state(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        descriptor = os.open("/dev/null", os.O_RDWR)
        device = os.fstat(descriptor).st_rdev
        os.close(descriptor)
        device_number = f"{os.major(device)}:{os.minor(device)}"
        tls_source = RAW._load_module("pbns_test_tls_source", "uefi-tls-tunnel.py")
        payload = cast(
            bytes, tls_source.deterministic_chunk(0, RAW.APPLICATION_OCTETS)
        )

        class FakeSerial:
            def __init__(self, **_keywords: object) -> None:
                self.descriptor = os.open("/dev/null", os.O_RDWR)
                self.timeout = 0.0
                self.write_timeout = 0.0

            def fileno(self) -> int:
                return self.descriptor

            def close(self) -> None:
                if self.descriptor >= 0:
                    os.close(self.descriptor)
                    self.descriptor = -1

            def __enter__(self) -> "FakeSerial":
                return self

            def __exit__(self, *_arguments: object) -> None:
                self.close()

        def identity(
            _sysfs: pathlib.Path,
            _tty: pathlib.Path,
            *,
            terminal_bcd: bool = False,
        ) -> dict[str, str]:
            return {
                "device": "test-device",
                "bcd": "9298" if terminal_bcd else RAW.DIAGNOSTIC_AWAITING_BCD,
                "dev": device_number,
                "interface": RAW.CDC_INTERFACE,
            }

        class SuccessfulTls:
            def __init__(self, *_arguments: object, **_keywords: object) -> None:
                pass

            def read_exact(self, amount: int) -> bytes:
                return payload[:amount]

        fake_module = SimpleNamespace(
            deterministic_chunk=lambda _offset, _amount: payload,
            load_pin=lambda _path: b"p" * 32,
            TlsSerialClient=SuccessfulTls,
        )
        arguments = SimpleNamespace(
            timeout=1.0,
            sysfs_root=root,
            tty_root=root,
            pin=root / "pin",
            expected_san="192.168.1.180",
            state_file=root / "client.json",
        )
        with (
            mock.patch.object(RAW, "diagnostic_identity", side_effect=identity),
            mock.patch.object(RAW, "_load_module", return_value=fake_module),
        ):
            state = RAW.run_client(arguments, serial_factory=FakeSerial)
        self.assertEqual(state["status"], "passed")
        self.assertEqual(state["application_octets_observed"], RAW.APPLICATION_OCTETS)
        self.assertEqual(state["application_sha256_observed"], RAW.APPLICATION_SHA256)
        RAW._validate_client_state(state)
        self.assertEqual(stat.S_IMODE(arguments.state_file.stat().st_mode), 0o600)
        for name, value in (
            ("application_octets_observed", RAW.APPLICATION_OCTETS - 1),
            ("application_sha256_observed", "0" * 64),
            ("duration_ns", 60_000_000_001),
        ):
            invalid = dict(state)
            invalid[name] = value
            with self.subTest(name=name), self.assertRaises(RAW.DiagnosticError):
                RAW._validate_client_state(invalid)

        class FailedTls:
            def __init__(self, *_arguments: object, **_keywords: object) -> None:
                raise OSError("transport failed")

        failed_module = SimpleNamespace(
            deterministic_chunk=lambda _offset, _amount: payload,
            load_pin=lambda _path: b"p" * 32,
            TlsSerialClient=FailedTls,
        )
        failed_arguments = SimpleNamespace(**vars(arguments))
        failed_arguments.state_file = root / "client-failed.json"

        def failed_identity(
            _sysfs: pathlib.Path,
            _tty: pathlib.Path,
            *,
            terminal_bcd: bool = False,
        ) -> dict[str, str]:
            value = identity(_sysfs, _tty, terminal_bcd=terminal_bcd)
            if terminal_bcd:
                value["bcd"] = "9208"
            return value

        with (
            mock.patch.object(RAW, "diagnostic_identity", side_effect=failed_identity),
            mock.patch.object(RAW, "_load_module", return_value=failed_module),
        ):
            failed = RAW.run_client(failed_arguments, serial_factory=FakeSerial)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["error_code"], "io")
        self.assertEqual(failed["application_octets_observed"], 0)
        self.assertIsNone(failed["application_sha256_observed"])
        RAW._validate_client_state(failed)

        class CodedFailureError(Exception):
            code = "truncated"

        class CodedFailedTls:
            def __init__(self, *_arguments: object, **_keywords: object) -> None:
                raise CodedFailureError()

        coded_module = SimpleNamespace(
            deterministic_chunk=lambda _offset, _amount: payload,
            load_pin=lambda _path: b"p" * 32,
            TlsSerialClient=CodedFailedTls,
        )
        coded_arguments = SimpleNamespace(**vars(arguments))
        coded_arguments.state_file = root / "client-coded-failure.json"
        with (
            mock.patch.object(RAW, "diagnostic_identity", side_effect=failed_identity),
            mock.patch.object(RAW, "_load_module", return_value=coded_module),
        ):
            coded = RAW.run_client(coded_arguments, serial_factory=FakeSerial)
        self.assertEqual(coded["error_code"], "truncated")
        RAW._validate_client_state(coded)

    def test_success_publication_binds_transfer_and_reviewed_artifact_lock(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        diagnostic = root / "diagnostic.uf2"
        rollback = root / "rollback.uf2"
        production = root / "production.uf2"
        picotool = root / "picotool"
        write_uf2(diagnostic, 0x10000000, b"diagnostic")
        write_uf2(rollback, 0x10000100, b"rollback")
        write_uf2(production, 0x10000200, b"production")
        picotool.write_bytes(b"reviewed-picotool")
        picotool.chmod(0o755)
        rollback_digest = hashlib.sha256(rollback.read_bytes()).hexdigest()
        production_digest = hashlib.sha256(production.read_bytes()).hexdigest()
        lock = root / "lock.json"
        client_state = root / "client.json"
        event_journal = root / "events.jsonl"
        client = {
            "status": "passed",
            "error_code": "none",
            "duration_ns": 1,
            "usb_bcd_initial": RAW.DIAGNOSTIC_AWAITING_BCD,
            "usb_bcd_terminal": "9298",
            "application_octets_observed": RAW.APPLICATION_OCTETS,
            "application_sha256_expected": RAW.APPLICATION_SHA256,
            "application_sha256_observed": RAW.APPLICATION_SHA256,
        }
        RAW._write_client_state(client_state, client)
        final_event = event(
            status="passed",
            error_code="none",
            tls_established=True,
            application_complete=True,
        )
        event_journal.write_text(json.dumps(final_event) + "\n", encoding="ascii")
        event_journal.chmod(0o600)
        with (
            mock.patch.object(RAW, "STAGE6_SHA256", rollback_digest),
            mock.patch.object(RAW, "STAGE6_SIZE", rollback.stat().st_size),
            mock.patch.object(RAW, "STAGE6_TARGET_START", 0x10000100),
            mock.patch.object(RAW, "STAGE6_TARGET_END", 0x10000108),
            mock.patch.object(RAW, "PRODUCTION_RAW_SHA256", production_digest),
            mock.patch.object(RAW, "PRODUCTION_RAW_SIZE", production.stat().st_size),
            mock.patch.object(RAW, "PRODUCTION_RAW_TARGET_START", 0x10000200),
            mock.patch.object(RAW, "PRODUCTION_RAW_TARGET_END", 0x1000020A),
            mock.patch.object(
                RAW,
                "PICOTOOL_SHA256",
                hashlib.sha256(picotool.read_bytes()).hexdigest(),
            ),
        ):
            RAW.write_lock(
                lock, RAW.lock_artifacts(diagnostic, rollback, production)
            )
            run = RAW.create_run_directory(root, "20260811T150005Z")
            record = RAW.publish_diagnostic(
                run,
                client_state,
                event_journal,
                diagnostic,
                lock,
                rollback,
                production,
            )
            self.assertEqual(record["status"], "passed")
            self.assertEqual(
                record["diagnostic_uf2_sha256"],
                hashlib.sha256(diagnostic.read_bytes()).hexdigest(),
            )
            self.assertEqual(record["application_octets_observed"], RAW.APPLICATION_OCTETS)
            self.assertEqual(record["application_sha256_observed"], RAW.APPLICATION_SHA256)
            RAW.verify_lock(lock, diagnostic, rollback, production, picotool)
            picotool.write_bytes(b"substituted-picotool")
            with self.assertRaises(RAW.DiagnosticError):
                RAW.verify_lock(lock, diagnostic, rollback, production, picotool)

            write_uf2(diagnostic, 0x10000000, b"changed")
            second = RAW.create_run_directory(root, "20260811T150006Z")
            with self.assertRaises(RAW.DiagnosticError):
                RAW.publish_diagnostic(
                    second,
                    client_state,
                    event_journal,
                    diagnostic,
                    lock,
                    rollback,
                    production,
                )
            self.assertEqual(list(second.iterdir()), [])

    def test_runner_cleanup_is_bounded_and_kills_tracked_child(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        pid_file = root / "child.pid"
        environment = dict(os.environ)
        environment["PBNS_CLEANUP_TEST_PID_FILE"] = str(pid_file)
        process = subprocess.Popen(
            [str(RUNNER), "--cleanup-self-test"],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        def stop_process() -> None:
            if process.poll() is None:
                process.kill()

        self.addCleanup(stop_process)
        deadline = time.monotonic() + 3.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(pid_file.exists())
        child = int(pid_file.read_text(encoding="ascii").strip())
        process.terminate()
        process.wait(timeout=8.0)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

    def test_runner_wait_timeout_is_bounded_and_cleans_child(self) -> None:
        started = time.monotonic()
        completed = subprocess.run(
            [str(RUNNER), "--wait-timeout-self-test"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("WAIT TIMEOUT PASS", completed.stdout)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_artifact_lock_publication_is_exclusive_and_descriptor_relative(self) -> None:
        temporary, root = self.private_root()
        self.addCleanup(temporary.cleanup)
        lock = root / "lock.json"
        record: dict[str, object] = {"schema": RAW.LOCK_SCHEMA}
        RAW.write_lock(lock, record)
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o644)
        self.assertEqual(json.loads(lock.read_text(encoding="ascii")), record)
        with self.assertRaises(RAW.DiagnosticError):
            RAW.write_lock(lock, record)
        link = root.parent / f"{root.name}-lock-link"
        link.symlink_to(root, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(RAW.DiagnosticError):
            RAW.write_lock(link / "other.json", record)

    def test_terminal_observation_covers_firmware_deadline(self) -> None:
        self.assertEqual(RAW.TERMINAL_OBSERVATION_NS, 35_000_000_000)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("wait_pid_bounded CLIENT_PID 1000", runner)
        self.assertNotIn("wait_pid_bounded CLIENT_PID 750", runner)

    def test_exact_command_surface_and_self_test(self) -> None:
        parser = RAW.build_parser()
        expected = {
            "self-test", "create-run", "client", "publish-diagnostic",
            "record-rollback", "validate-evidence", "lock-artifact", "verify-lock",
        }
        action = next(action for action in parser._actions if action.dest == "command")
        self.assertEqual(set(action.choices), expected)
        parsed = parser.parse_args(
            [
                "verify-lock",
                "--lock",
                "lock.json",
                "--uf2",
                "diagnostic.uf2",
                "--rollback",
                "rollback.uf2",
                "--production-raw",
                "production.uf2",
                "--picotool",
                "picotool",
            ]
        )
        self.assertEqual(parsed.picotool, pathlib.Path("picotool"))
        RAW.self_test()


if __name__ == "__main__":
    unittest.main()
