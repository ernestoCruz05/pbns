import hashlib
import importlib.util
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import tempfile
import time
import types
import unittest
from types import SimpleNamespace
from unittest import mock


class FakeSerial:
    def __init__(self, corrupt: bool = False) -> None:
        self.pending = bytearray()
        self.corrupt = corrupt
        self.write_calls = 0
        self.read_calls = 0

    def write(self, data: bytes) -> int:
        self.write_calls += 1
        amount = min(len(data), 7)
        copied = bytearray(data[:amount])
        if self.corrupt and copied:
            copied[0] ^= 1
            self.corrupt = False
        self.pending.extend(copied)
        return amount

    def flush(self) -> None:
        return None

    def read(self, size: int) -> bytes:
        self.read_calls += 1
        amount = min(size, len(self.pending), 5)
        result = bytes(self.pending[:amount])
        del self.pending[:amount]
        return result


def extract_static_function_body(source: str, name: str) -> str:
    declaration = re.compile(
        rf"(?m)^[ \t]*static\b[^;{{}}]*\b{re.escape(name)}\s*\(",
    )
    matches = list(declaration.finditer(source))
    if len(matches) != 1:
        raise AssertionError(f"expected one static {name} definition, found {len(matches)}")

    opening = source.find("{", matches[0].end())
    if opening < 0:
        raise AssertionError(f"missing opening brace for {name}")

    depth = 0
    index = opening
    state = "code"
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if character == '"':
                state = "string"
            elif character == "'":
                state = "character"
            elif character == "/" and following == "/":
                state = "line-comment"
                index += 1
            elif character == "/" and following == "*":
                state = "block-comment"
                index += 1
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return source[opening + 1 : index]
        elif state in ("string", "character"):
            if character == "\\":
                index += 1
            elif (state == "string" and character == '"') or (
                state == "character" and character == "'"
            ):
                state = "code"
        elif state == "line-comment":
            if character == "\n":
                state = "code"
        elif state == "block-comment" and character == "*" and following == "/":
            state = "code"
            index += 1
        index += 1

    raise AssertionError(f"unterminated static {name} definition")


class PicoLoopbackTest(unittest.TestCase):
    module: types.ModuleType

    @classmethod
    def setUpClass(cls) -> None:
        script = pathlib.Path(__file__).parents[2] / "integration" / "hil" / "pico-loopback.py"
        specification = importlib.util.spec_from_file_location("pico_loopback", script)
        assert specification is not None and specification.loader is not None
        cls.module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(cls.module)
        tunnel_path = script.with_name("uefi-tls-tunnel.py")
        tunnel_spec = importlib.util.spec_from_file_location("uefi_tls_tunnel_for_gate", tunnel_path)
        assert tunnel_spec is not None and tunnel_spec.loader is not None
        cls.tunnel = importlib.util.module_from_spec(tunnel_spec)
        tunnel_spec.loader.exec_module(cls.tunnel)

    def _usb_fixture(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        sysfs = root / "devices"
        tty = root / "tty"
        device = sysfs / "1-3"
        device.mkdir(parents=True)
        tty.mkdir()
        values = {
            "idVendor": "cafe\n",
            "idProduct": "4011\n",
            "bcdDevice": "0100\n",
            "product": "PBNS Proxy v1\n",
            "serial": "E66130100F527A26\n",
            "speed": "12\n",
        }
        for name, value in values.items():
            (device / name).write_text(value, encoding="utf-8")
        for interface, number, terminal in (
            ("1-3:1.0", "00\n", "ttyACM0"),
            ("1-3:1.2", "02\n", "ttyACM1"),
        ):
            interface_path = sysfs / interface
            interface_path.mkdir()
            (interface_path / "bInterfaceNumber").write_text(number, encoding="ascii")
            nested = interface_path / "tty" / terminal
            nested.mkdir(parents=True)
            terminal_path = tty / terminal
            terminal_path.mkdir()
            (terminal_path / "device").symlink_to(nested)
            (terminal_path / "dev").write_text(
                "1:3\n" if terminal == "ttyACM0" else "1:4\n", encoding="ascii"
            )
        return sysfs, tty

    @staticmethod
    def _cdc_metadata() -> dict[str, object]:
        return {
            "ttyACM0": SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 3)),
            "ttyACM1": SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 4)),
        }

    def test_exact_usb_identity_speed_and_cdc_roles_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sysfs, tty = self._usb_fixture(root)
            identity = self.module.verify_hardware_identity(
                sysfs,
                tty,
                cdc0=pathlib.Path("/dev/ttyACM0"),
                cdc1=pathlib.Path("/dev/ttyACM1"),
                expected_serial="E66130100F527A26",
                cdc_metadata=self._cdc_metadata(),
            )
            self.assertEqual(identity["device"], "1-3")
            self.assertEqual(identity["speed"], "12")
            self.assertEqual(identity["cdc0_interface"], "00")
            self.assertEqual(identity["cdc1_interface"], "02")
            mutations = {
                "idVendor": "dead\n",
                "idProduct": "beef\n",
                "bcdDevice": "0101\n",
                "product": "PBNS Provision\n",
                "serial": "BAD\n",
                "speed": "480\n",
            }
            device = sysfs / "1-3"
            for name, wrong in mutations.items():
                original = (device / name).read_text(encoding="utf-8")
                (device / name).write_text(wrong, encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(self.module.LoopbackError):
                    self.module.verify_hardware_identity(
                        sysfs,
                        tty,
                        cdc0=pathlib.Path("/dev/ttyACM0"),
                        cdc1=pathlib.Path("/dev/ttyACM1"),
                        expected_serial="E66130100F527A26",
                        cdc_metadata=self._cdc_metadata(),
                    )
                (device / name).write_text(original, encoding="utf-8")
            with self.assertRaises(self.module.LoopbackError):
                self.module.verify_hardware_identity(
                    sysfs,
                    tty,
                    cdc0=pathlib.Path("/dev/ttyACM1"),
                    cdc1=pathlib.Path("/dev/ttyACM0"),
                    expected_serial="E66130100F527A26",
                )

    def test_forbidden_and_block_device_paths_are_rejected(self) -> None:
        with self.assertRaises(self.module.LoopbackError):
            self.module.reject_unsafe_path(pathlib.Path("/dev/sdc"))
        with self.assertRaises(self.module.LoopbackError):
            self.module.reject_unsafe_path(
                pathlib.Path("/tmp/not-a-device"),
                metadata=SimpleNamespace(st_mode=stat.S_IFBLK),
            )
        self.module.reject_unsafe_path(
            pathlib.Path("/dev/ttyACM0"),
            metadata=SimpleNamespace(st_mode=stat.S_IFCHR),
        )

    def test_cdc_nodes_reject_symlinks_and_bind_exact_device_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = pathlib.Path(directory) / "ttyACM0"
            link.symlink_to("/dev/null")
            with self.assertRaises(self.module.LoopbackError):
                self.module.reject_unsafe_path(link)
        expected = f"{os.major(os.stat('/dev/null').st_rdev)}:{os.minor(os.stat('/dev/null').st_rdev)}"
        self.module.verify_cdc_node_metadata(
            SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.stat('/dev/null').st_rdev),
            expected,
        )
        with self.assertRaises(self.module.LoopbackError):
            self.module.verify_cdc_node_metadata(
                SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(99, 99)),
                expected,
            )

    def test_cdc_wrong_ancestry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sysfs, tty = self._usb_fixture(root)
            interface = sysfs / "9-9:1.0"
            interface.mkdir()
            (interface / "bInterfaceNumber").write_text("00\n", encoding="ascii")
            nested = interface / "tty" / "ttyACM0"
            nested.mkdir(parents=True)
            (tty / "ttyACM0" / "device").unlink()
            (tty / "ttyACM0" / "device").symlink_to(nested)
            with self.assertRaises(self.module.LoopbackError):
                self.module.verify_hardware_identity(
                    sysfs, tty, cdc0=pathlib.Path('/dev/ttyACM0'),
                    cdc1=pathlib.Path('/dev/ttyACM1'),
                    expected_serial='E66130100F527A26',
                    cdc_metadata={
                        'ttyACM0': SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 3)),
                        'ttyACM1': SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 3)),
                    },
                )

    def test_exact_digest_addressed_artifact_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contents = b"artifact-fixture"
            digest = hashlib.sha256(contents).hexdigest()
            artifact = pathlib.Path(directory) / digest
            artifact.write_bytes(contents)
            artifact.chmod(0o444)
            self.assertEqual(
                self.module.verify_digest_artifact(
                    artifact, expected_sha256=digest, expected_size=len(contents)
                ),
                digest,
            )
            for mutation in ("size", "digest", "mode", "name"):
                with self.subTest(mutation=mutation):
                    expected_size = len(contents) + (mutation == "size")
                    expected_digest = "0" * 64 if mutation == "digest" else digest
                    if mutation == "mode":
                        artifact.chmod(0o600)
                    selected = artifact
                    if mutation == "name":
                        selected = artifact.with_name("not-digest")
                        selected.write_bytes(contents)
                        selected.chmod(0o444)
                    with self.assertRaises(self.module.LoopbackError):
                        self.module.verify_digest_artifact(
                            selected,
                            expected_sha256=expected_digest,
                            expected_size=expected_size,
                        )
                    artifact.chmod(0o444)
            link = artifact.with_name("0" * 64)
            link.symlink_to(artifact)
            with self.assertRaises(self.module.LoopbackError):
                self.module.verify_digest_artifact(
                    link, expected_sha256="0" * 64, expected_size=len(contents)
                )

    def test_short_io_preserves_deterministic_bytes(self) -> None:
        serial_port = FakeSerial()
        result = self.module.run_serial_trial(
            serial_port,
            total_bytes=4096,
            write_chunks=(1, 7, 64, 255),
            read_chunk=13,
            seed=b"unit-loopback",
        )
        self.assertEqual(result["bytes_sent"], 4096)
        self.assertEqual(result["bytes_received"], 4096)
        self.assertGreater(serial_port.write_calls, 4)
        self.assertGreater(serial_port.read_calls, 4)
        self.assertEqual(
            result["stream_sha256"],
            hashlib.sha256(self.module.deterministic_bytes(4096, b"unit-loopback")).hexdigest(),
        )

    def test_corruption_is_rejected(self) -> None:
        with self.assertRaises(self.module.LoopbackError):
            self.module.run_serial_trial(
                FakeSerial(corrupt=True),
                total_bytes=128,
                write_chunks=(64,),
                read_chunk=64,
                seed=b"corrupt",
            )

    def test_results_are_exclusive_private_synchronized_and_payload_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            run = self.module.create_run_directory(
                root, timestamp="20260811T120000Z"
            )
            self.assertEqual(run.name, "20260811T120000Z-uefi-tls-raw")
            self.assertEqual(stat.S_IMODE(run.stat().st_mode), 0o700)
            self.assertEqual(run.stat().st_uid, os.getuid())
            result = self.module.self_test_result()
            path = self.module.write_result(run, result, filename="self-test.json")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), result)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertGreater(path.stat().st_size, 0)
            with self.assertRaises(self.module.LoopbackError):
                self.module.write_result(run, result, filename="self-test.json")
            with self.assertRaises(self.module.LoopbackError):
                self.module.write_result(
                    run,
                    {**result, "payload_capture": "00"},
                    filename="sensitive.json",
                )
            with self.assertRaises(self.module.LoopbackError):
                self.module.write_result(
                    run,
                    {**result, "unexpected": b"ciphertext"},
                    filename="bytes.json",
                )
            with mock.patch.object(
                self.module.os, "write", side_effect=OSError("injected")
            ):
                with self.assertRaises(self.module.LoopbackError):
                    self.module.write_result(
                        run, result, filename="injected-write-failure.json"
                    )
            self.assertFalse((run / "injected-write-failure.json").exists())
            with self.assertRaises(self.module.LoopbackError):
                self.module.create_run_directory(
                    root, timestamp="20260811T120000Z"
                )
            for field, value in (
                ("expected_san", "192.168.1.181"),
                ("required_spki_sha256", "0" * 64),
                ("required_tls_version", "TLSv1.3"),
                ("required_cipher", "wrong"),
                ("required_alpn", "wrong/1"),
                ("driver", "genuine-uefi"),
                ("uefi_execution", "passed"),
            ):
                with self.subTest(field=field), self.assertRaises(
                    self.module.LoopbackError
                ):
                    self.module.validate_result({**result, field: value})

    def test_completion_bound_covers_full_artifact_usb_packets(self) -> None:
        result = self.module.self_test_result()
        self.module.validate_result({**result, "completion_count": 524288})
        with self.assertRaises(self.module.LoopbackError):
            self.module.validate_result({**result, "completion_count": 524289})

    def _publish_gate_records(self, run: pathlib.Path) -> None:
        counters = {"upstream": 0, "downstream": 0}
        for record in self.module.self_test_gate_records():
            trial = str(record["trial"])
            if trial in counters:
                suffix = "-warmup" if record["warmup"] else ""
                filename = f"{trial}{suffix}.json"
                counters[trial] += 1
            else:
                filename = f"{trial}.json"
            self.module.write_result(run, record, filename=filename)

    def test_whole_directory_validator_rejects_every_unexpected_entry(self) -> None:
        for kind in ("binary", "hidden", "symlink", "json", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                root.chmod(0o700)
                run = self.module.create_run_directory(root, timestamp="20260811T130000Z")
                self._publish_gate_records(run)
                if kind == "binary":
                    (run / "ciphertext.bin").write_bytes(b"forbidden")
                elif kind == "hidden":
                    (run / ".capture").write_text("forbidden", encoding="ascii")
                elif kind == "symlink":
                    (run / "extra").symlink_to("upstream.json")
                elif kind == "json":
                    (run / "extra.json").write_text("{}\n", encoding="ascii")
                else:
                    (run / "extra").mkdir()
                with self.assertRaises(self.tunnel.TunnelError):
                    self.tunnel._validate_results(run)

    def test_result_filenames_are_bound_to_exact_trial_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            run = self.module.create_run_directory(root, timestamp="20260811T130002Z")
            self._publish_gate_records(run)
            self.tunnel._validate_results(run)

            upstream = run / "upstream.json"
            artifact = run / "artifact.json"
            upstream_bytes = upstream.read_bytes()
            artifact_bytes = artifact.read_bytes()
            upstream.unlink()
            artifact.unlink()
            upstream.write_bytes(artifact_bytes)
            artifact.write_bytes(upstream_bytes)
            upstream.chmod(0o600)
            artifact.chmod(0o600)
            with self.assertRaises(self.tunnel.TunnelError):
                self.tunnel._validate_results(run)

            upstream.unlink()
            artifact.unlink()
            upstream.write_bytes(upstream_bytes)
            artifact.write_bytes(upstream_bytes)
            upstream.chmod(0o600)
            artifact.chmod(0o600)
            with self.assertRaises(self.tunnel.TunnelError):
                self.tunnel._validate_results(run)

    def test_canonical_result_manifest_covers_exact_thirteen_trials(self) -> None:
        expected = {
            "upstream-warmup.json": ("upstream", True),
            "downstream-warmup.json": ("downstream", True),
            "upstream.json": ("upstream", False),
            "downstream.json": ("downstream", False),
            "artifact.json": ("artifact", False),
            "wrong-san.json": ("wrong-san", False),
            "wrong-spki.json": ("wrong-spki", False),
            "wrong-alpn.json": ("wrong-alpn", False),
            "wrong-cipher.json": ("wrong-cipher", False),
            "cancellation.json": ("cancellation", False),
            "fresh-reconnect.json": ("fresh-reconnect", False),
            "truncation.json": ("truncation", False),
            "digest-mismatch.json": ("digest-mismatch", False),
        }
        self.assertEqual(self.module.EXPECTED_RESULT_TRIALS, expected)
        self.assertEqual(self.module.EXPECTED_RESULT_FILES, frozenset(expected))

    def test_result_directory_descriptor_must_match_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            run = self.module.create_run_directory(root, timestamp="20260811T130001Z")
            self._publish_gate_records(run)
            self.tunnel._validate_results(run)
            real_stat = self.tunnel.os.stat
            def swapped(path, *args, **kwargs):
                value = real_stat(path, *args, **kwargs)
                if pathlib.Path(path) == run:
                    return SimpleNamespace(st_dev=value.st_dev + 1, st_ino=value.st_ino)
                return value
            with mock.patch.object(self.tunnel.os, "stat", side_effect=swapped):
                with self.assertRaises(self.tunnel.TunnelError):
                    self.tunnel._validate_results(run)

    def test_evidence_transactions_quarantine_every_failure_point(self) -> None:
        failures = (
            ("write", 2),
            ("fsync", 3),
            ("close", 2),
            ("link", 1),
            ("unlink", 1),
            ("fsync", 4),
            ("fsync", 5),
            ("fsync", 6),
        )
        for index, (name, failing_call) in enumerate(failures):
            with self.subTest(name=name, call=failing_call), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                root.chmod(0o700)
                run = self.module.create_run_directory(
                    root, timestamp=f"20260811T14{index:02d}00Z"
                )
                target = getattr(self.module.os, name)
                calls = 0

                def injected(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if name == "close":
                        result = target(*args, **kwargs)
                        if calls == failing_call:
                            raise OSError("injected close")
                        return result
                    if calls == failing_call:
                        raise OSError("injected transaction failure")
                    return target(*args, **kwargs)

                with mock.patch.object(self.module.os, name, side_effect=injected):
                    with self.assertRaises(self.module.LoopbackError):
                        self.module.write_result(
                            run, self.module.self_test_result(), filename="self-test.json"
                        )
                self.assertTrue(any(entry.name.startswith(".") for entry in run.iterdir()))

    def test_success_fsyncs_directory_after_removing_last_invalid_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            run = self.module.create_run_directory(root, timestamp="20260811T141000Z")
            real_fsync = self.module.os.fsync
            real_unlink = self.module.os.unlink
            events = []

            def fsync(descriptor):
                events.append(("fsync", descriptor))
                return real_fsync(descriptor)

            def unlink(path, *args, **kwargs):
                events.append(("unlink", str(path)))
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(self.module.os, "fsync", side_effect=fsync), mock.patch.object(
                self.module.os, "unlink", side_effect=unlink
            ):
                self.module.write_result(
                    run, self.module.self_test_result(), filename="self-test.json"
                )
            invalid_index = events.index(("unlink", ".self-test.json.invalid"))
            self.assertEqual(events[invalid_index + 1][0], "fsync")
            self.assertEqual(set(run.iterdir()), {run / "self-test.json"})

    def test_exact_rate_math_rejects_rounding_and_nonfinite_values(self) -> None:
        mib = 1024 * 1024
        self.assertFalse(self.module.meets_minimum_rate(3 * mib, 5_000_000_001))
        self.assertTrue(self.module.meets_minimum_rate(3 * mib, 5_000_000_000))
        self.assertTrue(self.module.meets_minimum_rate(3 * mib, 4_999_999_999))
        valid = self.module.self_test_gate_records()
        rounded_below = [
            {
                **record,
                "duration_ns": 1_666_666_667,
                "rate_mib_s": self.module.display_rate_mib_s(
                    self.module.DIRECT_BYTES, 1_666_666_667
                ),
            }
            if record["trial"] == "upstream" and not record["warmup"]
            else record
            for record in valid
        ]
        self.assertEqual(
            next(
                record["rate_mib_s"]
                for record in rounded_below
                if record["trial"] == "upstream" and not record["warmup"]
            ),
            0.6,
        )
        with self.assertRaises(self.module.LoopbackError):
            self.module.validate_performance_gate(
                rounded_below, expected_artifact_sha256=self.module.ARTIFACT_SHA256
            )
        for bad in (float("nan"), float("inf"), 0.600001):
            mutated = [
                {**record, "rate_mib_s": bad}
                if record["trial"] == "upstream" and not record["warmup"]
                else record
                for record in valid
            ]
            with self.subTest(rate=bad), self.assertRaises(self.module.LoopbackError):
                self.module.validate_performance_gate(
                    mutated, expected_artifact_sha256=self.module.ARTIFACT_SHA256
                )
        inconsistent_artifact = [
            {**record, "error_code": "wrong-spki"}
            if record["trial"] == "artifact" else record
            for record in valid
        ]
        with self.assertRaises(self.module.LoopbackError):
            self.module.validate_performance_gate(
                inconsistent_artifact, expected_artifact_sha256=self.module.ARTIFACT_SHA256
            )

    def test_shell_signal_cleanup_kills_stuck_child(self) -> None:
        shell = pathlib.Path(__file__).parents[2] / "integration" / "hil" / "pico-loopback.sh"
        with tempfile.TemporaryDirectory() as directory:
            pid_file = pathlib.Path(directory) / "child.pid"
            process = subprocess.Popen(
                [str(shell), "--cleanup-self-test"],
                env={**os.environ, "PBNS_CLEANUP_TEST_PID_FILE": str(pid_file)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            for _ in range(200):
                if pid_file.exists():
                    break
                time.sleep(0.01)
            self.assertTrue(pid_file.exists())
            child = int(pid_file.read_text(encoding="ascii"))
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=8)
            self.assertEqual(process.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)

    def test_legacy_pico_tls_hardware_commands_are_retired(self) -> None:
        source = (
            pathlib.Path(__file__).parents[2] / "integration" / "hil" / "pico-loopback.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            'add_parser("echo-server")',
            'add_parser("trial")',
            'add_parser("silence-trial")',
            "run_physical_trial",
            "payload_sha256",
        ):
            self.assertNotIn(forbidden, source)

    def test_firmware_clears_data_queues_on_disconnect_before_network_step(self) -> None:
        source_path = pathlib.Path(__file__).parents[2] / "pico" / "src" / "main.c"
        source = source_path.read_text(encoding="utf-8")
        self.assertRegex(
            source,
            r"(?m)^static[ \t]+bool[ \t]+tunnel_task[ \t]*\([ \t]*void[ \t]*\)",
        )
        task = extract_static_function_body(source, "tunnel_task")
        connected = task.index("tud_cdc_n_connected(DATA_CDC_INSTANCE)")
        observe = task.index("pbns_pump_session_observe", connected)
        read_flush = task.index("tud_cdc_n_read_flush(DATA_CDC_INSTANCE)", observe)
        write_clear = task.index("tud_cdc_n_write_clear(DATA_CDC_INSTANCE)", read_flush)
        pump_reset = task.index("pbns_byte_pump_reset", write_clear)
        network = task.index("pbns_network_step", pump_reset)
        self.assertLess(connected, observe)
        self.assertLess(observe, read_flush)
        self.assertLess(read_flush, write_clear)
        self.assertLess(write_clear, pump_reset)
        self.assertLess(pump_reset, network)
        self.assertEqual(source.count("tud_cdc_n_read_flush(DATA_CDC_INSTANCE)"), 1)
        self.assertEqual(
            source.count("tud_cdc_n_read_flush(PROVISION_CDC_INSTANCE)"), 2
        )

    def test_hardware_shell_locks_raw_gate_and_all_negative_trials(self) -> None:
        shell = pathlib.Path(__file__).parents[2] / "integration" / "hil" / "pico-loopback.sh"
        contents = shell.read_text(encoding="utf-8")
        for marker in (
            "PBNS_CDC0_PORT",
            "PBNS_PROVISION_PORT",
            "PBNS_PICO_SERIAL",
            "PBNS_GATEWAY_SERVER_NAME",
            "E66130100F527A26",
            "192.168.1.180",
            "e99ced85ba0c91c3b8d914ec3fcd7b7b5531e81a87a72830e181eb43de3ecd14",
            "245db7d544efcd4f2fb8d69f292d14bf5bf1f4aac81ed07e4ec6f301da5ce1c7",
            "d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3",
            "wrong-san",
            "wrong-spki",
            "wrong-alpn",
            "wrong-cipher",
            "cancellation",
            "fresh-reconnect",
            "truncation",
            "digest-mismatch",
            "rollback-needed",
            "--expected-san",
            "--require-hardware",
            "STOP_GRACE_ATTEMPTS=50",
            "handle_signal",
            "CONNECT_DELAY_SECONDS=3",
        ):
            self.assertIn(marker, contents)
        self.assertNotIn("provision-pico.py", contents)
        self.assertNotIn("PROVISION_RECORD", contents)
        self.assertNotIn("/dev/sdc", contents)

    def test_gate_rejects_missing_warmup_low_rate_count_digest_and_negatives(self) -> None:
        valid = self.module.self_test_gate_records()
        self.module.validate_performance_gate(
            valid,
            expected_artifact_sha256=(
                "d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3"
            ),
        )
        mutations = (
            [record for record in valid if not record["warmup"]],
            [
                {**record, "rate_mib_s": 0.59}
                if record["trial"] == "upstream" and not record["warmup"]
                else record
                for record in valid
            ],
            [
                {**record, "bytes_observed": 26553919}
                if record["trial"] == "artifact"
                else record
                for record in valid
            ],
            [
                {**record, "sha256_observed": "0" * 64}
                if record["trial"] == "artifact"
                else record
                for record in valid
            ],
            [record for record in valid if record["trial"] != "wrong-alpn"],
            [
                {**record, "error_code": "none"}
                if record["trial"] == "wrong-spki"
                else record
                for record in valid
            ],
            [
                *valid,
                next(record for record in valid if record["trial"] == "truncation"),
            ],
        )
        for records in mutations:
            with self.assertRaises(self.module.LoopbackError):
                self.module.validate_performance_gate(
                    records,
                    expected_artifact_sha256=(
                        "d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
