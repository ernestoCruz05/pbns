import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


class RecoveryObservabilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).resolve().parents[2]
        self.validator_path = (
            self.pbns_root
            / "integration"
            / "qemu"
            / "verify-recovery-observability.py"
        )
        self.assertTrue(self.validator_path.is_file())
        spec = importlib.util.spec_from_file_location(
            "verify_recovery_observability", self.validator_path
        )
        assert spec is not None and spec.loader is not None
        self.validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.validator)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.serial = self.root / "serial.log"
        self.before = self.root / "nv-before.bin"
        self.after = self.root / "nv-after.bin"
        self.disk_before = self.root / "disk-before.sha256"
        self.disk_after = self.root / "disk-after.sha256"
        self.before.write_bytes((5).to_bytes(8, "big"))
        self.after.write_bytes((7).to_bytes(8, "big"))
        self.disk_before.write_text("a" * 64 + "\n")
        self.disk_after.write_text("a" * 64 + "\n")
        for path in (self.before, self.after, self.disk_before, self.disk_after):
            path.chmod(0o600)
        self.lines = [
            "PBNS RECOVERY STATE 0",
            "PBNS RECOVERY STATE 1",
            "PBNS RECOVERY STATE 2",
            "PBNS RECOVERY STATE 3",
            "PBNS RECOVERY STATE 4",
            "PBNS RECOVERY STREAM DURATION MS=60000",
            "PBNS RECOVERY STATE 5",
            "PBNS RECOVERY STATE 6",
            "PBNS RECOVERY MEMORY LOAD BEGIN size=26553920 version=7",
            "PBNS RECOVERY MEMORY LOAD PASS",
            "PBNS RECOVERY STATE 7",
            "PBNS RECOVERY ROLLBACK ADVANCE BEGIN current=5 target=7",
            "PBNS RECOVERY ROLLBACK ADVANCE PASS",
            "PBNS RECOVERY STATE 8",
            "PBNS RECOVERY STARTIMAGE BEGIN",
            "PBNS RECOVERY READ-ONLY MODE",
        ]
        self._write(self.lines)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, lines: list[str]) -> None:
        self.serial.write_text("firmware\r\n" + "\r\n".join(lines) + "\r\n")
        self.serial.chmod(0o600)

    def _arguments(self) -> list[str]:
        return [
            sys.executable, str(self.validator_path),
            "--serial", str(self.serial),
            "--nv-before", str(self.before),
            "--nv-after", str(self.after),
            "--disk-before", str(self.disk_before),
            "--disk-after", str(self.disk_after),
            "--case-root", str(self.root),
            "--expected-size", "26553920",
            "--current-version", "5",
            "--target-version", "7",
        ]

    def _validate(self, case: str = "signed-trusted", target_version: int = 7) -> int | None:
        return self.validator.verify(
            self.serial,
            self.before,
            self.after,
            self.disk_before,
            self.disk_after,
            self.root,
            expected_size=26553920,
            current_version=5,
            target_version=target_version,
            case=case,
        )

    def test_accepts_exact_signed_memory_handoff_order(self) -> None:
        self._validate()

    def test_returns_duration_and_cli_prints_it_only_after_all_signed_oracles(self) -> None:
        self.assertEqual(self.validator.verify(
            self.serial, self.before, self.after, self.disk_before, self.disk_after,
            self.root, expected_size=26553920, current_version=5, target_version=7,
        ), 60000)
        completed = subprocess.run(
            [*self._arguments(), "--print-stream-duration"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "60000\n")
        default_output = subprocess.run(
            self._arguments(), text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(default_output.returncode, 0, default_output.stderr)
        self.assertEqual(default_output.stdout, "PBNS RECOVERY OBSERVABILITY PASS\n")
        self.disk_after.write_text("b" * 64 + "\n")
        self.disk_after.chmod(0o600)
        rejected = subprocess.run(
            [*self._arguments(), "--print-stream-duration"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, "")

    def test_descriptor_bound_evidence_rejects_symlink_wrong_mode_and_oversize(self) -> None:
        target = self.root / "target.log"
        target.write_bytes(b"PBNS")
        target.chmod(0o600)
        link = self.root / "serial-link.log"
        link.symlink_to(target)
        with self.assertRaises(self.validator.VerificationError):
            self.validator._read_bounded(link, 8)
        target.chmod(0o644)
        with self.assertRaises(self.validator.VerificationError):
            self.validator._read_bounded(target, 8)
        target.chmod(0o600)
        target.write_bytes(b"PBNS-oversize")
        with self.assertRaises(self.validator.VerificationError):
            self.validator._read_bounded(target, 4)
        target.write_bytes(b"PBNS")
        target.chmod(0o600)
        original_read = self.validator.os.read
        grew = False

        def append_after_bound(descriptor: int, count: int) -> bytes:
            nonlocal grew
            if count == 1 and not grew:
                grew = True
                with target.open("ab") as evidence:
                    evidence.write(b"!")
                    evidence.flush()
                    os.fsync(evidence.fileno())
            return original_read(descriptor, count)

        with mock.patch.object(self.validator.os, "read", side_effect=append_after_bound):
            with self.assertRaises(self.validator.VerificationError):
                self.validator._read_bounded(target, 8)

    def test_rejects_missing_duplicate_malformed_overbound_or_reordered_stream_duration(self) -> None:
        duration = "PBNS RECOVERY STREAM DURATION MS=60000"
        state_four = self.lines.index("PBNS RECOVERY STATE 4")
        state_five = self.lines.index("PBNS RECOVERY STATE 5")
        variants = (
            [line for line in self.lines if line != duration],
            [*self.lines[:state_five], duration, *self.lines[state_five:]],
            ["PBNS RECOVERY STREAM DURATION MS=60001" if line == duration else line for line in self.lines],
            ["PBNS RECOVERY STREAM DURATION MS=-1" if line == duration else line for line in self.lines],
            ["PBNS RECOVERY STREAM DURATION MS=01" if line == duration else line for line in self.lines],
            ["PBNS RECOVERY STREAM DURATION MS=abc" if line == duration else line for line in self.lines],
            [*self.lines[:state_five], "PBNS RECOVERY STREAM DURATION MS=abc", *self.lines[state_five:]],
            [*self.lines[:state_four], duration, self.lines[state_four], *self.lines[state_four + 1:]],
        )
        for lines in variants:
            with self.subTest(lines=lines):
                self._write(lines)
                with self.assertRaises(self.validator.VerificationError):
                    self._validate()

    def test_accepts_zero_stream_duration(self) -> None:
        self._write([
            "PBNS RECOVERY STREAM DURATION MS=0" if line ==
            "PBNS RECOVERY STREAM DURATION MS=60000" else line
            for line in self.lines
        ])
        self._validate()

    def test_rejects_missing_duplicate_and_reordered_markers(self) -> None:
        variants = (
            self.lines[:-1],
            self.lines + [self.lines[1]],
            [*self.lines[:7], self.lines[8], self.lines[7], *self.lines[9:]],
        )
        for lines in variants:
            with self.subTest(lines=lines):
                self._write(lines)
                with self.assertRaises(self.validator.VerificationError):
                    self._validate()

    def test_rejects_missing_duplicate_or_reordered_service_states(self) -> None:
        variants = (
            [line for line in self.lines if line != "PBNS RECOVERY STATE 2"],
            [*self.lines[:7], "PBNS RECOVERY STATE 5", *self.lines[7:]],
            [self.lines[0], self.lines[2], self.lines[1], *self.lines[3:]],
        )
        for lines in variants:
            with self.subTest(lines=lines):
                self._write(lines)
                with self.assertRaises(self.validator.VerificationError):
                    self._validate()

    def test_rejects_reject_failure_fallback_or_secret_text(self) -> None:
        for line in (
            "PBNS RECOVERY MEMORY LOAD REJECT status=800000000000001A",
            "PBNS RECOVERY FAILED stage=9 status=-8",
            "PBNS RECOVERY FALLBACK stage=4 loader_status=1",
            "policy authorization=secret",
            "request nonce=00",
        ):
            with self.subTest(line=line):
                self._write(self.lines + [line])
                with self.assertRaises(self.validator.VerificationError):
                    self._validate()

    def test_rejects_wrong_size_versions_nv_or_disk(self) -> None:
        changed = list(self.lines)
        size_marker = "PBNS RECOVERY MEMORY LOAD BEGIN size=26553920 version=7"
        changed[changed.index(size_marker)] = size_marker.replace("26553920", "1")
        self._write(changed)
        with self.assertRaises(self.validator.VerificationError):
            self._validate()
        self._write(self.lines)
        self.after.write_bytes((6).to_bytes(8, "big"))
        with self.assertRaises(self.validator.VerificationError):
            self._validate()
        self.after.write_bytes((7).to_bytes(8, "big"))
        self.disk_after.write_text("b" * 64 + "\n")
        with self.assertRaises(self.validator.VerificationError):
            self._validate()

    def test_production_failure_oracles_require_exact_lifecycle_boundaries(self) -> None:
        cases = {
            "unsigned-untrusted": [
                *[f"PBNS RECOVERY STATE {number}" for number in range(7)],
                "PBNS RECOVERY MEMORY LOAD BEGIN size=26553920 version=7",
                "PBNS RECOVERY MEMORY LOAD REJECT status=0x800000000000001A",
                "PBNS RECOVERY FREE BEGIN size=26553920",
                "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9",
                "PBNS RECOVERY FAILED stage=6 status=-8",
            ],
            "truncated": [
                *[f"PBNS RECOVERY STATE {number}" for number in range(7)],
                "PBNS RECOVERY MEMORY LOAD BEGIN size=26553920 version=7",
                "PBNS RECOVERY MEMORY LOAD REJECT status=0x800000000000001A",
                "PBNS RECOVERY FREE BEGIN size=26553920",
                "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9",
                "PBNS RECOVERY FAILED stage=6 status=-8",
            ],
            "forged-manifest": [
                "PBNS RECOVERY STATE 0",
                "PBNS RECOVERY STATE 1",
                "PBNS RECOVERY STATE 2",
                "PBNS RECOVERY STATE 9",
                "PBNS RECOVERY FAILED stage=2 status=-8",
            ],
            "downgrade": [
                *[f"PBNS RECOVERY STATE {number}" for number in range(6)],
                "PBNS RECOVERY FREE BEGIN size=26553920",
                "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9",
                "PBNS RECOVERY FAILED stage=5 status=-15",
            ],
        }
        self.after.write_bytes((5).to_bytes(8, "big"))
        for case, lines in cases.items():
            with self.subTest(case=case):
                self._write(lines)
                self.assertIsNone(self._validate(case, 5 if case == "downgrade" else 7))
                self._write(lines + ["PBNS RECOVERY ROLLBACK ADVANCE PASS"])
                with self.assertRaises(self.validator.VerificationError):
                    self._validate(case, 5 if case == "downgrade" else 7)

    def test_production_failure_chronology_rejects_cleanup_or_failed_state_reordering(self) -> None:
        cases = {
            "unsigned-untrusted": [
                *[f"PBNS RECOVERY STATE {number}" for number in range(7)],
                "PBNS RECOVERY MEMORY LOAD BEGIN size=26553920 version=7",
                "PBNS RECOVERY MEMORY LOAD REJECT status=0x800000000000001A",
                "PBNS RECOVERY FREE BEGIN size=26553920", "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9", "PBNS RECOVERY FAILED stage=6 status=-8",
            ],
            "truncated": [
                *[f"PBNS RECOVERY STATE {number}" for number in range(7)],
                "PBNS RECOVERY MEMORY LOAD BEGIN size=26553920 version=7",
                "PBNS RECOVERY MEMORY LOAD REJECT status=0x800000000000001A",
                "PBNS RECOVERY FREE BEGIN size=26553920", "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9", "PBNS RECOVERY FAILED stage=6 status=-8",
            ],
            "downgrade": [
                *[f"PBNS RECOVERY STATE {number}" for number in range(6)],
                "PBNS RECOVERY FREE BEGIN size=26553920", "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9", "PBNS RECOVERY FAILED stage=5 status=-15",
            ],
            "forged-manifest": [
                "PBNS RECOVERY STATE 0", "PBNS RECOVERY STATE 1", "PBNS RECOVERY STATE 2",
                "PBNS RECOVERY STATE 9", "PBNS RECOVERY FAILED stage=2 status=-8",
            ],
        }
        self.after.write_bytes((5).to_bytes(8, "big"))
        for case, lines in cases.items():
            with self.subTest(case=case):
                state = lines.index("PBNS RECOVERY STATE 9")
                failure = next(index for index, line in enumerate(lines) if "PBNS RECOVERY FAILED" in line)
                reordered = list(lines)
                reordered[state], reordered[failure] = reordered[failure], reordered[state]
                self._write(reordered)
                with self.assertRaises(self.validator.VerificationError):
                    self._validate(case, 5 if case == "downgrade" else 7)
                if case == "forged-manifest":
                    failed_state = lines.index("PBNS RECOVERY STATE 9")
                    mutated = [
                        *lines[:failed_state], "PBNS RECOVERY FREE BEGIN size=26553920",
                        "PBNS RECOVERY FREE PASS", *lines[failed_state:]
                    ]
                else:
                    mutated = [line for line in lines if line != "PBNS RECOVERY STATE 9"]
                self._write(mutated)
                with self.assertRaises(self.validator.VerificationError):
                    self._validate(case, 5 if case == "downgrade" else 7)

    def test_print_duration_is_rejected_for_failure_cases(self) -> None:
        self.after.write_bytes((5).to_bytes(8, "big"))
        self.after.chmod(0o600)
        self._write([
            *[f"PBNS RECOVERY STATE {number}" for number in range(7)],
            "PBNS RECOVERY MEMORY LOAD BEGIN size=26553920 version=7",
            "PBNS RECOVERY MEMORY LOAD REJECT status=0x800000000000001A",
            "PBNS RECOVERY FREE BEGIN size=26553920", "PBNS RECOVERY FREE PASS",
            "PBNS RECOVERY STATE 9", "PBNS RECOVERY FAILED stage=6 status=-8",
        ])
        completed = subprocess.run(
            [*self._arguments(), "--case", "unsigned-untrusted", "--print-stream-duration"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")

    def test_rejects_evaluation_event_file_for_every_production_case(self) -> None:
        event_file = self.root / "recovery-events.jsonl"
        event_file.write_text("{}\n")
        event_file.chmod(0o600)
        for case in ("signed-trusted", "unsigned-untrusted", "truncated", "forged-manifest", "downgrade"):
            with self.subTest(case=case):
                with self.assertRaises(self.validator.VerificationError):
                    self._validate(case, 5 if case == "downgrade" else 7)


if __name__ == "__main__":
    unittest.main()
