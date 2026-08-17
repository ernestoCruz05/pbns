import pathlib
import subprocess
import tempfile
import unittest


class SecureBootPreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).resolve().parents[2]
        self.verifier = self.pbns_root / "integration" / "qemu" / "verify-secureboot-preflight.py"
        self.guid = "EFIGlobalVariable"

    def verify(self, serial: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "serial.log"
            path.write_text(serial, encoding="utf-8")
            return subprocess.run(
                [str(self.verifier), "--serial", str(path)], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )

    def block(self, name: str, value: str, guid: str | None = None) -> str:
        return "\n".join((
            f"PBNS-SB-BEGIN-{name}",
            f"Variable NV+RT+BS '{guid or self.guid}:{name}' DataSize = 0x01",
            f"00000000: {value}                                               *.*",
            f"PBNS-SB-END-{name}",
        ))

    def valid(self) -> str:
        return "\x1b[0m" + self.block("SecureBoot", "01") + "\r\n" + self.block("SetupMode", "00")

    def test_accepts_one_ordered_bounded_single_byte_block_per_variable(self) -> None:
        completed = self.verify(self.valid())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("PBNS SECUREBOOT SERIAL ORACLE PASS", completed.stdout)

    def test_rejects_metadata_alias_and_wrong_namespace_false_positives(self) -> None:
        wrong_namespace = self.block("SecureBoot", "01", "OtherGuid") + "\n" + self.block("SetupMode", "00")
        self.assertNotEqual(self.verify(wrong_namespace).returncode, 0)
        metadata = "\n".join((
            "SecureBoot=01 SetupMode=00 DataSize = 0x01",
            "guid:EfiGlobalVariable SecureBoot 01",
            "PBNS-SB-BEGIN-SecureBoot",
            f"Variable NV+RT+BS '{self.guid}:Other' DataSize = 0x01",
            "00000000: 01                                               *.*",
            "PBNS-SB-END-SecureBoot",
            self.block("SetupMode", "00"),
        ))
        self.assertNotEqual(self.verify(metadata).returncode, 0)

    def test_rejects_duplicate_markers_extra_rows_and_extra_content(self) -> None:
        duplicated = "\n".join((self.block("SecureBoot", "01"), self.block("SecureBoot", "01"), self.block("SetupMode", "00")))
        self.assertNotEqual(self.verify(duplicated).returncode, 0)
        extra_byte = "\n".join((
            "PBNS-SB-BEGIN-SecureBoot",
            f"Variable NV+RT+BS '{self.guid}:SecureBoot' DataSize = 0x01",
            "00000000: 01 00                                            *..*",
            "PBNS-SB-END-SecureBoot", self.block("SetupMode", "00"),
        ))
        self.assertNotEqual(self.verify(extra_byte).returncode, 0)
        extra_line = "\n".join((
            "PBNS-SB-BEGIN-SecureBoot",
            f"Variable NV+RT+BS '{self.guid}:SecureBoot' DataSize = 0x01",
            "unexpected", "00000000: 01                                               *.*",
            "PBNS-SB-END-SecureBoot", self.block("SetupMode", "00"),
        ))
        self.assertNotEqual(self.verify(extra_line).returncode, 0)

    def test_rejects_reversed_nested_or_overlapping_marker_order(self) -> None:
        reversed_order = self.block("SetupMode", "00") + "\n" + self.block("SecureBoot", "01")
        self.assertNotEqual(self.verify(reversed_order).returncode, 0)
        nested = "\n".join((
            "PBNS-SB-BEGIN-SecureBoot",
            "PBNS-SB-BEGIN-SetupMode",
            f"Variable NV+RT+BS '{self.guid}:SetupMode' DataSize = 0x01",
            "00000000: 00                                               *.*",
            "PBNS-SB-END-SetupMode",
            f"Variable NV+RT+BS '{self.guid}:SecureBoot' DataSize = 0x01",
            "00000000: 01                                               *.*",
            "PBNS-SB-END-SecureBoot",
        ))
        self.assertNotEqual(self.verify(nested).returncode, 0)


if __name__ == "__main__":
    unittest.main()
