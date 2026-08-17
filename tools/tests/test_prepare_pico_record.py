import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest


class PreparePicoRecordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        self.root = pathlib.Path(self.fixture.name)
        self.pbns = self.root / "pbns"
        self.home = self.root / "home"
        self.bin = self.root / "bin"
        self.capture = self.root / "capture"
        for directory in (
            self.pbns / "tools",
            self.pbns / "gateway",
            self.pbns / "build" / "dev",
            self.pbns / "tests" / "fixtures" / "keys",
            self.home,
            self.bin,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        source = pathlib.Path(__file__).parents[1] / "prepare-pico-record.sh"
        self.script = self.pbns / "tools" / "prepare-pico-record.sh"
        shutil.copy2(source, self.script)
        self.script.chmod(0o755)
        (self.pbns / "tests" / "fixtures" / "keys" / "tls-gateway-test-spki.sha256").write_text(
            "5a" * 32 + "\n", encoding="ascii"
        )
        private = self.home / ".pbns-provision"
        private.mkdir(mode=0o700)
        (private / "ssid.bin").write_bytes(b"test-network")
        (private / "psk.bin").write_bytes(b"private-passphrase")
        (private / "ssid.bin").chmod(0o600)
        (private / "psk.bin").chmod(0o600)
        self._write_fake_go()
        self._write_fake_validator()

    def _write_fake_go(self) -> None:
        fake_go = self.bin / "go"
        fake_go.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os
                import pathlib
                import stat
                import sys

                def argument(name: str) -> str:
                    index = sys.argv.index(name)
                    return sys.argv[index + 1]

                ssid_path = pathlib.Path(argument("--ssid-file"))
                psk_path = pathlib.Path(argument("--psk-file"))
                output_path = pathlib.Path(argument("--output"))
                if stat.S_IMODE(ssid_path.stat().st_mode) != 0o600:
                    raise SystemExit(7)
                if stat.S_IMODE(psk_path.stat().st_mode) != 0o600:
                    raise SystemExit(7)
                if stat.S_IMODE(output_path.parent.stat().st_mode) != 0o700:
                    raise SystemExit(7)
                capture = pathlib.Path(os.environ["PBNS_HELPER_TEST_CAPTURE"])
                capture.write_text(
                    "ssid=" + ssid_path.read_text(encoding="utf-8") + "\\n" +
                    "psk=" + psk_path.read_text(encoding="utf-8") + "\\n" +
                    "host=" + argument("--host") + "\\n" +
                    "port=" + argument("--port") + "\\n",
                    encoding="utf-8",
                )
                mode = os.environ.get("PBNS_HELPER_TEST_FAIL", "")
                descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(b"synthetic-record")
                if mode == "race":
                    final = pathlib.Path(os.environ["HOME"]) / ".pbns-provision" / "credentials.cbor"
                    final.write_bytes(b"racer")
                    final.chmod(0o600)
                if mode == "go":
                    raise SystemExit(9)
                print("wrote private Pico credential record")
                """
            ),
            encoding="utf-8",
        )
        fake_go.chmod(0o755)

    def _write_fake_validator(self) -> None:
        validator = self.pbns / "build" / "dev" / "pbns-pico-record-validate"
        validator.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os
                import pathlib
                import sys

                if os.environ.get("PBNS_HELPER_TEST_FAIL") == "validator":
                    raise SystemExit(9)
                if pathlib.Path(sys.argv[1]).read_bytes() != b"synthetic-record":
                    raise SystemExit(8)
                if not pathlib.Path(sys.argv[2]).is_file():
                    raise SystemExit(8)
                print("PICO CREDENTIAL RECORD VALID")
                """
            ),
            encoding="utf-8",
        )
        validator.chmod(0o755)

    def run_helper(
        self, input_text: str, *, fail: str = "", arguments: tuple[str, ...] = ()
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HOME"] = str(self.home)
        environment["PATH"] = f"{self.bin}:/usr/bin:/bin"
        environment["PBNS_HELPER_TEST_CAPTURE"] = str(self.capture)
        if fail:
            environment["PBNS_HELPER_TEST_FAIL"] = fail
        else:
            environment.pop("PBNS_HELPER_TEST_FAIL", None)
        return subprocess.run(
            [str(self.script), *arguments],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def private_directory(self) -> pathlib.Path:
        return self.home / ".pbns-provision"

    def test_success_keeps_only_private_validated_record(self) -> None:
        result = self.run_helper("192.0.2.10\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        private = self.private_directory()
        record = private / "credentials.cbor"
        self.assertEqual(record.read_bytes(), b"synthetic-record")
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
        self.assertEqual(sorted(path.name for path in private.iterdir()), ["credentials.cbor"])
        self.assertEqual(
            self.capture.read_text(encoding="utf-8"),
            "ssid=test-network\n"
            "psk=private-passphrase\n"
            "host=192.0.2.10\n"
            "port=8443\n",
        )
        combined = result.stdout + result.stderr
        self.assertNotIn("test-network", combined)
        self.assertNotIn("private-passphrase", combined)
        self.assertIn("PBNS PICO RECORD READY", result.stdout)
        self.assertIn("do not open CDC1", result.stdout)

    def test_prompt_mode_creates_private_directory_and_removes_staged_inputs(self) -> None:
        shutil.rmtree(self.private_directory())
        result = self.run_helper(
            "prompt-network\nprompt-passphrase\n192.0.2.10\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        private = self.private_directory()
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
        self.assertEqual(
            sorted(path.name for path in private.iterdir()), ["credentials.cbor"]
        )
        self.assertEqual(
            self.capture.read_text(encoding="utf-8"),
            "ssid=prompt-network\n"
            "psk=prompt-passphrase\n"
            "host=192.0.2.10\n"
            "port=8443\n",
        )
        combined = result.stdout + result.stderr
        self.assertNotIn("prompt-network", combined)
        self.assertNotIn("prompt-passphrase", combined)

    def test_refuses_existing_output_without_invoking_generator(self) -> None:
        private = self.private_directory()
        record = private / "credentials.cbor"
        record.write_bytes(b"existing")
        record.chmod(0o600)
        result = self.run_helper("192.0.2.10\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record.read_bytes(), b"existing")
        self.assertFalse(self.capture.exists())

    def test_rejects_invalid_or_unsafe_ipv4(self) -> None:
        for address in (
            "not-an-ip",
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
        ):
            with self.subTest(address=address):
                self.capture.unlink(missing_ok=True)
                result = self.run_helper(f"{address}\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.private_directory() / "credentials.cbor").exists())
                self.assertFalse(self.capture.exists())
                private = self.private_directory()
                self.assertTrue((private / "ssid.bin").is_file())
                self.assertTrue((private / "psk.bin").is_file())
                self.assertFalse(any(private.glob(".prepare.*")))

    def test_generator_or_validator_failure_cleans_staging_and_output(self) -> None:
        for component in ("go", "validator"):
            with self.subTest(component=component):
                result = self.run_helper("192.0.2.10\n", fail=component)
                self.assertNotEqual(result.returncode, 0)
                private = self.private_directory()
                self.assertFalse((private / "credentials.cbor").exists())
                self.assertTrue((private / "ssid.bin").is_file())
                self.assertTrue((private / "psk.bin").is_file())
                self.assertFalse(any(private.glob(".prepare.*")))

    def test_rejects_missing_or_non_private_source_files(self) -> None:
        private = self.private_directory()
        (private / "psk.bin").unlink()
        missing = self.run_helper("192.0.2.10\n")
        self.assertNotEqual(missing.returncode, 0)
        self.assertFalse(self.capture.exists())
        (private / "psk.bin").write_bytes(b"private-passphrase")
        (private / "psk.bin").chmod(0o644)
        readable = self.run_helper("192.0.2.10\n")
        self.assertNotEqual(readable.returncode, 0)
        self.assertFalse(self.capture.exists())

    def test_rejects_command_line_values(self) -> None:
        result = self.run_helper(
            "192.0.2.10\n", arguments=("--ssid", "must-not-be-accepted")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.capture.exists())
        private = self.private_directory()
        self.assertTrue((private / "ssid.bin").is_file())
        self.assertTrue((private / "psk.bin").is_file())
        self.assertFalse((private / "credentials.cbor").exists())

    def test_publish_race_does_not_remove_other_output(self) -> None:
        result = self.run_helper("192.0.2.10\n", fail="race")
        self.assertNotEqual(result.returncode, 0)
        record = self.private_directory() / "credentials.cbor"
        self.assertEqual(record.read_bytes(), b"racer")
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertEqual(
            sorted(path.name for path in record.parent.iterdir()),
            ["credentials.cbor", "psk.bin", "ssid.bin"],
        )


if __name__ == "__main__":
    unittest.main()
