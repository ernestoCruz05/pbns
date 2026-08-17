import importlib.util
import json
import os
import pathlib
import tempfile
import unittest


class SecureBootRuntimeDriverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).resolve().parents[2]
        self.driver_path = (
            self.pbns_root / "integration" / "qemu" / "secureboot-runtime-driver.py"
        )
        self.assertTrue(self.driver_path.is_file())
        spec = importlib.util.spec_from_file_location(
            "secureboot_runtime_driver", self.driver_path
        )
        assert spec is not None and spec.loader is not None
        self.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.driver)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="task14c-secureboot-", dir=self.pbns_root / "integration" / "state"
        )
        self.root = pathlib.Path(self.temporary.name)
        self.root.chmod(0o700)
        self.code = self._file("OVMF_CODE.fd", b"code")
        self.variables = self._file("OVMF_VARS.fd", b"vars")
        self.esp = self.root / "esp"
        self.esp.mkdir(mode=0o700)
        self.log = self.root / "signed-secureboot-runtime.log"
        self.args_record = self.root / "arguments.json"
        self.fake = self.root / "fake-qemu"
        self.fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, signal, sys, time\n"
            "pathlib.Path(os.environ['PBNS_FAKE_ARGS']).write_text(json.dumps(sys.argv[1:]))\n"
            "mode = os.environ.get('PBNS_FAKE_MODE', 'valid')\n"
            "if mode == 'forbidden':\n"
            "    print('enrollment_token=must-not-be-retained')\n"
            "elif mode == 'overflow':\n"
            "    print('X' * 8192)\n"
            "else:\n"
            "    print('PBNS-SB-BEGIN-SecureBoot')\n"
            "    print(\"Variable 'EFIGlobalVariable:SecureBoot' DataSize = 0x01\")\n"
            "    print('  00000000: 01')\n"
            "    print('PBNS-SB-END-SecureBoot')\n"
            "    print('PBNS-SB-BEGIN-SetupMode')\n"
            "    print(\"Variable 'EFIGlobalVariable:SetupMode' DataSize = 0x01\")\n"
            "    print('  00000000: 00')\n"
            "    print('PBNS-SB-END-SetupMode', flush=True)\n"
            "    if mode == 'stubborn':\n"
            "        signal.signal(signal.SIGTERM, lambda *_: None)\n"
            "        while True: time.sleep(1)\n",
            encoding="ascii",
        )
        self.fake.chmod(0o700)
        self.previous_args = os.environ.get("PBNS_FAKE_ARGS")
        self.previous_mode = os.environ.get("PBNS_FAKE_MODE")
        os.environ["PBNS_FAKE_ARGS"] = str(self.args_record)
        os.environ.pop("PBNS_FAKE_MODE", None)

    def tearDown(self) -> None:
        if self.previous_args is None:
            os.environ.pop("PBNS_FAKE_ARGS", None)
        else:
            os.environ["PBNS_FAKE_ARGS"] = self.previous_args
        if self.previous_mode is None:
            os.environ.pop("PBNS_FAKE_MODE", None)
        else:
            os.environ["PBNS_FAKE_MODE"] = self.previous_mode
        self.temporary.cleanup()

    def _file(self, name: str, contents: bytes) -> pathlib.Path:
        path = self.root / name
        path.write_bytes(contents)
        path.chmod(0o600)
        return path

    def _arguments(self):
        return self.driver.parser().parse_args(
            [
                "--case-root",
                str(self.root),
                "--code",
                str(self.code),
                "--variables",
                str(self.variables),
                "--esp",
                str(self.esp),
                "--log",
                str(self.log),
            ]
        )

    def test_uses_the_exact_case_variables_and_accepts_exact_runtime_state(self) -> None:
        self.driver.run(
            self._arguments(), executable=str(self.fake), deadline_seconds=2.0
        )
        arguments = json.loads(self.args_record.read_text(encoding="utf-8"))
        self.assertIn(f"if=pflash,format=raw,file={self.variables}", arguments)
        self.assertIn(
            f"if=pflash,format=raw,readonly=on,file={self.code}", arguments
        )
        self.assertIn(f"format=raw,file=fat:rw:{self.esp}", arguments)
        self.assertIn("-nic", arguments)
        self.assertIn("none", arguments)
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)
        self.driver.validate_serial(
            self.log.read_text(encoding="utf-8", errors="strict")
        )

    def test_forbidden_output_retains_only_a_generic_private_diagnostic(self) -> None:
        os.environ["PBNS_FAKE_MODE"] = "forbidden"
        with self.assertRaises(SystemExit):
            self.driver.run(
                self._arguments(), executable=str(self.fake), deadline_seconds=2.0
            )
        self.assertEqual(
            self.log.read_bytes(), b"PBNS SECUREBOOT RUNTIME REJECT\n"
        )
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)

    def test_output_overflow_is_bounded_and_rejected(self) -> None:
        os.environ["PBNS_FAKE_MODE"] = "overflow"
        self.driver.OUTPUT_CAP = 64
        with self.assertRaises(SystemExit):
            self.driver.run(
                self._arguments(), executable=str(self.fake), deadline_seconds=2.0
            )
        self.assertLessEqual(self.log.stat().st_size, 64)

    def test_stubborn_qemu_teardown_is_bounded(self) -> None:
        os.environ["PBNS_FAKE_MODE"] = "stubborn"
        import time

        began = time.monotonic()
        with self.assertRaises(SystemExit):
            self.driver.run(
                self._arguments(),
                executable=str(self.fake),
                deadline_seconds=0.05,
                term_timeout=0.05,
                kill_timeout=1.0,
            )
        self.assertLess(time.monotonic() - began, 1.5)

    def test_rejects_an_unrelated_variable_store_before_qemu(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outside = pathlib.Path(directory) / "OVMF_VARS.fd"
            outside.write_bytes(b"vars")
            outside.chmod(0o600)
            arguments = self._arguments()
            arguments.variables = outside
            with self.assertRaises(SystemExit):
                self.driver.run(
                    arguments, executable=str(self.fake), deadline_seconds=2.0
                )
        self.assertFalse(self.args_record.exists())
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
