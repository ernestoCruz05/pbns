import importlib.util
import inspect
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


class RecoveryLiveDriverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).resolve().parents[2]
        self.driver_path = (
            self.pbns_root / "integration" / "qemu" / "recovery-live-driver.py"
        )
        self.assertTrue(self.driver_path.is_file())
        spec = importlib.util.spec_from_file_location("recovery_live_driver", self.driver_path)
        assert spec is not None and spec.loader is not None
        self.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.driver)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="task14c-driver-", dir=self.pbns_root / "integration" / "state"
        )
        self.root = pathlib.Path(self.temporary.name)
        self.root.chmod(0o700)
        self.original_path = os.environ.get("PATH", "")
        (self.root / "swtpm").symlink_to(sys.executable)
        os.environ["PATH"] = f"{self.root}:{self.original_path}"
        self.code = self._file("OVMF_CODE.fd", b"code")
        self.variables = self._file("OVMF_VARS.fd", b"vars")
        self.disk = self._file("disk.raw", b"\x00" * 4096)
        self.esp = self.root / "esp"
        self.esp.mkdir(mode=0o700)
        self.swtpm_state = self.root / "swtpm-state"
        self.swtpm_state.mkdir(mode=0o700)
        (self.swtpm_state / "tpm").mkdir(mode=0o700)
        (self.swtpm_state / "managed").write_text("PBNS_SWTPM_STATE_V1\n")
        (self.swtpm_state / "managed").chmod(0o600)
        self.runtime = pathlib.Path(tempfile.gettempdir()) / (
            "pbns-swtpm." + secrets.token_hex(8)
        )
        self.runtime.mkdir(mode=0o700)
        self.server_socket = socket.socket(socket.AF_UNIX)
        self.control_socket = socket.socket(socket.AF_UNIX)
        self.socket_path = self.runtime / "server.sock"
        self.control_path = pathlib.Path(f"{self.socket_path}.ctrl")
        self.server_socket.bind(str(self.socket_path))
        self.control_socket.bind(str(self.control_path))
        self.socket_path.chmod(0o600)
        self.control_path.chmod(0o600)
        (self.swtpm_state / "socket.path").write_text(f"{self.socket_path}\n")
        (self.swtpm_state / "socket.path").chmod(0o600)
        fake_swtpm = self.root / "fake-swtpm.py"
        fake_swtpm.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, threading\n"
            "pathlib.Path(os.environ['PBNS_FAKE_SWTPM_READY']).write_text('ready')\n"
            "threading.Event().wait()\n",
            encoding="utf-8",
        )
        fake_swtpm.chmod(0o700)
        ready = self.root / "fake-swtpm.ready"
        state_argument = f"dir={self.swtpm_state / 'tpm'},mode=0600"
        self.swtpm = subprocess.Popen(
            ["swtpm", str(fake_swtpm), state_argument],
            executable=sys.executable,
            env={**os.environ, "PBNS_FAKE_SWTPM_READY": str(ready)},
        )
        start_time = self._wait_for_fake_swtpm_exec(
            ready, fake_swtpm, state_argument
        )
        (self.swtpm_state / "swtpm.pid").write_text(f"{self.swtpm.pid}\n")
        (self.swtpm_state / "swtpm.pid").chmod(0o600)
        (self.swtpm_state / "owner.pid").write_text("2\n")
        (self.swtpm_state / "owner.pid").chmod(0o600)
        (self.swtpm_state / "runtime.path").write_text(f"{self.runtime}\n")
        (self.swtpm_state / "runtime.path").chmod(0o600)
        record = subprocess.run(
            [
                str(self.pbns_root / "integration" / "swtpm" / "quiesce-swtpm-runtime.py"),
                "--record",
                str(self.swtpm.pid),
                str(pathlib.Path(shutil.which("swtpm") or "").resolve()),
                str(self.swtpm_state),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(record.returncode, 0, record.stderr)
        identity = json.loads(
            (self.swtpm_state / "process.identity").read_text(encoding="ascii")
        )
        self.assertEqual(identity["start"], start_time)
        self.args_record = self.root / "args.json"
        self.input_record = self.root / "input.bin"
        self.fake_qemu = self.root / "fake-qemu.py"
        self.fake_qemu.write_text(
            """#!/usr/bin/env python3
import json, os, pathlib, sys, time
pathlib.Path(os.environ['PBNS_FAKE_ARGS']).write_text(json.dumps(sys.argv[1:]))
phase = os.environ['PBNS_FAKE_PHASE']
case = os.environ['PBNS_FAKE_CASE']
received = bytearray()
def emit(value):
    sys.stdout.buffer.write(value); sys.stdout.buffer.flush(); time.sleep(0.01)
def take(count):
    value = sys.stdin.buffer.read(count); received.extend(value)
if phase == 'recovery':
    emit(b'Type REC'); emit(b'OVER to download a RAM-only recovery image: ')
    take(8)
    emit(b'Select recovery assurance: T/t'); emit(b' or S/s: ')
    take(1)
    if case == 'signed-trusted':
        emit(b'PBNS RECOVERY MEMORY LOAD BEGIN size=1 version=7\\r\\n')
        emit(b'PBNS RECOVERY MEMORY LOAD PASS\\r\\n')
        emit(b'PBNS RECOVERY ROLLBACK ADVANCE BEGIN current=5 target=7\\r\\n')
        emit(b'PBNS RECOVERY ROLLBACK ADVANCE PASS\\r\\n')
        emit(b'PBNS RECOVERY STARTIMAGE BEGIN\\r\\n')
        emit(b'PBNS RECOVERY READ-ONLY MODE\\r\\n')
    else:
        stage = {'unsigned-untrusted': 6, 'truncated': 6, 'gateway-interruption': 4,
                 'forged-manifest': 2, 'forged-digest': 5, 'forged-chunk': 4,
                 'downgrade': 5}[case]
        status = -15 if case == 'downgrade' else -8
        emit(b'PBNS RECOVERY FREE BEGIN size=1\\r\\n')
        emit(b'PBNS RECOVERY FREE PASS\\r\\n')
        emit(b'PBNS RECOVERY STATE 9\\r\\n')
        emit(f'PBNS RECOVERY FAILED stage={stage} status={status}\\r\\n'.encode())
elif phase == 'launcher-setup':
    emit(b'Select the existing normal boot option:\\r\\n  [3] Boot0001 PBNS Normal')
    emit(b' Fixture\\r\\n> '); take(2)
    emit(b'PBNS BOOT SETUP PASS normal=Boot0001 recovery=Boot0002\\r\\n')
else:
    emit(b'PBNS NORMAL FIXTURE PASS\\r\\n')
    emit(b'PBNS RECOVERY FALLBACK stage=4 loader_status=8000000000000015\\r\\n')
    emit(b'Type RECOVER to download a RAM-only recovery image: ')
pathlib.Path(os.environ['PBNS_FAKE_INPUT']).write_bytes(received)
""",
            encoding="utf-8",
        )
        self.fake_qemu.chmod(0o700)

    def _wait_for_fake_swtpm_exec(
        self,
        ready: pathlib.Path,
        fake_swtpm: pathlib.Path,
        state_argument: str,
    ) -> str:
        deadline = time.monotonic() + 2.0
        expected_executable = pathlib.Path(shutil.which("swtpm") or "").resolve()
        while time.monotonic() < deadline:
            try:
                command_line = pathlib.Path(f"/proc/{self.swtpm.pid}/cmdline").read_bytes()
                encoded_stat = pathlib.Path(f"/proc/{self.swtpm.pid}/stat").read_bytes()
                start_time = encoded_stat.rsplit(b") ", 1)[1].split()[19].decode("ascii")
                executable = pathlib.Path(f"/proc/{self.swtpm.pid}/exe").resolve(
                    strict=True
                )
                if (
                    ready.read_text(encoding="ascii") == "ready"
                    and executable == expected_executable
                    and str(fake_swtpm).encode() in command_line.split(b"\0")
                    and state_argument.encode() in command_line.split(b"\0")
                    and start_time.isdecimal()
                ):
                    return start_time
            except (OSError, IndexError, UnicodeDecodeError):
                pass
            time.sleep(0.01)
        self.fail("fake swtpm did not exec with a verifiable process identity")

    def tearDown(self) -> None:
        os.environ["PATH"] = self.original_path
        if self.swtpm.poll() is None:
            self.swtpm.terminate()
            self.swtpm.wait(timeout=5)
        self.server_socket.close()
        self.control_socket.close()
        for path in (self.socket_path, self.control_path):
            path.unlink(missing_ok=True)
        self.runtime.rmdir()
        self.temporary.cleanup()

    def _file(self, name: str, content: bytes) -> pathlib.Path:
        path = self.root / name
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def _arguments(self, case: str, phase: str, pico: str = "present"):
        log = self.root / f"{case}-{phase}.log"
        return self.driver.parser().parse_args(
            [
                "--case-root", str(self.root), "--case", case,
                "--phase", phase, "--code", str(self.code),
                "--variables", str(self.variables), "--esp", str(self.esp),
                "--swtpm-state", str(self.swtpm_state), "--disk", str(self.disk),
                "--log", str(log), "--pico", pico,
            ]
        )

    def _run(self, case: str, phase: str, pico: str = "present") -> bytes:
        old = os.environ.copy()
        os.environ.update(
            {
                "PBNS_FAKE_ARGS": str(self.args_record),
                "PBNS_FAKE_INPUT": str(self.input_record),
                "PBNS_FAKE_PHASE": phase,
                "PBNS_FAKE_CASE": case,
            }
        )
        try:
            self.driver.run(
                self._arguments(case, phase, pico),
                executable=str(self.fake_qemu),
                pico_validator=lambda: None,
                deadline_seconds=5,
            )
        finally:
            os.environ.clear()
            os.environ.update(old)
        return self.input_record.read_bytes()

    def test_runtime_deadline_outlives_the_gateway_transfer_window(self) -> None:
        parameter = inspect.signature(self.driver.run).parameters["deadline_seconds"]
        self.assertEqual(parameter.default, 2760.0)

    def test_sigterm_cooperatively_reaps_qemu_and_retains_audited_log(self) -> None:
        child_pid = self.root / "fake-qemu.pid"
        self.fake_qemu.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, signal, time\n"
            "pathlib.Path(os.environ['PBNS_FAKE_QEMU_PID']).write_text(str(os.getpid()))\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('driver signal test', flush=True)\n"
            "while True: time.sleep(1)\n",
            encoding="utf-8",
        )
        self.fake_qemu.chmod(0o700)
        log = self.root / "signal-recovery.log"
        arguments = [
            "--case-root", str(self.root), "--case", "gateway-interruption",
            "--phase", "recovery", "--code", str(self.code),
            "--variables", str(self.variables), "--esp", str(self.esp),
            "--swtpm-state", str(self.swtpm_state), "--disk", str(self.disk),
            "--log", str(log), "--pico", "present",
        ]
        runner = f'''\
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("recovery_live_driver", {str(self.driver_path)!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.run(module.parser().parse_args(sys.argv[1:]), executable={str(self.fake_qemu)!r}, pico_validator=lambda: None, deadline_seconds=30)
'''
        process = subprocess.Popen(
            [sys.executable, "-c", runner, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PBNS_FAKE_QEMU_PID": str(child_pid)},
        )
        deadline = time.monotonic() + 3
        while not child_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(child_pid.is_file(), "fake QEMU did not start")
        qemu_pid = int(child_pid.read_text(encoding="ascii"))
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=self.driver.WORST_CLEANUP_SECONDS + 2)
        self.assertNotEqual(process.returncode, 0, stderr)
        self.assertLess(time.monotonic() - started, self.driver.WORST_CLEANUP_SECONDS + 2)
        for _ in range(20):
            if not pathlib.Path(f"/proc/{qemu_pid}").exists():
                break
            time.sleep(0.02)
        self.assertFalse(pathlib.Path(f"/proc/{qemu_pid}").exists(), "fake QEMU was orphaned")
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(log.read_text(encoding="utf-8"), "driver signal test\n")

    def test_forced_driver_death_kills_qemu_with_parent_death_signal(self) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("PR_SET_PDEATHSIG is Linux-specific")
        child_pid = self.root / "fake-qemu-parent-death.pid"
        self.fake_qemu.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, signal, time\n"
            "pathlib.Path(os.environ['PBNS_FAKE_QEMU_PID']).write_text(str(os.getpid()))\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('driver parent-death test', flush=True)\n"
            "while True: time.sleep(1)\n",
            encoding="utf-8",
        )
        self.fake_qemu.chmod(0o700)
        arguments = [
            "--case-root", str(self.root), "--case", "gateway-interruption",
            "--phase", "recovery", "--code", str(self.code),
            "--variables", str(self.variables), "--esp", str(self.esp),
            "--swtpm-state", str(self.swtpm_state), "--disk", str(self.disk),
            "--log", str(self.root / "parent-death.log"), "--pico", "present",
        ]
        runner = f'''\
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("recovery_live_driver", {str(self.driver_path)!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.run(module.parser().parse_args(sys.argv[1:]), executable={str(self.fake_qemu)!r}, pico_validator=lambda: None, deadline_seconds=30)
'''
        process = subprocess.Popen(
            [sys.executable, "-c", runner, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PBNS_FAKE_QEMU_PID": str(child_pid)},
        )
        deadline = time.monotonic() + 3.0
        while not child_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(child_pid.is_file(), "fake QEMU did not start")
        qemu_pid = int(child_pid.read_text(encoding="ascii"))
        encoded_stat = pathlib.Path(f"/proc/{process.pid}/stat").read_bytes()
        driver_start = encoded_stat.rsplit(b") ", 1)[1].split()[19].decode("ascii")
        terminator = self.pbns_root / "integration" / "qemu" / "terminate-child-process.py"
        started = time.monotonic()
        terminated = subprocess.run(
            [
                sys.executable, str(terminator), str(process.pid),
                str(pathlib.Path(f"/proc/{process.pid}/exe").resolve()), driver_start,
                "--term-timeout", str(self.driver.INITIAL_EXIT_WAIT_SECONDS / 4),
                "--kill-timeout", "1",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(terminated.returncode, 0, terminated.stderr)
        process.communicate(timeout=1)
        self.assertLess(time.monotonic() - started, self.driver.WORST_CLEANUP_SECONDS)
        disappearance_deadline = time.monotonic() + 2.0
        while pathlib.Path(f"/proc/{qemu_pid}").exists() and time.monotonic() < disappearance_deadline:
            time.sleep(0.02)
        self.assertFalse(
            pathlib.Path(f"/proc/{qemu_pid}").exists(),
            "fake QEMU survived forced driver death",
        )

    def test_cleanup_does_not_read_stdout_after_kill_timeout(self) -> None:
        class Stream:
            def __init__(self, read: bool = False) -> None:
                self.read_called = False
                self.closed = False
                self._read = read

            def read(self, _count: int) -> bytes:
                self.read_called = True
                raise AssertionError("live QEMU stdout must not be read")

            def close(self) -> None:
                self.closed = True

        class LiveProcess:
            def __init__(self) -> None:
                self.stdin = Stream()
                self.stdout = Stream(read=True)
                self.terminate_called = False
                self.kill_called = False

            def poll(self):
                return None

            def wait(self, *, timeout: float) -> None:
                raise subprocess.TimeoutExpired("fake-qemu", timeout)

            def terminate(self) -> None:
                self.terminate_called = True

            def kill(self) -> None:
                self.kill_called = True

        process = LiveProcess()
        failure = self.driver._cleanup_qemu(process, bytearray())
        self.assertEqual(failure, "QEMU did not exit during bounded cleanup")
        self.assertTrue(process.terminate_called)
        self.assertTrue(process.kill_called)
        self.assertFalse(process.stdout.read_called)
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)

    def test_driver_restores_prior_sigterm_handler(self) -> None:
        prior = signal.getsignal(signal.SIGTERM)
        self._run("downgrade", "recovery")
        self.assertIs(signal.getsignal(signal.SIGTERM), prior)
        with mock.patch.object(self.driver.subprocess, "Popen", side_effect=RuntimeError("launch")):
            with self.assertRaisesRegex(RuntimeError, "launch"):
                self.driver.run(
                    self._arguments("signed-trusted", "recovery"),
                    executable=str(self.fake_qemu),
                    pico_validator=lambda: None,
                )
        self.assertIs(signal.getsignal(signal.SIGTERM), prior)
        with mock.patch.object(self.driver, "_write_log", side_effect=OSError("log")):
            with self.assertRaisesRegex(OSError, "log"):
                self._run("signed-trusted", "recovery")
        self.assertIs(signal.getsignal(signal.SIGTERM), prior)

    def test_driver_rejects_non_main_thread_before_installing_handler(self) -> None:
        errors: list[BaseException] = []

        def invoke() -> None:
            try:
                self.driver.run(
                    self._arguments("downgrade", "recovery"),
                    executable=str(self.fake_qemu),
                    pico_validator=lambda: None,
                )
            except BaseException as error:
                errors.append(error)

        with mock.patch.object(self.driver.signal, "signal") as install_handler:
            thread = threading.Thread(target=invoke)
            thread.start()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive(), "non-main-thread driver call did not return")
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], SystemExit)
        self.assertIn("main thread", str(errors[0]))
        install_handler.assert_not_called()

    def test_recovery_failure_terminal_is_accepted_after_prompts_and_cleanup(self) -> None:
        self.assertEqual(self._run("downgrade", "recovery"), b"RECOVER\rT")
        output = (self.root / "downgrade-recovery.log").read_bytes()
        self.assertLess(output.index(b"PBNS RECOVERY FREE BEGIN"), output.index(b"PBNS RECOVERY FREE PASS"))
        self.assertLess(output.index(b"PBNS RECOVERY FREE PASS"), output.index(b"PBNS RECOVERY STATE 9"))
        self.assertLess(output.index(b"PBNS RECOVERY STATE 9"), output.index(b"PBNS RECOVERY FAILED stage=5 status=-15"))

    def test_recovery_waits_for_both_exact_prompts_and_never_selects_s(self) -> None:
        self.assertEqual(self._run("signed-trusted", "recovery"), b"RECOVER\rT")
        arguments = json.loads(self.args_record.read_text())
        joined = " ".join(arguments)
        self.assertIn("q35,accel=tcg", arguments)
        self.assertIn("-nic none", joined)
        self.assertNotIn("-enable-kvm", arguments)
        self.assertIn("vendorid=0xcafe,productid=0x4011", joined)
        self.assertIn("read-only=on", joined)

    def test_launcher_setup_uses_the_unique_displayed_normal_index(self) -> None:
        self.assertEqual(self._run("normal-launcher", "launcher-setup"), b"3\r")

    def test_launcher_run_sends_nothing_and_stops_at_ordered_oracle(self) -> None:
        self.assertEqual(self._run("pico-absent", "launcher-run", "absent"), b"")
        arguments = json.loads(self.args_record.read_text())
        self.assertFalse(any("usb-host" in argument for argument in arguments))

    def test_rejects_incompatible_phase_case_and_pico_pairs(self) -> None:
        for case, phase, pico in (
            ("signed-trusted", "launcher-run", "present"),
            ("normal-launcher", "recovery", "present"),
            ("pico-absent", "launcher-run", "present"),
            ("signed-trusted", "recovery", "absent"),
        ):
            with self.subTest(case=case, phase=phase, pico=pico):
                with self.assertRaises(SystemExit):
                    self.driver.validate(self._arguments(case, phase, pico))

    def test_rejects_paths_outside_root_symlinks_modes_and_devices(self) -> None:
        args = self._arguments("signed-trusted", "recovery")
        outside = pathlib.Path(tempfile.mkstemp(prefix="task14c-outside-")[1])
        try:
            outside.chmod(0o600)
            args.disk = outside
            with self.assertRaises(SystemExit):
                self.driver.validate(args)
        finally:
            outside.unlink()
        link = self.root / "disk-link"
        link.symlink_to(self.disk)
        args = self._arguments("signed-trusted", "recovery")
        args.disk = link
        with self.assertRaises(SystemExit):
            self.driver.validate(args)
        self.variables.chmod(0o644)
        with self.assertRaises(SystemExit):
            self.driver.validate(self._arguments("signed-trusted", "recovery"))
        self.variables.chmod(0o600)

    def test_rejects_missing_control_socket_and_unverified_swtpm_pid(self) -> None:
        self.control_socket.close()
        self.control_path.unlink()
        with self.assertRaises(SystemExit):
            self.driver.validate(self._arguments("signed-trusted", "recovery"))
        self.control_socket = socket.socket(socket.AF_UNIX)
        self.control_socket.bind(str(self.control_path))
        self.control_path.chmod(0o600)
        (self.swtpm_state / "swtpm.pid").write_text(f"{os.getpid()}\n")
        (self.swtpm_state / "swtpm.pid").chmod(0o600)
        with self.assertRaises(SystemExit):
            self.driver.validate(self._arguments("signed-trusted", "recovery"))

    def test_gateway_readiness_requires_verified_identity_before_qemu(self) -> None:
        matrix = self.pbns_root / "integration" / "qemu" / "run-recovery-matrix.sh"
        source = matrix.read_text(encoding="utf-8")
        self.assertEqual(source.count('gateway_expected_executable=$(readlink -f "$private_dir/pbns-gateway") || fail'), 2)
        self.assertEqual(source.count("gateway_ready=1"), 2)
        self.assertEqual(source.count('[[ $gateway_ready -eq 1 && -n $gateway_executable && -n $gateway_start ]] || fail'), 2)
        self.assertEqual(source.count('[[ $(readlink -f "/proc/$gateway_pid/exe" 2>/dev/null) == "$gateway_executable" ]] || fail'), 2)
        self.assertNotIn('gateway_executable=$(readlink -f "/proc/$pid/exe")', source)
        self.assertIn('kill -TERM -- "$pid" 2>/dev/null || true', source)
        ready = [index for index in range(len(source)) if source.startswith("gateway_ready=1", index)]
        assertions = [index for index in range(len(source)) if source.startswith('[[ $gateway_ready -eq 1 && -n $gateway_executable && -n $gateway_start ]] || fail', index)]
        production_qemu = [index for index in range(len(source)) if source.startswith('python3 "$script_dir/recovery-live-driver.py"', index)]
        self.assertEqual(len(ready), len(assertions))
        self.assertEqual(len(production_qemu), 4)
        self.assertTrue(all(before < after < launch for before, after, launch in zip(ready, assertions, production_qemu[:2])))

        evaluation_start = source.index("start_evaluation_gateway() {")
        evaluation_driver = source.index("start_evaluation_driver() {")
        self.assertLess(evaluation_start, evaluation_driver)
        self.assertIn("verify_gateway_command_identity", source[evaluation_start:evaluation_driver])
        self.assertIn('[[ $gateway_ready -eq 1 ]] || fail', source[evaluation_start:evaluation_driver])

    def test_evaluation_driver_reaps_zombies_without_proc_identity_and_runner_waits_for_cleanup(self) -> None:
        matrix = self.pbns_root / "integration" / "qemu" / "run-recovery-matrix.sh"
        source = matrix.read_text(encoding="utf-8")
        start = source.index("wait_evaluation_driver() {")
        end = source.index("\nrun_evaluation_fault_case() {", start)
        function = source[start:end]
        self.assertIn('if ! child_stopped "$pid"; then', function)
        self.assertIn('child_stopped "$pid" || fail', function)
        self.assertLess(function.index('if ! child_stopped "$pid"; then'), function.index('python3 - "$pid"'))
        self.assertIn('wait "$pid" || fail', function)
        timeout = re.search(r"^driver_term_timeout=([0-9.]+)$", source, re.MULTILINE)
        self.assertIsNotNone(timeout)
        assert timeout is not None
        self.assertGreater(float(timeout.group(1)), self.driver.WORST_CLEANUP_SECONDS)
        self.assertIn('--term-timeout "$driver_term_timeout"', source)
        self.assertLess(source.index("if ! terminate_gateway"), source.index("if ! terminate_driver"))

    def test_qemu_output_has_a_process_file_size_limit(self) -> None:
        source = self.driver_path.read_text(encoding="utf-8")
        self.assertIn("resource.RLIMIT_FSIZE", source)
        self.assertIn("64 * 1024 * 1024", source)

    def test_exact_pico_validator_rejects_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            device = root / "1-1"
            device.mkdir()
            for name, value in {
                "idVendor": "cafe\n", "idProduct": "4011\n",
                "serial": "wrong\n", "product": "PBNS Proxy v1\n",
            }.items():
                (device / name).write_text(value)
            with self.assertRaises(SystemExit):
                self.driver.verify_pico(root)


if __name__ == "__main__":
    unittest.main()
