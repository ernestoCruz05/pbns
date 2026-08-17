import importlib.util
import json
import os
import pathlib
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest


class RecoveryPolicyGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).resolve().parents[2]
        self.script = (
            self.pbns_root / "integration" / "swtpm" / "run-recovery-policy.sh"
        )
        self.swtpm_root = self.pbns_root / "integration" / "swtpm"
        self.pause_script = self.swtpm_root / "pause-swtpm.sh"
        self.resume_script = self.swtpm_root / "resume-swtpm.sh"
        self.start_script = self.swtpm_root / "start-swtpm.sh"
        self.stop_script = self.swtpm_root / "stop-swtpm.sh"
        self.live_policy_script = self.swtpm_root / "run-recovery-policy-live.sh"
        self.terminate_child = (
            self.pbns_root / "integration" / "qemu" / "terminate-child-process.py"
        )

    def test_gate_is_disposable_swtpm_only(self) -> None:
        self.assertTrue(self.script.is_file())
        self.assertTrue(os.access(self.script, os.X_OK))
        source = self.script.read_text(encoding="utf-8")
        for required in (
            "PBNS_RECOVERY_NV_INDEX=0x01801000",
            'TPM2TOOLS_TCTI="swtpm:path=$socket_path"',
            "integration/state/",
            "umask 077",
            "mkdir -m 0700",
            "install -m 0600",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        for forbidden in (
            "/dev/tpm",
            "tpm2_clear",
            "tpm2_nvundefine",
            "TPM2TOOLS_TCTI=device",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_gate_uses_public_policy_commands_and_cleans_transients(self) -> None:
        source = self.script.read_text(encoding="utf-8")
        for required in (
            "tpm2_startauthsession",
            "tpm2_policynvwritten",
            "tpm2_policynv",
            "tpm2_policycphash",
            "tpm2_loadexternal",
            "tpm2_verifysignature",
            "tpm2_policyauthorize",
            "tpm2_nvwrite",
            "tpm2_nvread",
            "tpm2_flushcontext",
            "trap cleanup EXIT",
            "initialization-replay",
            "update-replay",
            "equal-target",
            "downgrade",
            "SWTPM RECOVERY POLICY PASS current=5",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)

    def test_gate_requires_exactly_one_state_directory(self) -> None:
        completed = subprocess.run(
            [str(self.script)],
            cwd=self.pbns_root.parent,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("usage:", completed.stderr)

    def test_owned_child_termination_is_pidfd_bound_and_bounded(self) -> None:
        self.assertTrue(self.terminate_child.is_file())
        spec = importlib.util.spec_from_file_location(
            "terminate_child_process", self.terminate_child
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            child = pathlib.Path(directory) / "child.py"
            child.write_text(
                "import pathlib, signal, sys, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: None)\n"
                "pathlib.Path(sys.argv[1]).write_text('ready')\n"
                "while True: time.sleep(1)\n",
                encoding="ascii",
            )
            ready = pathlib.Path(directory) / "ready"
            process = subprocess.Popen([sys.executable, str(child), str(ready)])
            try:
                for _ in range(100):
                    if ready.is_file():
                        break
                    time.sleep(0.01)
                self.assertTrue(ready.is_file())
                executable = pathlib.Path(f"/proc/{process.pid}/exe").resolve()
                encoded = pathlib.Path(f"/proc/{process.pid}/stat").read_bytes()
                start = encoded.rsplit(b") ", 1)[1].split()[19].decode("ascii")
                began = time.monotonic()
                module.terminate(
                    process.pid,
                    executable,
                    start,
                    term_timeout=0.05,
                    kill_timeout=1.0,
                )
                self.assertLess(time.monotonic() - began, 1.5)
                self.assertEqual(process.wait(timeout=1), -9)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=1)

    def test_owned_child_termination_rejects_wrong_start_identity(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "terminate_child_process", self.terminate_child
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            executable = pathlib.Path(f"/proc/{process.pid}/exe").resolve()
            encoded = pathlib.Path(f"/proc/{process.pid}/stat").read_bytes()
            start = int(encoded.rsplit(b") ", 1)[1].split()[19])
            with self.assertRaises(module.ProcessError):
                module.terminate(
                    process.pid,
                    executable,
                    str(start + 1),
                    term_timeout=0.05,
                    kill_timeout=0.05,
                )
            self.assertIsNone(process.poll())
        finally:
            process.kill()
            process.wait(timeout=1)

    def test_start_refuses_symlink_state_without_touching_target(self) -> None:
        state_root = self.pbns_root / "integration" / "state"
        with tempfile.TemporaryDirectory(dir=state_root) as directory:
            target = pathlib.Path(directory)
            target.chmod(0o700)
            sentinel = target / "sentinel"
            sentinel.write_text("preserve\n", encoding="ascii")
            sentinel.chmod(0o600)
            link = state_root / f"task14c-start-link-{os.getpid()}"
            link.symlink_to(target, target_is_directory=True)
            try:
                process = subprocess.run(
                    [str(self.start_script), str(link)],
                    cwd=self.pbns_root.parent,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve\n")
                self.assertTrue(link.is_symlink())
            finally:
                link.unlink(missing_ok=True)

    def test_stop_refuses_unmanaged_or_symlink_state_without_deleting_it(self) -> None:
        state_root = self.pbns_root / "integration" / "state"
        state_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="task14c-unmanaged-", dir=state_root) as td:
            unmanaged = pathlib.Path(td)
            unmanaged.chmod(0o700)
            sentinel = unmanaged / "sentinel"
            sentinel.write_text("retain", encoding="utf-8")
            completed = subprocess.run(
                [str(self.stop_script), str(unmanaged)],
                cwd=self.pbns_root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "retain")
        with tempfile.TemporaryDirectory(prefix="task14c-outside-") as outside:
            sentinel = pathlib.Path(outside) / "sentinel"
            sentinel.write_text("retain", encoding="utf-8")
            link = state_root / f"task14c-stop-link-{os.getpid()}"
            try:
                link.symlink_to(outside, target_is_directory=True)
                completed = subprocess.run(
                    [str(self.stop_script), str(link)],
                    cwd=self.pbns_root.parent,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "retain")
            finally:
                link.unlink(missing_ok=True)

    def test_live_policy_helper_rejects_symlink_state(self) -> None:
        state_root = self.pbns_root / "integration" / "state"
        state_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="task14c-link-target-") as target:
            link = state_root / f"task14c-link-{os.getpid()}"
            try:
                link.symlink_to(target, target_is_directory=True)
                completed = subprocess.run(
                    [str(self.live_policy_script), "initialize", str(link), "5"],
                    cwd=self.pbns_root.parent,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
            finally:
                link.unlink(missing_ok=True)

    def test_retained_lifecycle_scripts_are_private_and_state_preserving(self) -> None:
        for script in (self.pause_script, self.resume_script):
            with self.subTest(script=script.name):
                self.assertTrue(script.is_file())
                self.assertTrue(os.access(script, os.X_OK))
                source = script.read_text(encoding="utf-8")
                for marker in ("integration/state/", "PBNS_SWTPM_STATE_V1", "swtpm"):
                    self.assertIn(marker, source)
        quiesce = self.swtpm_root / "quiesce-swtpm-runtime.py"
        source = quiesce.read_text(encoding="utf-8")
        for marker in ("process.identity", "pause.intent", "O_NOFOLLOW", "dir_fd", "runtime.path", "socket.path", "/proc/{pid}", "unexpected runtime inventory"):
            self.assertIn(marker, source)
        self.assertNotIn('rm -rf -- "$state_dir"', self.pause_script.read_text())
        self.assertIn("dir=$state_dir/tpm,mode=0600", self.resume_script.read_text())

    def test_scripts_record_and_exclude_durable_process_identity(self) -> None:
        for script in (self.start_script, self.resume_script, self.pause_script, self.stop_script):
            with self.subTest(script=script.name):
                self.assertIn("process.identity", script.read_text(encoding="utf-8"))
        prepare = self.pbns_root / "integration" / "qemu" / "prepare-recovery-live-state.sh"
        self.assertIn("process.identity", prepare.read_text(encoding="utf-8"))
        self.assertIn("pause.intent", prepare.read_text(encoding="utf-8"))

    def test_retained_lifecycle_preserves_nv_bytes(self) -> None:
        required = (
            "swtpm",
            "tpm2_getcap",
            "tpm2_nvdefine",
            "tpm2_nvwrite",
            "tpm2_nvread",
        )
        if any(shutil.which(tool) is None for tool in required):
            self.skipTest("swtpm/tpm2-tools unavailable")
        state_root = self.pbns_root / "integration" / "state"
        state_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="task14c-lifecycle-", dir=state_root) as td:
            state = pathlib.Path(td) / "state"
            script = f"""
set -euo pipefail
{self.start_script!s} {state!s}
export TPM2TOOLS_TCTI="swtpm:path=$(<\"{state!s}/socket.path\")"
tpm2_nvdefine 0x01801100 -C o -s 8 -g sha256 -a 'ownerread|ownerwrite'
printf '\\x50\\x42\\x4e\\x53\\x00\\x00\\x00\\x01' >"{state!s}/value.bin"
tpm2_nvwrite 0x01801100 -C o -i "{state!s}/value.bin"
{self.pause_script!s} {state!s}
{self.resume_script!s} {state!s}
export TPM2TOOLS_TCTI="swtpm:path=$(<\"{state!s}/socket.path\")"
tpm2_nvread 0x01801100 -C o -s 8 -o "{state!s}/actual.bin"
cmp "{state!s}/value.bin" "{state!s}/actual.bin"
{self.stop_script!s} {state!s}
"""
            completed = subprocess.run(
                ["bash", "-c", script],
                cwd=self.pbns_root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )
            if state.exists():
                subprocess.run(
                    [str(self.stop_script), str(state)],
                    cwd=self.pbns_root.parent,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            self.assertEqual(
                completed.returncode,
                0,
                msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            )

    def test_pause_rejects_tampered_clean_exit_metadata_without_signalling_reused_pid(self) -> None:
        state_root = self.pbns_root / "integration" / "state"
        state_root.mkdir(mode=0o700, exist_ok=True)

        def make_state(directory: pathlib.Path, process_pid: str = "999999999", process_start: str = "1") -> tuple[pathlib.Path, pathlib.Path]:
            state = directory / "state"
            (state / "tpm").mkdir(parents=True)
            state.chmod(0o700)
            (state / "tpm").chmod(0o700)
            runtime = pathlib.Path(tempfile.mkdtemp(prefix="pbns-swtpm."))
            runtime.chmod(0o700)
            metadata = {
                "managed": "PBNS_SWTPM_STATE_V1\n",
                "owner.pid": "2\n",
                "process.identity": json.dumps({"version": 1, "pid": int(process_pid), "start": process_start, "executable": str(pathlib.Path(shutil.which("swtpm") or "/bin/true").resolve()), "state": f"dir={state}/tpm,mode=0600"}, sort_keys=True) + "\n",
                "runtime.path": str(runtime) + "\n",
                "socket.path": str(runtime / "server.sock") + "\n",
            }
            for name, value in metadata.items():
                path = state / name
                path.write_text(value, encoding="utf-8")
                path.chmod(0o600)
            return state, runtime

        def pause(state: pathlib.Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run([str(self.pause_script), str(state)], cwd=self.pbns_root.parent, text=True, capture_output=True, check=False)

        with tempfile.TemporaryDirectory(prefix="task14c-tamper-", dir=state_root) as td:
            root = pathlib.Path(td)
            for name in ("malformed", "partial-identity", "forged-executable", "wrong-mode", "symlink", "outside-intent", "device-mismatch", "inode-mismatch", "runtime-symlink", "unexpected-entry", "mixed-socket", "unequal-pid"):
                case = root / name
                case.mkdir(mode=0o700)
                state, runtime = make_state(case)
                replacement: pathlib.Path | None = None
                try:
                    if name == "malformed":
                        (state / "process.identity").write_text("not-json\n", encoding="ascii")
                    elif name == "partial-identity":
                        (state / "process.identity").write_text("{}\n", encoding="ascii")
                    elif name == "forged-executable":
                        identity = json.loads((state / "process.identity").read_text(encoding="ascii"))
                        identity["executable"] = "/bin/true"
                        (state / "process.identity").write_text(json.dumps(identity) + "\n", encoding="ascii")
                    elif name == "wrong-mode":
                        (state / "process.identity").chmod(0o644)
                    elif name == "symlink":
                        target = state / "pid-target"
                        target.write_text("999999999\n", encoding="ascii")
                        target.chmod(0o600)
                        (state / "process.identity").unlink()
                        (state / "process.identity").symlink_to(target)
                    elif name == "outside-intent":
                        victim_fd, victim_name = tempfile.mkstemp(prefix="task14c-victim-")
                        os.close(victim_fd)
                        victim = pathlib.Path(victim_name)
                        victim.write_text("preserve", encoding="ascii")
                        identity = json.loads((state / "process.identity").read_text(encoding="ascii"))
                        (state / "pause.intent").write_text(json.dumps({"version": 1, "identity": identity, "runtime": str(victim), "socket": str(victim / "server.sock"), "device": 1, "inode": 1, "quarantine": ".pbns-swtpm-quarantine.0123456789abcdef"}) + "\n", encoding="ascii")
                        (state / "pause.intent").chmod(0o600)
                    elif name in ("device-mismatch", "inode-mismatch"):
                        identity = json.loads((state / "process.identity").read_text(encoding="ascii"))
                        victim = runtime / "victim"
                        victim.write_text("preserve", encoding="ascii")
                        runtime_stat = runtime.stat()
                        intent = {
                            "version": 1,
                            "identity": identity,
                            "runtime": str(runtime),
                            "socket": str(runtime / "server.sock"),
                            "device": runtime_stat.st_dev + (1 if name == "device-mismatch" else 0),
                            "inode": runtime_stat.st_ino + (1 if name == "inode-mismatch" else 0),
                            "quarantine": ".pbns-swtpm-quarantine.0123456789abcdef",
                        }
                        (state / "pause.intent").write_text(json.dumps(intent) + "\n", encoding="ascii")
                        (state / "pause.intent").chmod(0o600)
                    elif name == "runtime-symlink":
                        replacement = pathlib.Path(tempfile.mkdtemp(prefix="pbns-swtpm."))
                        runtime.rmdir()
                        runtime.symlink_to(replacement, target_is_directory=True)
                    elif name == "unexpected-entry":
                        (runtime / "surprise").write_text("x", encoding="ascii")
                    elif name == "mixed-socket":
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sock.bind(str(runtime / "server.sock"))
                        sock.close()
                    else:
                        (state / "swtpm.pid").write_text("999999998\n", encoding="ascii")
                        (state / "swtpm.pid").chmod(0o600)
                    attempt = pause(state)
                    self.assertNotEqual(attempt.returncode, 0, name)
                    self.assertTrue(state.exists(), name)
                    if name == "outside-intent":
                        self.assertEqual(victim.read_text(encoding="ascii"), "preserve")
                        victim.unlink()
                    if name in ("device-mismatch", "inode-mismatch"):
                        self.assertEqual(attempt.stdout, "", name)
                        self.assertEqual(victim.read_text(encoding="ascii"), "preserve", name)
                        self.assertTrue(runtime.is_dir(), name)
                        self.assertFalse((state / "paused").exists(), name)
                finally:
                    if runtime.is_symlink():
                        runtime.unlink()
                    shutil.rmtree(runtime, ignore_errors=True)
                    if replacement is not None:
                        shutil.rmtree(replacement, ignore_errors=True)
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            try:
                encoded = pathlib.Path(f"/proc/{process.pid}/stat").read_bytes()
                actual_start = int(encoded.rsplit(b") ", 1)[1].split()[19])
                case = root / "pid-reused"
                case.mkdir(mode=0o700)
                state, runtime = make_state(case, str(process.pid), str(actual_start + 1))
                try:
                    self.assertNotEqual(pause(state).returncode, 0)
                    self.assertIsNone(process.poll())
                finally:
                    shutil.rmtree(runtime, ignore_errors=True)
            finally:
                process.kill()
                process.wait(timeout=1)

    def test_start_record_failure_terminates_exact_daemon_without_orphan(self) -> None:
        if any(shutil.which(tool) is None for tool in ("swtpm", "tpm2_getcap")):
            self.skipTest("swtpm/tpm2-tools unavailable")
        state_root = self.pbns_root / "integration" / "state"
        state_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="task14c-record-fail-", dir=state_root) as td:
            state = pathlib.Path(td) / "state"
            completed = subprocess.run([str(self.start_script), str(state)], cwd=self.pbns_root.parent, text=True, capture_output=True, check=False, env={**os.environ, "PBNS_SWTPM_TEST_RECORD_FAIL": "1"})
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(state.exists())
            processes = subprocess.check_output(["ps", "-eo", "args="], text=True)
            self.assertNotIn(f"dir={state}/tpm,mode=0600", processes)

    def test_pause_recovers_clean_control_shutdown_and_preserves_nv_bytes(self) -> None:
        required = ("swtpm", "tpm2_getcap", "tpm2_nvdefine", "tpm2_nvwrite", "tpm2_nvread")
        if any(shutil.which(tool) is None for tool in required):
            self.skipTest("swtpm/tpm2-tools unavailable")
        state_root = self.pbns_root / "integration" / "state"
        state_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="task14c-clean-exit-", dir=state_root) as td:
            state = pathlib.Path(td) / "state"
            value = b"PBNS\x00\x00\x00\x0e"
            victim: subprocess.Popen[str] | None = None
            try:
                started = subprocess.run([str(self.start_script), str(state)], cwd=self.pbns_root.parent, text=True, capture_output=True, check=False)
                self.assertEqual(started.returncode, 0, started.stderr)
                socket_path = pathlib.Path((state / "socket.path").read_text(encoding="utf-8").strip())
                self.assertTrue((state / "process.identity").is_file())
                original_identity = (state / "process.identity").read_text(encoding="ascii")
                original_pid = (state / "swtpm.pid").read_text(encoding="ascii")
                environment = {**os.environ, "TPM2TOOLS_TCTI": f"swtpm:path={socket_path}"}
                subprocess.run(["tpm2_nvdefine", "0x01801101", "-C", "o", "-s", "8", "-g", "sha256", "-a", "ownerread|ownerwrite"], env=environment, check=True, capture_output=True)
                (state / "value.bin").write_bytes(value)
                subprocess.run(["tpm2_nvwrite", "0x01801101", "-C", "o", "-i", str(state / "value.bin")], env=environment, check=True, capture_output=True)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
                    control.connect(str(socket_path) + ".ctrl")
                    control.sendall(struct.pack(">I", 3))
                    control.recv(4)
                original_pid_number = int(original_pid.strip())
                for _ in range(100):
                    if (not (state / "swtpm.pid").exists() and not socket_path.exists()
                            and not pathlib.Path(str(socket_path) + ".ctrl").exists()
                            and not pathlib.Path(f"/proc/{original_pid_number}").exists()):
                        break
                    time.sleep(0.05)
                self.assertFalse((state / "swtpm.pid").exists())
                self.assertFalse(socket_path.exists())
                self.assertFalse(pathlib.Path(str(socket_path) + ".ctrl").exists())
                self.assertFalse(pathlib.Path(f"/proc/{original_pid_number}").exists())
                victim_signal = state / "different-process-signalled"
                victim = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "import pathlib, signal, sys; "
                        "signal.signal(signal.SIGTERM, lambda *_: pathlib.Path(sys.argv[1]).write_text('TERM')); "
                        "signal.pause()",
                        str(victim_signal),
                    ]
                )
                self.assertNotEqual(victim.pid, original_pid_number)
                interrupted = subprocess.run([str(self.pause_script), str(state)], cwd=self.pbns_root.parent, text=True, capture_output=True, check=False, env={**os.environ, "PBNS_SWTPM_TEST_CRASH_STEP": "after-intent"})
                self.assertEqual(interrupted.returncode, 97)
                self.assertTrue((state / "pause.intent").is_file())
                (state / "swtpm.pid").write_text(original_pid, encoding="ascii")
                (state / "swtpm.pid").chmod(0o600)
                self.assertEqual((state / "swtpm.pid").read_text(encoding="ascii"), original_pid)
                self.assertEqual(stat.S_IMODE((state / "swtpm.pid").stat().st_mode), 0o600)
                after_quarantine = subprocess.run([str(self.pause_script), str(state)], cwd=self.pbns_root.parent, text=True, capture_output=True, check=False, env={**os.environ, "PBNS_SWTPM_TEST_CRASH_STEP": "after-quarantine"})
                self.assertEqual(after_quarantine.returncode, 97)
                self.assertIsNone(victim.poll())
                self.assertFalse(victim_signal.exists())
                marker_failed = subprocess.run([str(self.pause_script), str(state)], cwd=self.pbns_root.parent, text=True, capture_output=True, check=False, env={**os.environ, "PBNS_SWTPM_TEST_FAIL_MARKER": "1"})
                self.assertNotEqual(marker_failed.returncode, 0)
                self.assertTrue((state / "pause.intent").is_file())
                paused = subprocess.run([str(self.pause_script), str(state)], cwd=self.pbns_root.parent, text=True, capture_output=True, check=False)
                self.assertEqual(paused.returncode, 0, paused.stderr)
                self.assertTrue((state / "paused").is_file())
                self.assertFalse((state / "pause.intent").exists())
                self.assertFalse((state / "swtpm.pid").exists())
                self.assertFalse((state / "process.identity").exists())
                self.assertIsNone(victim.poll())
                self.assertFalse(victim_signal.exists())
                resumed = subprocess.run([str(self.resume_script), str(state)], cwd=self.pbns_root.parent, text=True, capture_output=True, check=False)
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                self.assertNotEqual((state / "process.identity").read_text(encoding="ascii"), original_identity)
                new_socket = pathlib.Path((state / "socket.path").read_text(encoding="utf-8").strip())
                subprocess.run(["tpm2_nvread", "0x01801101", "-C", "o", "-s", "8", "-o", str(state / "actual.bin")], env={**os.environ, "TPM2TOOLS_TCTI": f"swtpm:path={new_socket}"}, check=True, capture_output=True)
                self.assertEqual((state / "actual.bin").read_bytes(), value)
            finally:
                if victim is not None and victim.poll() is None:
                    victim.kill()
                    victim.wait(timeout=1)
                subprocess.run([str(self.stop_script), str(state)], cwd=self.pbns_root.parent, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    unittest.main()
