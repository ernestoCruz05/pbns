import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


class QemuScriptsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).parents[2]
        self.bootstrap = self.pbns_root / "integration" / "qemu" / "bootstrap-iasl.sh"
        self.build = self.pbns_root / "integration" / "qemu" / "build-ovmf.sh"
        self.run = self.pbns_root / "integration" / "qemu" / "run-probe.sh"
        self.cose_run = (
            self.pbns_root / "integration" / "qemu" / "run-cose-probe.sh"
        )
        self.time_run = (
            self.pbns_root / "integration" / "qemu" / "run-time-probe.sh"
        )
        self.baseline_run = (
            self.pbns_root / "integration" / "qemu" / "run-baseline-probe.sh"
        )
        self.enrollment_local_run = (
            self.pbns_root
            / "integration"
            / "qemu"
            / "run-enrollment-local-probe.sh"
        )
        self.time_live_local_run = (
            self.pbns_root
            / "integration"
            / "qemu"
            / "run-time-live-local-probe.sh"
        )
        self.swtpm_start = (
            self.pbns_root / "integration" / "swtpm" / "start-swtpm.sh"
        )
        self.swtpm_stop = (
            self.pbns_root / "integration" / "swtpm" / "stop-swtpm.sh"
        )
        self.swtpm_test = (
            self.pbns_root / "integration" / "swtpm" / "test-tss2-sys.sh"
        )
        self.secureboot_enroll = (
            self.pbns_root / "integration" / "qemu" / "enroll-test-secureboot.sh"
        )
        self.recovery_matrix = (
            self.pbns_root / "integration" / "qemu" / "run-recovery-matrix.sh"
        )
        self.secureboot_store_verify = (
            self.pbns_root / "integration" / "qemu" / "verify-secureboot-store.py"
        )
        self.secureboot_preflight_verify = (
            self.pbns_root / "integration" / "qemu" / "verify-secureboot-preflight.py"
        )
        self.secureboot_runtime_driver = (
            self.pbns_root / "integration" / "qemu" / "secureboot-runtime-driver.py"
        )
        self.recovery_live_prepare = (
            self.pbns_root
            / "integration"
            / "qemu"
            / "prepare-recovery-live-state.sh"
        )
        self.enrollment_time_driver = (
            self.pbns_root / "integration" / "qemu" / "enrollment-time-driver.py"
        )
        self.attestation_run = (
            self.pbns_root / "integration" / "qemu" / "run-attestation.sh"
        )

    def test_iasl_bootstrap_is_versioned_and_checksum_pinned(self) -> None:
        contents = self.bootstrap.read_text(encoding="utf-8")
        for marker in (
            "20190215.0.0",
            "0f207af637358f32c93f09f3df12056452964e6a5242de484508e91d352946cb",
            "9dc25808684701d5a009a9e984385a7b5d36fbd1e398810028c5d163b7553dff",
            "api.nuget.org",
            "sha256sum",
            "ASL+ Optimizing Compiler/Disassembler version 20190215",
            "IASL BOOTSTRAP PASS",
        ):
            self.assertIn(marker, contents)
        self.assertNotIn("sudo", contents)

    def test_ovmf_build_is_pinned_and_isolated(self) -> None:
        contents = self.build.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "b03a21a63e3bd001f52c527e5a57feddb53a690b",
            "submodule status --recursive",
            "OvmfPkg/OvmfPkgX64.dsc",
            "TPM2_ENABLE=TRUE",
            "SECURE_BOOT_ENABLE=TRUE",
            'rm -rf -- "$PBNS_EDK2_DIR/Build/OvmfX64"',
            'rm -f -- "$PBNS_EDK2_DIR/Conf/.AutoGenIdFile.txt"',
            "PBNS_IASL_DIR",
            "9dc25808684701d5a009a9e984385a7b5d36fbd1e398810028c5d163b7553dff",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
            "OVMF BUILD PASS",
        ):
            self.assertIn(marker, contents)
        self.assertNotIn("sudo", contents)
        self.assertLess(
            contents.index('rm -f -- "$PBNS_EDK2_DIR/Conf/.AutoGenIdFile.txt"'),
            contents.index('source "$PBNS_EDK2_DIR/edksetup.sh" BaseTools'),
        )

    def test_swtpm_gate_is_private_fresh_and_deterministically_cleaned(self) -> None:
        start = self.swtpm_start.read_text(encoding="utf-8")
        stop = self.swtpm_stop.read_text(encoding="utf-8")
        lifecycle = (self.pbns_root / "integration" / "swtpm" / "quiesce-swtpm-runtime.py").read_text(encoding="utf-8")
        oracle = self.swtpm_test.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "umask 077",
            "chmod 0700",
            "chmod 0600",
            "--tpm2",
            "type=unixio,path=",
            "--flags startup-clear",
            "TPM2TOOLS_TCTI=",
            "swtpm:path=",
            "tpm2_getcap",
            "trap cleanup",
            "/proc/{pid}",
        ):
            self.assertIn(marker, start + stop + lifecycle)
        for marker in (
            "TPM2TOOLS_TCTI=\"swtpm:path=",
            "tpm2_createprimary",
            "tpm2_create",
            "tpm2_load",
            "tpm2_sign",
            "tpm2_verifysignature",
            "tpm2_createek",
            "tpm2_createak",
            "tpm2_getrandom",
            "tpm2_nvdefine",
            "tpm2_nvwrite",
            "tpm2_nvread",
            "tpm2_nvundefine",
            "SWTPM TSS2 SYS PASS",
        ):
            self.assertIn(marker, oracle)
        self.assertIn("refusing nonempty state", start)
        self.assertIn('rm -rf -- "$state_dir"', stop)
        for contents in (start, stop, oracle):
            self.assertNotIn("eval", contents)
            self.assertNotIn("chmod 777", contents)
            self.assertNotIn("chmod a+", contents)

    def test_cose_probe_is_disposable_offline_and_has_a_strict_oracle(self) -> None:
        contents = self.cose_run.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "mktemp -d",
            "OVMF_VARS.fd",
            "PbnsCoseProbe.efi",
            "EFI/BOOT/BOOTX64.EFI",
            "startup.nsh",
            "fat:rw:",
            "-machine q35,accel=tcg",
            "-nic none",
            "PBNS COSE SIGN1 VERIFY PASS",
            "PBNS COSE ENCRYPT ROUNDTRIP PASS",
            "PBNS COSE ENCRYPT NEGATIVE PASS",
            "PBNS COSE PROBE FAIL",
            "UEFI COSE INTEROP PASS",
        ):
            self.assertIn(marker, contents)
        for forbidden in ("usb-host", "/dev/sda", "/dev/nvme", "-enable-kvm"):
            self.assertNotIn(forbidden, contents)

    def test_time_probe_is_disposable_offline_and_never_uses_rtc(self) -> None:
        contents = self.time_run.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "mktemp -d",
            "OVMF_VARS.fd",
            "PbnsTime.efi",
            "EFI/BOOT/BOOTX64.EFI",
            "startup.nsh",
            "fat:rw:",
            "-machine q35,accel=tcg",
            "-nic none",
            "PBNS TRUSTED TIME INTERVAL PASS",
            "PBNS TRUSTED TIME PROBE FAIL",
            "UEFI TRUSTED TIME SOFTWARE CHECKPOINT PASS",
        ):
            self.assertIn(marker, contents)
        for forbidden in (
            "usb-host",
            "/dev/sda",
            "/dev/nvme",
            "-enable-kvm",
            "SetTime",
        ):
            self.assertNotIn(forbidden, contents)

    def test_baseline_probe_is_disposable_offline_and_uses_swtpm(self) -> None:
        contents = self.baseline_run.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "umask 077",
            "mktemp -d",
            "OVMF_VARS.fd",
            "PbnsBaseline.efi",
            "EFI/BOOT/BOOTX64.EFI",
            "startup.nsh",
            "fat:rw:",
            "-machine q35,accel=tcg",
            "-nic none",
            "start-swtpm.sh",
            "stop-swtpm.sh",
            "-tpmdev",
            "tpm-tis",
            "PBNS BASELINE EVENT LOG MS",
            "PBNS BASELINE HASHING MS",
            "PBNS BASELINE PCR READ MS",
            "PBNS BASELINE ENCODING MS",
            "PBNS BASELINE CAPTURE PASS",
            "baseline-probe-no-tpm.log",
            "PBNS BASELINE PROBE FAIL status Unsupported",
            "missing TCG2 rejected",
            "UEFI MEASURED BOOT EMULATED CHECKPOINT PASS",
            "emulated-system",
        ):
            self.assertIn(marker, contents)
        for forbidden in (
            "usb-host",
            "/dev/sda",
            "/dev/nvme",
            "-enable-kvm",
            "physical",
        ):
            self.assertNotIn(forbidden, contents)

    def test_enrollment_local_probe_is_private_offline_and_uses_swtpm(self) -> None:
        contents = self.enrollment_local_run.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "umask 077",
            "mktemp -d",
            "OVMF_VARS.fd",
            "PbnsEnroll.efi",
            "software-create",
            "EFI/BOOT/BOOTX64.EFI",
            "startup.nsh",
            "fat:rw:",
            '"-machine", "q35,accel=tcg"',
            '"-nic", "none"',
            "start-swtpm.sh",
            "stop-swtpm.sh",
            "-tpmdev",
            "tpm-tis",
            "os.urandom(32)",
            "input hidden",
            "PBNS ENROLL INIT ENCRYPTION CHECKPOINT PASS",
            "PBNS ENROLL FAIL CDC0 unavailable",
            "UEFI ENROLLMENT LOCAL EMULATED CHECKPOINT PASS",
            "emulated-system-local-only",
        ):
            self.assertIn(marker, contents)
        for forbidden in (
            "usb-host",
            "/dev/sda",
            "/dev/nvme",
            "-enable-kvm",
            "chmod 777",
        ):
            self.assertNotIn(forbidden, contents)

    def test_time_live_local_probe_reopens_identity_without_network(self) -> None:
        contents = self.time_live_local_run.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "umask 077",
            "mktemp -d",
            "OVMF_VARS.fd",
            "PbnsEnroll.efi",
            "PbnsTimeLive.efi",
            "EFI/BOOT/BOOTX64.EFI",
            '"-machine", "q35,accel=tcg"',
            '"-nic", "none"',
            "start-swtpm.sh",
            "stop-swtpm.sh",
            "TPM2TOOLS_TCTI",
            "/proc/{pid}/cmdline",
            "os.urandom(32)",
            "PBNS TIME LIVE FAIL CDC0 unavailable",
            "persistent_identity_reopen",
            "rtc_access",
            "UEFI TRUSTED TIME LIVE LOCAL EMULATED CHECKPOINT PASS",
        ):
            self.assertIn(marker, contents)
        for forbidden in (
            "usb-host",
            "/dev/sda",
            "/dev/nvme",
            "-enable-kvm",
            "SetTime",
            "chmod 777",
        ):
            self.assertNotIn(forbidden, contents)

    def test_secureboot_enrollment_uses_only_a_private_copied_variable_store(self) -> None:
        contents = self.secureboot_enroll.read_text(encoding="utf-8")
        store_verify = self.secureboot_store_verify.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "umask 077",
            "virt-fw-vars",
            '--input "$vars_template" --output "$work_vars"',
            '--enroll-cert "$uki_test_cert"',
            "--microsoft-kek none",
            "--no-microsoft",
            "--add-db a0baa8a3-041d-48a8-bc87-c36d121b5e3d",
            "--secure-boot",
            "mktemp -d",
            "chmod 0700",
            "chmod 0600",
            "ln \"$work_vars\" \"$vars_copy\"",
            "ln \"$work_decoded\" \"$decoded\"",
            "record_diagnostic",
            "PBNS_SECUREBOOT_ENROLLMENT_FAILED",
            "PBNS SECUREBOOT VARIABLE ENROLLMENT PASS",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, contents)
        for marker in (
            "--print", "--verbose", "--extract-certs", "SecureBootEnable",
            "EfiCertX509 count=1", "fixture.der", "filecmp.cmp", "OWNER_GUID",
        ):
            with self.subTest(store_marker=marker):
                self.assertIn(marker, store_verify)
        for forbidden in (
            "KeyTool.efi", "cert-to-efi-sig-list", "sign-efi-sig-list",
            "/sys/firmware/efi/efivars", "--inplace", "sudo",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, contents + store_verify)

    def test_secureboot_enrollment_creates_a_private_test_certificate_only_store(self) -> None:
        if shutil.which("virt-fw-vars") is None:
            self.skipTest("virt-fw-vars is not installed")
        template = pathlib.Path("/usr/share/edk2/OvmfX64/OVMF_VARS.fd")
        if not template.is_file():
            self.skipTest("OVMF variable template is not installed")
        state_root = self.pbns_root / "integration" / "state"
        with tempfile.TemporaryDirectory(dir=state_root) as directory:
            state = pathlib.Path(directory)
            state.chmod(0o700)
            completed = subprocess.run(
                [str(self.secureboot_enroll), str(state)],
                cwd=self.pbns_root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("PBNS SECUREBOOT VARIABLE ENROLLMENT PASS", completed.stdout)
            variables = state / "OVMF_VARS.secboot.fd"
            decoded = state / "OVMF_VARS.secboot.txt"
            self.assertEqual(os.stat(state).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(variables).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(decoded).st_mode & 0o777, 0o600)
            report = decoded.read_text(encoding="utf-8")
            for variable in ("name=PK ", "name=KEK ", "name=db ", "name=SecureBootEnable "):
                with self.subTest(variable=variable):
                    self.assertIn(variable, report)
            self.assertEqual(report.count("subject CN=PBNS TEST ONLY Recovery Image"), 3)
            self.assertNotIn("Microsoft", report)
            self.assertIn("bool: ON", report)
            self.assertFalse((state / "secureboot-enrollment-failed.log").exists())
            self.assertEqual(list(state.glob(".secureboot-enrollment.*")), [])
            rerun = subprocess.run(
                [str(self.secureboot_enroll), str(state)], cwd=self.pbns_root.parent,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertNotEqual(rerun.returncode, 0)
            self.assertIn("PBNS secure boot enrollment failed", rerun.stderr)

    def test_enrollment_missing_input_and_missing_tool_record_private_diagnostics(self) -> None:
        state_root = self.pbns_root / "integration" / "state"
        with tempfile.TemporaryDirectory(dir=state_root) as directory:
            state = pathlib.Path(directory)
            state.chmod(0o700)
            missing_input = subprocess.run(
                [str(self.secureboot_enroll), str(state)], cwd=self.pbns_root.parent,
                env=os.environ | {"PBNS_OVMF_SECUREBOOT_VARS": str(state / "missing.fd")},
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertNotEqual(missing_input.returncode, 0)
            diagnostic = state / "secureboot-enrollment-failed.log"
            self.assertEqual(os.stat(diagnostic).st_mode & 0o777, 0o600)
            self.assertEqual(diagnostic.read_text(), "PBNS_SECUREBOOT_ENROLLMENT_FAILED\n")
        with tempfile.TemporaryDirectory(dir=state_root) as directory, tempfile.TemporaryDirectory() as fake_directory:
            state = pathlib.Path(directory)
            state.chmod(0o700)
            fake = pathlib.Path(fake_directory)
            for command in ("dirname", "stat", "chmod"):
                target = shutil.which(command)
                assert target is not None
                (fake / command).symlink_to(target)
            missing_tool = subprocess.run(
                ["/usr/bin/bash", str(self.secureboot_enroll), str(state)], cwd=self.pbns_root.parent,
                env=os.environ | {"PATH": str(fake)}, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False,
            )
            self.assertNotEqual(missing_tool.returncode, 0)
            diagnostic = state / "secureboot-enrollment-failed.log"
            self.assertEqual(os.stat(diagnostic).st_mode & 0o777, 0o600)
            self.assertEqual(diagnostic.read_text(), "PBNS_SECUREBOOT_ENROLLMENT_FAILED\n")

    def test_enrollment_signal_cleans_scratch_and_records_private_diagnostic(self) -> None:
        state_root = self.pbns_root / "integration" / "state"
        with tempfile.TemporaryDirectory(dir=state_root) as directory, tempfile.TemporaryDirectory() as fake_directory:
            state = pathlib.Path(directory)
            state.chmod(0o700)
            fake = pathlib.Path(fake_directory)
            for command in ("dirname", "stat", "chmod", "mktemp", "rm"):
                target = shutil.which(command)
                assert target is not None
                (fake / command).symlink_to(target)
            for name, content in {
                "virt-fw-vars": "#!/usr/bin/bash\n/bin/sleep 30\n",
                "openssl": "#!/usr/bin/env bash\nexit 0\n",
                "python3": "#!/usr/bin/env bash\nexit 0\n",
            }.items():
                path = fake / name
                path.write_text(content, encoding="utf-8")
                path.chmod(0o755)
            process = subprocess.Popen(
                ["/usr/bin/bash", str(self.secureboot_enroll), str(state)], cwd=self.pbns_root.parent,
                env=os.environ | {"PATH": str(fake)}, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True,
            )
            deadline = time.monotonic() + 5
            while not list(state.glob(".secureboot-enrollment.*")) and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(list(state.glob(".secureboot-enrollment.*")))
            os.killpg(process.pid, signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 143, stderr)
            diagnostic = state / "secureboot-enrollment-failed.log"
            self.assertEqual(os.stat(diagnostic).st_mode & 0o777, 0o600)
            self.assertEqual(diagnostic.read_text(), "PBNS_SECUREBOOT_ENROLLMENT_FAILED\n")
            self.assertEqual(list(state.glob(".secureboot-enrollment.*")), [])

    def test_enrollment_time_driver_bounds_output_and_child_waits(self) -> None:
        contents = self.enrollment_time_driver.read_text(encoding="utf-8")
        self.assertIn("OUTPUT_CAP = 8 * 1024 * 1024", contents)
        self.assertIn("process.wait(timeout=5)", contents)
        self.assertNotIn("process.wait()", contents)
        self.assertNotIn("process.stdout.read()", contents)

    def test_attestation_runner_is_exact_stock_qemu_passthrough(self) -> None:
        contents = self.attestation_run.read_text(encoding="utf-8")
        for marker in (
            "attestation-passthrough-driver.py",
            "select-pico",
            "hostbus",
            "hostaddr",
            "q35,accel=tcg",
            "-nic none",
            "start-swtpm.sh",
            "provision-swtpm-ek.py",
            "attestation-passthrough-current.path",
        ):
            self.assertIn(marker, contents)
        for forbidden in (
            "vendorid=0xcafe",
            "productid=0x4011",
            "-enable-kvm",
            "/dev/tpm",
            "/dev/sd",
            "/dev/nvme",
        ):
            self.assertNotIn(forbidden, contents)

    def test_recovery_live_policy_reopens_clean_exited_swtpm_before_policy(self) -> None:
        source = self.recovery_live_prepare.read_text(encoding="utf-8")
        start = source.rindex(
            'stop_gateway\n"$pbns_root/integration/swtpm/pause-swtpm.sh"'
        )
        end = source.index("\nfor forbidden_state", start)
        checkpoint = source[start:end]
        checkpoint = checkpoint.replace(
            '"$pbns_root/integration/swtpm/pause-swtpm.sh"', "pause_swtpm"
        ).replace(
            '"$pbns_root/integration/swtpm/resume-swtpm.sh"', "resume_swtpm"
        ).replace(
            '"$pbns_root/integration/swtpm/run-recovery-policy-live.sh"',
            "run_recovery_policy",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            state = root / "swtpm-state"
            state.mkdir()
            harness = f'''\
set -euo pipefail
order_log={str(root / "order.log")!r}
swtpm_state={str(state)!r}
work_dir={str(root)!r}
database={str(root / "gateway.db")!r}
pbnsctl_binary=pbnsctl
swtpm_running=1
stop_gateway() {{ printf '%s\\n' stop-gateway >>"$order_log"; }}
pbnsctl() {{ printf 'host-check:%s\\n' "$swtpm_running" >>"$order_log"; printf '%s\\n' hosts=1; }}
pause_swtpm() {{ printf 'pause:%s\\n' "$swtpm_running" >>"$order_log"; }}
resume_swtpm() {{ printf 'resume:%s\\n' "$swtpm_running" >>"$order_log"; }}
run_recovery_policy() {{
    operation=$1
    shift
    state_arg=$1
    shift
    printf '%s:%s:%s\\n' "$operation" "$swtpm_running" "$*" >>"$order_log"
    if [[ $operation == read ]]; then
        printf '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x05' >"${{@: -1}}"
    fi
}}
{checkpoint}
printf 'final:%s\\n' "$swtpm_running" >>"$order_log"
'''
            completed = subprocess.run(
                ["bash", "-c", harness], text=True, capture_output=True, check=False
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                (root / "order.log").read_text(encoding="utf-8").splitlines(),
                [
                    "stop-gateway",
                    "pause:1",
                    "resume:1",
                    "host-check:1",
                    "initialize:1:5",
                    "authorize:1:5 7 target-7",
                    "authorize:1:4 5 downgrade-5",
                    f"read:1:{state / 'current-version.bin'}",
                    "pause:1",
                    "final:0",
                ],
            )

    def test_recovery_live_base_is_signed_coupled_closed_and_private(self) -> None:
        self.assertTrue(self.recovery_live_prepare.is_file())
        self.assertTrue(os.access(self.recovery_live_prepare, os.X_OK))
        contents = self.recovery_live_prepare.read_text(encoding="utf-8")
        for marker in (
            "PbnsEnroll.efi",
            "PbnsTimeLive.efi",
            "PBNSRecovery.efi",
            "PBNSLauncher.efi",
            "PbnsBootSetup.efi",
            "ReturnSuccess.efi",
            "Shell.efi",
            "PBNSNormal.efi",
            "sbsign",
            "sbverify --list",
            "enrollment-time-driver.py",
            "--phase enrollment",
            "--mode t",
            "--phase time",
            "enrollment_token=",
            "hosts=1",
            "run-recovery-policy-live.sh",
            '"$swtpm_state" 5 7 target-7',
            '"$swtpm_state" 4 5 downgrade-5',
            "pause-swtpm.sh",
            "wait \"$pid\"",
            "output_limit_kib=65536",
            'ulimit -f "$output_limit_kib"',
            "child_stopped",
            "terminate-child-process.py",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
            "gateway.db",
            "esp-template",
            "swtpm-state",
            "recovery-policy",
            "recovery-base",
            "runtime.path",
            "socket.path",
            "swtpm.pid",
            "private",
            "mode 0600",
            "mode 0700",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, contents)
        self.assertNotIn('wait "$gateway_pid" 2>/dev/null || true', contents)
        self.assertLess(contents.index("stop_gateway"), contents.index("hosts=1"))
        self.assertLess(
            contents.rindex('"$pbns_root/integration/swtpm/pause-swtpm.sh"'),
            contents.index('mv -T -- "$base_tmp" "$base"'),
        )
        for forbidden in (
            "/dev/tpm", "/dev/sdc", "/dev/sd", "device:", "abrmd",
            "-enable-kvm", "/sys/firmware/efi/efivars", "sudo",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, contents)

    def test_recovery_matrix_proves_secureboot_preflight_then_blocks_without_live_driver(self) -> None:
        required = ("qemu-system-x86_64", "sbsign", "virt-fw-vars")
        if any(shutil.which(command) is None for command in required):
            self.skipTest("QEMU Secure Boot preflight tools are not installed")
        if not pathlib.Path("/usr/share/edk2/OvmfX64/OVMF_CODE.secboot.fd").is_file():
            self.skipTest("Secure Boot OVMF code is not installed")
        state_root = self.pbns_root / "integration" / "state"
        with tempfile.TemporaryDirectory(dir=state_root) as directory:
            state = pathlib.Path(directory)
            state.chmod(0o700)
            enrollment = subprocess.run(
                [str(self.secureboot_enroll), str(state)],
                cwd=self.pbns_root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(enrollment.returncode, 0, enrollment.stderr)
            environment = os.environ | {"PBNS_RECOVERY_QEMU_STATE": str(state)}
            matrix = subprocess.run(
                [str(self.recovery_matrix)],
                cwd=self.pbns_root.parent,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(matrix.returncode, 0)
            self.assertIn(
                "PBNS SECUREBOOT PREFLIGHT PASS SecureBoot=1 SetupMode=0",
                matrix.stdout,
            )
            self.assertIn("RECOVERY MATRIX BLOCKED", matrix.stdout)
            blocker = state / "recovery-matrix-blocked.log"
            self.assertEqual(os.stat(blocker).st_mode & 0o777, 0o600)
            self.assertEqual(blocker.read_text(), "PBNS_RECOVERY_MATRIX_BLOCKED\n")
            retained = state / "recovery-secureboot-preflight.log"
            self.assertEqual(os.stat(retained).st_mode & 0o777, 0o600)
            reparsed = subprocess.run(
                [str(self.secureboot_preflight_verify), "--serial", str(retained)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(reparsed.returncode, 0, reparsed.stderr)
            self.assertFalse((state / "recovery-secureboot-preflight-failed.log").exists())
            self.assertEqual(list(state.glob(".recovery-preflight.*")), [])

    def test_recovery_matrix_secureboot_preflights_cold_reset_with_no_reboot(self) -> None:
        contents = self.recovery_matrix.read_text(encoding="utf-8")
        preflight_redirect = contents.index("preflight_esp/startup.nsh")
        preflight_start = contents.rindex("printf '%s\\r\\n'", 0, preflight_redirect)
        preflight_end = contents.index("\n", preflight_redirect)
        signed_redirect = contents.index("signed_preflight_dir/startup.nsh")
        signed_start = contents.rindex("printf '%s\\r\\n'", 0, signed_redirect)
        signed_end = contents.index("\n", signed_redirect)
        self.assertIn("'reset -c'", contents[preflight_start:preflight_end])
        self.assertIn("'reset -c'", contents[signed_start:signed_end])
        self.assertNotIn("'reset -s'", contents)
        self.assertIn(
            "-no-reboot",
            contents[preflight_end:contents.index("serial_safe()", preflight_end)],
        )
        self.assertIn(
            '"-no-reboot",',
            self.secureboot_runtime_driver.read_text(encoding="utf-8"),
        )

    def test_recovery_matrix_pins_serial_uki_before_install_and_publication(self) -> None:
        contents = self.recovery_matrix.read_text(encoding="utf-8")
        pinned_path = (
            'integration/state/recovery-build-20260810-serial-final/PBNSRecovery.efi'
        )
        pinned_sha256 = (
            "d2666d96e00cfd66d9ec7ecb4e20146d7f62fd673b00f64ed48d7169e3e353a3"
        )
        old_path = "integration/state/recovery-build-20260802-final/PBNSRecovery.efi"
        old_sha256 = "7fec33d720d41a67f383a2dcd16e493d5d7016af79c3ff8fc51a24afa7a56943"
        self.assertIn(pinned_path, contents)
        self.assertIn(f"expected_uki_sha256={pinned_sha256}", contents)
        self.assertIn("[[ $artifact_size -eq 26553920 ]] || fail", contents)
        self.assertNotIn(old_path, contents)
        self.assertNotIn(old_sha256, contents)
        verification = contents.index(
            'sbverify --cert "$uki_test_cert" "$signed_uki" >/dev/null 2>&1 || fail'
        )
        install = contents.index('install -m 0600 "$signed_uki" "$artifact_input"')
        publication = contents.index('"$private_dir/pbnsctl" recovery publish')
        self.assertLess(verification, install)
        self.assertLess(verification, publication)
        self.assertLess(install, publication)

    def test_recovery_matrix_reopens_clean_exited_swtpm_before_nv_after(self) -> None:
        source = self.recovery_matrix.read_text(encoding="utf-8")
        start = source.index(
            'case_swtpm_running=1\n'
            '"$pbns_root/integration/swtpm/resume-swtpm.sh" "$case_swtpm"'
        )
        end = source.index('\nrm -rf -- "$private_dir"', start)
        checkpoint = source[start:end]
        checkpoint = checkpoint.replace(
            '"$pbns_root/integration/swtpm/pause-swtpm.sh"', "pause_swtpm"
        ).replace(
            '"$pbns_root/integration/swtpm/resume-swtpm.sh"', "resume_swtpm"
        ).replace(
            '"$pbns_root/integration/swtpm/run-recovery-policy-live.sh"',
            "run_recovery_policy",
        ).replace(
            '''python3 "$script_dir/recovery-live-driver.py" \\
    --case-root "$case_root" --case signed-trusted --phase recovery \\
    --code "$case_code" --variables "$case_vars" --esp "$case_esp" \\
    --swtpm-state "$case_swtpm" --disk "$disk" --log "$serial" \\
    --pico present''',
            "recovery_live_driver",
        ).replace(
            '"$pbns_root/integration/swtpm/stop-swtpm.sh"', "stop_swtpm"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            harness = f'''\\
set -euo pipefail
order_log={str(root / "order.log")!r}
case_root={str(root)!r}
case_swtpm={str(root / "swtpm-state")!r}
nv_before={str(root / "nv-before.bin")!r}
nv_after={str(root / "nv-after.bin")!r}
nv_before_runtime={str(root / "swtpm-state" / "nv-before.bin")!r}
nv_after_runtime={str(root / "swtpm-state" / "nv-after.bin")!r}
case_code=code
case_vars=variables
case_esp=esp
serial=serial
disk=disk
disk_before=disk-before
disk_after=disk-after
signed_secureboot_log=secureboot.log
artifact_size=1
gateway_log={str(root / "gateway.log")!r}
private_dir={str(root / "private")!r}
script_dir=scripts
case_swtpm_running=0
: >"$gateway_log"
mkdir "$private_dir" "$case_swtpm"
fail() {{ return 1; }}
pause_swtpm() {{ printf 'pause:%s\\n' "$case_swtpm_running" >>"$order_log"; }}
resume_swtpm() {{ printf 'resume:%s\\n' "$case_swtpm_running" >>"$order_log"; }}
recovery_live_driver() {{ printf 'recovery-live-driver:%s\\n' "$case_swtpm_running" >>"$order_log"; }}
hash_disk() {{ printf 'hash-disk:%s\\n' "$case_swtpm_running" >>"$order_log"; }}
python3() {{ printf 'verify-%s:%s\\n' "$(basename "$1" .py)" "$case_swtpm_running" >>"$order_log"; }}
terminate_gateway() {{ printf 'terminate-gateway:%s\\n' "$case_swtpm_running" >>"$order_log"; }}
stop_swtpm() {{ printf 'stop:%s\\n' "$case_swtpm_running" >>"$order_log"; }}
publish_nv_evidence() {{ (set -o noclobber; cat -- "$1" >"$2"); chmod 0600 "$2"; }}
run_recovery_policy() {{
    operation=$1
    shift
    printf '%s:%s:%s\\n' "$operation" "$case_swtpm_running" "${{@: -1}}" >>"$order_log"
    [[ $operation != read ]] || printf '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x05' >"${{@: -1}}"
}}
{checkpoint}
printf 'final:%s\\n' "$case_swtpm_running" >>"$order_log"
'''
            completed = subprocess.run(
                ["bash", "-c", harness], text=True, capture_output=True, check=False
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                (root / "order.log").read_text(encoding="utf-8").splitlines(),
                [
                    "resume:1",
                    f"read:1:{root / 'swtpm-state' / 'nv-before.bin'}",
                    "recovery-live-driver:1",
                    "pause:1",
                    "resume:1",
                    f"read:1:{root / 'swtpm-state' / 'nv-after.bin'}",
                    "hash-disk:1",
                    "verify-verify-secureboot-preflight:1",
                    "verify-verify-recovery-observability:1",
                    "terminate-gateway:1",
                    "stop:1",
                    "final:0",
                ],
            )
            self.assertEqual((root / "nv-before.bin").read_bytes(), b"\0" * 7 + b"\x05")
            self.assertEqual((root / "nv-after.bin").read_bytes(), b"\0" * 7 + b"\x05")

    def test_recovery_matrix_nv_evidence_is_create_exclusive(self) -> None:
        source = self.recovery_matrix.read_text(encoding="utf-8")
        start = source.index("publish_nv_evidence() {")
        end = source.index("\n}\n", start) + 3
        function = source[start:end]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            runtime = root / "runtime.bin"
            evidence = root / "evidence.bin"
            victim = root / "victim.bin"
            runtime.write_bytes(b"\0" * 7 + b"\x05")
            os.chmod(runtime, 0o600)
            victim.write_bytes(b"unchanged")
            script = f'''\\
set -euo pipefail
case_root={str(root)!r}
fail() {{ return 1; }}
{function}
publish_nv_evidence {str(runtime)!r} {str(evidence)!r}
'''
            first = subprocess.run(["bash", "-c", script], capture_output=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(evidence.read_bytes(), b"\0" * 7 + b"\x05")
            self.assertEqual(os.stat(evidence).st_mode & 0o777, 0o600)
            second = subprocess.run(["bash", "-c", script], capture_output=True, check=False)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(evidence.read_bytes(), b"\0" * 7 + b"\x05")
            evidence.unlink()
            evidence.symlink_to(victim)
            linked = subprocess.run(["bash", "-c", script], capture_output=True, check=False)
            self.assertNotEqual(linked.returncode, 0)
            self.assertEqual(victim.read_bytes(), b"unchanged")

    def test_recovery_matrix_production_failures_are_independent_and_immutable(self) -> None:
        contents = self.recovery_matrix.read_text(encoding="utf-8")
        for marker in (
            'clone_coupled_base "$case_name"',
            "sbattach --remove",
            'sbverify --list "$artifact_input"',
            "truncate -s $((artifact_size / 2))",
            "downgrade-5.cbor",
            "--recovery-target-version \"$target_version\"",
            "--recovery-minimum-version \"$minimum_version\"",
            "--case \"$case_name\" --phase recovery",
            'recovery-matrix-evidence.py" case',
            "PBNS_ERR_REPLAY",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, contents)
        self.assertNotIn("--evaluation-events", contents[contents.index("run_production_failure_case"):])

    def test_recovery_matrix_evaluation_faults_use_closed_private_gateway_instances(self) -> None:
        source = self.recovery_matrix.read_text(encoding="utf-8")
        for marker in (
            'go build -trimpath -o "$private_dir/pbns-recovery-eval-gateway" ./cmd/pbns-recovery-eval-gateway',
            'gateway_command=(',
            '"$gateway_expected_executable" --case "$case_name" --fault "$fault" --events "$events" --',
            'verify_gateway_command_identity',
            'wait_evaluation_barrier "$events" "$case_name" "$fault" 7 interrupt-ready',
            'wait_evaluation_barrier "$events_restart" "$case_name" "$fault" 0 sent',
            'run_evaluation_fault_case forged-digest artifact-digest-mismatch',
            'run_evaluation_fault_case forged-chunk chunk-sequence',
            'run_evaluation_fault_case gateway-interruption interrupt-after-data-7',
            '--events-restart "$events_restart" --serial-restart "$serial_restart"',
            'os.fsync(descriptor)',
            'argv != command',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        evaluation = source[source.index("run_evaluation_fault_case() {"):]
        self.assertNotIn('pbns-gateway" --case', evaluation)
        self.assertIn('"${gateway_suffix[@]}"', source)

    def test_recovery_matrix_requires_runtime_oracles_and_is_disposable(self) -> None:
        contents = self.recovery_matrix.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "umask 077",
            "virt-fw-vars",
            "verify-secureboot-store.py",
            "verify-secureboot-preflight.py",
            "PBNS-SB-BEGIN-SecureBoot",
            "PBNS-SB-END-SetupMode",
            "echo -off",
            "PBNS SECUREBOOT PREFLIGHT PASS SecureBoot=1 SetupMode=0",
            "signed-trusted",
            "unsigned-untrusted",
            "truncated",
            "gateway-interruption",
            "forged-manifest",
            "forged-digest",
            "forged-chunk",
            "downgrade",
            "normal-launcher",
            "pico-absent",
            "verify-recovery-observability.py",
            "[NOT-RUN]",
            "--current-version 5 --target-version 7",
            "disk-before.sha256",
            "disk-after.sha256",
            "q35,accel=tcg",
            "-nic none",
            "readonly=on",
            "OVMF_VARS",
            "PBNS_RECOVERY_MATRIX_BLOCKED",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, contents)
        for forbidden in (
            "/dev/sd",
            "/dev/nvme",
            "/dev/sdc",
            "-hda",
            "-enable-kvm",
            "/sys/firmware/efi/efivars",
            "sudo",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, contents)

    def test_probe_uses_only_disposable_fat_and_exact_usb_identity(self) -> None:
        contents = self.run.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "--self-test",
            "--require-hardware",
            "mktemp -d",
            "startup.nsh",
            "EFI/BOOT/BOOTX64.EFI",
            "PbnsProbe.efi",
            "fat:rw:",
            "qemu-xhci",
            "vendorid=0xcafe",
            "productid=0x4011",
            "-nic none",
            "correlated unimplemented response",
            "CDC0 adapter unavailable",
            "BootOrder|SetVariable",
            "QEMU PROBE PASS",
            "PBNS_GATEWAY_SERVER_NAME",
            "make-test-pki.sh",
            "gateway-reissued-cert.pem",
            "verify-spki.py",
        ):
            self.assertIn(marker, contents)
        self.assertLess(contents.index("verify-spki.py"), contents.index('"$GATEWAY_BINARY"'))
        self.assertLess(contents.index("verify-spki.py"), contents.index("usb-host"))
        self.assertNotIn("PBNS_GATEWAY_CERT:-", contents)
        for forbidden in ("/dev/sda", "/dev/nvme"):
            self.assertNotIn(forbidden, contents)


if __name__ == "__main__":
    unittest.main()
