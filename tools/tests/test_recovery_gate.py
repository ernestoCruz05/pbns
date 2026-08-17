import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


class RecoveryGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).resolve().parents[2]
        self.verify = self.pbns_root / "tools" / "verify-recovery.sh"
        self.hash_tool = self.pbns_root / "tools" / "hash-disk-image.sh"
        self.matrix = self.pbns_root / "integration" / "qemu" / "run-recovery-matrix.sh"
        self.physical = self.pbns_root / "integration" / "physical" / "run-recovery.sh"

    def test_gate_names_every_required_stage_without_unconditional_pass(self) -> None:
        source = self.verify.read_text(encoding="utf-8")
        for stage in (
            "launcher",
            "manifest",
            "stream",
            "live-recovery-service",
            "anti-rollback",
            "uki-policy",
            "secureboot-memory-load",
            "disk-immutability",
            "normal-pico-absent",
            "physical-recovery",
        ):
            with self.subTest(stage=stage):
                self.assertIn(stage, source)
        self.assertIn("RECOVERY BLOCKED", source)
        self.assertIn("RECOVERY PASS", source)
        self.assertIn("all_passed", source)
        self.assertLess(
            source.index('anti_state="$state_root/verify-recovery-swtpm-$$"'),
            source.rindex("run_uki_policy\n\nmatrix_log="),
        )

    def test_hosted_only_gate_never_invokes_runtime_runners(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "pbns"
            verify = root / "tools" / "verify-recovery.sh"
            verify.parent.mkdir(parents=True)
            shutil.copy2(self.verify, verify)
            verify.chmod(0o755)
            (root / "gateway").mkdir()
            (root / "build" / "dev").mkdir(parents=True)
            (root / "integration" / "state").mkdir(parents=True)
            marker = root / "runtime-runner-invoked"
            stub = "#!/usr/bin/env bash\nprintf '%s\\n' \"$0\" >> \"$RUNNER_MARKER\"\nexit 0\n"
            for runner in (
                root / "integration" / "swtpm" / "start-swtpm.sh",
                root / "integration" / "swtpm" / "run-recovery-policy.sh",
                root / "integration" / "swtpm" / "stop-swtpm.sh",
                root / "integration" / "qemu" / "run-recovery-matrix.sh",
                root / "integration" / "physical" / "run-recovery.sh",
            ):
                runner.parent.mkdir(parents=True, exist_ok=True)
                runner.write_text(stub, encoding="utf-8")
                runner.chmod(0o755)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            for command in ("ctest", "go", "python3"):
                path = fake_bin / command
                path.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
                path.chmod(0o755)
            environment = os.environ | {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                "RUNNER_MARKER": str(marker),
            }
            completed = subprocess.run(
                [str(verify), "--hosted-only"],
                cwd=root.parent,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            runner_invoked = marker.exists()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("[PASS] live-recovery-service", completed.stdout)
        self.assertIn("[PASS] uki-policy", completed.stdout)
        for stage in (
            "anti-rollback",
            "secureboot-memory-load",
            "disk-immutability",
            "normal-pico-absent",
            "physical-recovery",
        ):
            with self.subTest(stage=stage):
                self.assertEqual(completed.stdout.count(f"[BLOCKED] {stage}"), 1)
        self.assertNotIn("[PASS] anti-rollback", completed.stdout)
        self.assertIn("RECOVERY BLOCKED", completed.stdout)
        self.assertFalse(runner_invoked, "hosted-only invoked a runtime runner")

    def test_qemu_matrix_is_disposable_and_network_free(self) -> None:
        source = self.matrix.read_text(encoding="utf-8")
        for required in (
            "q35,accel=tcg",
            "-nic none",
            "readonly=on",
            "OVMF_VARS",
            "mktemp -d",
            "fat:rw:",
            "PBNSRecovery.efi",
            "signed-trusted",
            "unsigned-untrusted",
            "truncated",
            "gateway-interruption",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        for forbidden in ("/dev/sd", "/dev/nvme", "-hda", "-enable-kvm"):
            self.assertNotIn(forbidden, source)

    def test_signed_runtime_stage_uses_production_gateway_and_stays_blocked(self) -> None:
        source = self.matrix.read_text(encoding="utf-8")
        for marker in (
            "recovery-base",
            "cases/signed-trusted",
            "resume-swtpm.sh",
            "run-recovery-policy-live.sh",
            "recovery publish",
            "--recovery-repository",
            "--recovery-artifact-sha256",
            "--recovery-target-version 7",
            "--recovery-minimum-version 6",
            "--recovery-policy-authorization",
            "--recovery-policy-public-key",
            "--recovery-policy-kid recovery-policy-key-1",
            "--recovery-manifest-signing-key",
            "--recovery-manifest-signing-kid recovery-manifest-key-1",
            "--recovery-secureboot-public-key",
            "--recovery-validity-lead 2m",
            "--recovery-validity-trailing 2m",
            "--recovery-transfer-timeout 45m",
            "--handshake-timeout 15s --read-timeout 60s --write-timeout 60s",
            "recovery-live-driver.py",
            "verify-recovery-observability.py",
            "signed-secureboot-runtime.log",
            "secureboot-runtime-driver.py",
            "os.open(destination, os.O_RDONLY | os.O_DIRECTORY)",
            "output_limit_kib=65536",
            'ulimit -f "$output_limit_kib"',
            "terminate_gateway",
            "terminate-child-process.py",
            '--variables "$case_vars"',
            '--serial "$signed_secureboot_log"',
            "nv-before.bin",
            "nv-after.bin",
            "disk-before.sha256",
            "disk-after.sha256",
            "PBNS GATEWAY LOG REJECT",
            "[PASS] signed-trusted",
            "RECOVERY MATRIX BLOCKED",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        self.assertLess(
            source.index("signed_secureboot_log="),
            source.index('python3 "$script_dir/recovery-live-driver.py"'),
        )
        self.assertNotIn('wait "$gateway_pid" 2>/dev/null || true', source)
        # Evaluation faults are isolated below the production matrix section;
        # the signed runtime must never use their instrumented gateway.
        production = source[:source.index("# Evaluation faults are deliberately isolated")]
        self.assertNotIn("pbns-recovery-eval-gateway", production)
        self.assertNotIn("--fault", production)

    def test_uefi_owned_tls_is_bound_before_recovery_broker_and_gated(self) -> None:
        service = (self.pbns_root / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryServiceLib.c").read_text(encoding="utf-8")
        trust = (self.pbns_root / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryTrust.c").read_text(encoding="utf-8")
        manifest = (self.pbns_root / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryServiceLib.inf").read_text(encoding="utf-8")
        application = (self.pbns_root / "uefi" / "Applications" / "PBNSRecovery" / "PBNSRecovery.inf").read_text(encoding="utf-8")
        for required in (
            "PBNS_TLS_UEFI_TRANSPORT *tls_transport",
            "PBNS_TPM_RANDOM_SOURCE tls_tpm_random",
            "PbnsTlsTransportCreate",
            "PbnsTlsTransportAsTransport(service->tls_transport)",
            "PbnsTlsTransportDestroy(service->tls_transport)",
            "PbnsRecoveryServiceTrustConfig",
        ):
            with self.subTest(required=required):
                self.assertIn(required, service + trust)
        self.assertLess(
            service.index("pbns_usb_transport_create"),
            service.index("PbnsTlsTransportCreate"),
        )
        self.assertLess(
            service.index("PbnsTlsTransportCreate"), service.index("pbns_broker_init")
        )
        self.assertLess(
            service.index("PbnsTlsTransportDestroy(service->tls_transport)"),
            service.index("pbns_usb_transport_destroy(service->usb_transport)"),
        )
        broker_init = service[service.index("pbns_broker_init"):]
        self.assertNotIn("pbns_usb_transport_as_transport(service->usb_transport)", broker_init)
        for required in ("192.168.1.180", "PBNS_TLS_ALPN_PROTOCOL", "PbnsTlsTransportLib"):
            with self.subTest(required=required):
                self.assertIn(required, trust + manifest + application)
        for forbidden in ("GetTime", "gRT->", "pico", "credentials.h", "tls_client.h"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, trust)

        matrix = self.matrix.read_text(encoding="utf-8")
        self.assertIn("--case signed-trusted", matrix)
        self.assertIn("task14c-signed-final-20260810T022831Z.DBx3aC", matrix)
        self.assertIn("/repository/artifacts/$expected_uki_sha256", matrix)
        self.assertNotIn("recovery-build-20260810-serial-final/PBNSRecovery.efi", matrix)
        for required in (
            '[[ -f $signed_uki && ! -L $signed_uki ]]',
            '$(stat -c %u "$signed_uki") -ne $EUID',
            '$(stat -c %a "$signed_uki") != 444',
            '$(basename -- "$signed_uki") != $expected_uki_sha256',
            '$(stat -c %s "$signed_uki") -ne $expected_uki_size',
            '$(sha256sum "$signed_uki" | awk \'{print $1}\') != $expected_uki_sha256',
        ):
            with self.subTest(required=required):
                self.assertIn(required, matrix)
        self.assertIn('install -m 0600 "$signed_uki" "$artifact_input"', matrix)
        duration_command = 'stream_duration_ms=$(python3 "$script_dir/verify-recovery-observability.py"'
        self.assertEqual(matrix.count(duration_command), 1)
        self.assertIn("--print-stream-duration", matrix)
        self.assertIn('[[ $stream_duration_ms =~ ^(0|[1-9][0-9]*)$ ]]', matrix)
        self.assertIn('[[ $stream_duration_ms -le 60000 ]]', matrix)
        self.assertLess(matrix.index('hash_disk "$disk" "$disk_after"'), matrix.index(duration_command))
        self.assertNotIn('python3 - "$serial"', matrix)
        self.assertNotIn("PBNS RECOVERY STREAM DURATION MS=", matrix)
        self.assertNotIn("/proc/uptime", matrix)
        self.assertIn('"duration_ms"', self.matrix.read_text(encoding="utf-8"))
        self.assertIn("60000", self.matrix.read_text(encoding="utf-8"))
        recovery = (self.pbns_root / "uefi" / "Applications" / "PBNSRecovery" / "PBNSRecovery.c").read_text(encoding="utf-8")
        self.assertIn("PbnsUefiMonotonicMs", recovery)
        self.assertIn("PBNS RECOVERY STREAM DURATION MS=%Lu", recovery)
        self.assertLess(recovery.index("PbnsUefiMonotonicMs"), recovery.index("PbnsRecoveryServiceStream"))

    def test_task14c_transfer_deadline_contract_is_bound_across_layers(self) -> None:
        trust = (self.pbns_root / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryTrust.c").read_text(encoding="utf-8")
        gateway_config = (self.pbns_root / "gateway" / "internal" / "config" / "config.go").read_text(encoding="utf-8")
        gateway_service = (self.pbns_root / "gateway" / "internal" / "recovery" / "service.go").read_text(encoding="utf-8")
        driver = (self.pbns_root / "integration" / "qemu" / "recovery-live-driver.py").read_text(encoding="utf-8")
        matrix = self.matrix.read_text(encoding="utf-8")

        self.assertIn("PBNS_RECOVERY_MANIFEST_DEADLINE_MS UINT32_C(600000)", trust)
        self.assertIn("PBNS_RECOVERY_ARTIFACT_DEADLINE_MS UINT32_C(2700000)", trust)
        self.assertIn("PBNS_RECOVERY_ARTIFACT_DEADLINE_MS);", trust)
        self.assertIn("--recovery-transfer-timeout 45m", matrix)
        self.assertIn("--read-timeout 60s", matrix)
        self.assertIn("deadline_seconds: float = 2760.0", driver)
        self.assertIn("boundedRecoveryDuration(config.RecoveryTransferTimeout, 60*time.Minute)", gateway_config)
        self.assertIn("boundedDuration(config.TransferTimeout, 60*time.Minute)", gateway_service)

    def test_hash_tool_accepts_only_private_regular_state_images(self) -> None:
        self.assertTrue(os.access(self.hash_tool, os.X_OK))
        with tempfile.TemporaryDirectory(dir=self.pbns_root / "integration" / "state") as directory:
            image = pathlib.Path(directory) / "disk.raw"
            image.write_bytes(b"PBNS disposable disk")
            image.chmod(0o600)
            completed = subprocess.run(
                [str(self.hash_tool), str(image)],
                cwd=self.pbns_root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertRegex(completed.stdout, r"^[0-9a-f]{64}  [0-9]+  disk.raw\n$")
            link = pathlib.Path(directory) / "link.raw"
            link.symlink_to(image)
            rejected = subprocess.run(
                [str(self.hash_tool), str(link)],
                cwd=self.pbns_root.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_physical_gate_is_result_only_and_exactly_scoped(self) -> None:
        source = self.physical.read_text(encoding="utf-8")
        for required in (
            "PBNS_PHYSICAL_RECOVERY_CONFIRMED",
            "PBNS_PHYSICAL_RECOVERY_RESULT",
            "PBNS_PHYSICAL_RECOVERY_DEVICE",
            "/dev/sdc",
            'mode 0600',
            '"physical-platform"',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "dd ",
            "mkfs",
            "mount ",
            "efibootmgr -c",
            "tpm2_clear",
            "sbkeysync",
        ):
            self.assertNotIn(forbidden, source)

    def test_public_qemu_policy_result_stays_narrow_and_blocked(self) -> None:
        result_path = (
            self.pbns_root
            / "eval"
            / "results"
            / "recovery-uki-policy-20260802-qemu.json"
        )
        result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(result["schema"], "pbns-recovery-result-v1")
        self.assertEqual(result["evidence_class"], "emulated-system")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["checks"]["uki-policy"], "pass")
        self.assertEqual(result["checks"]["disk-immutability"], "pass")
        self.assertEqual(result["checks"]["secureboot-memory-load"], "blocked")
        self.assertFalse(result["secure_boot_enabled"])
        self.assertEqual(
            result["disk_before_sha256"], result["disk_after_sha256"]
        )

    def test_live_qemu_result_is_published_only_after_all_runtime_oracles(self) -> None:
        source = self.matrix.read_text(encoding="utf-8")
        for marker in (
            "recovery-live-qemu.json",
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
            "SecureBoot=1 SetupMode=0",
            "disk-before.sha256",
            "disk-after.sha256",
            "nv-before.bin",
            "nv-after.bin",
            "PBNS_RECOVERY_MATRIX_BLOCKED",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        live_result = self.pbns_root / "eval" / "results" / "recovery-live-qemu.json"
        if live_result.exists():
            result = json.loads(live_result.read_text(encoding="utf-8"))
            self.assertEqual(result["schema"], "pbns-recovery-result-v1")
            self.assertEqual(result["evidence_class"], "emulated-system")
            self.assertEqual(result["secure_boot_enabled"], True)
            self.assertEqual(result["setup_mode"], False)
            self.assertEqual(result["disk_before_sha256"], result["disk_after_sha256"])
            self.assertEqual(result["checks"]["physical-recovery"], "not-run")
            for name in (
                "launcher", "manifest", "stream", "anti-rollback", "uki-policy",
                "secureboot-memory-load", "disk-immutability", "normal-pico-absent",
            ):
                with self.subTest(check=name):
                    self.assertEqual(result["checks"][name], "pass")

    def test_recovery_schema_distinguishes_blocked_not_run_and_pass(self) -> None:
        schema_path = self.pbns_root / "eval" / "schema" / "recovery-result.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        serialized = json.dumps(schema, sort_keys=True)
        for marker in (
            "pbns-recovery-result-v1",
            "emulated-system",
            "physical-platform",
            "blocked",
            "not-run",
            "pass",
            "disk_before_sha256",
            "disk_after_sha256",
        ):
            self.assertIn(marker, serialized)

    def test_recovery_schema_keeps_policy_results_compatible_and_defines_closed_live_fields(self) -> None:
        schema_path = self.pbns_root / "eval" / "schema" / "recovery-result.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        policy = json.loads((self.pbns_root / "eval" / "results" / "recovery-uki-policy-20260802-qemu.json").read_text(encoding="utf-8"))
        self.assertTrue(set(schema["required"]).issubset(policy))
        self.assertFalse(schema["additionalProperties"])
        for key in ("recorded_utc", "ovmf_code_sha256", "ovmf_variables_sha256", "artifacts", "cases"):
            with self.subTest(key=key):
                self.assertIn(key, schema["properties"])
        artifact = schema["$defs"]["artifact"]
        self.assertEqual(artifact["required"], ["sha256", "size"])
        self.assertFalse(artifact["additionalProperties"])
        case = schema["$defs"]["case"]
        self.assertFalse(case["additionalProperties"])
        self.assertEqual(set(case["required"]), {"status", "artifact_sha256", "nv_version_before", "nv_version_after", "disk_before_sha256", "disk_after_sha256"})
        self.assertEqual(len(schema["properties"]["artifacts"]["properties"]), 3)
        self.assertEqual(len(schema["properties"]["cases"]["properties"]), 10)


if __name__ == "__main__":
    unittest.main()
