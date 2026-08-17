import os
import pathlib
import re
import subprocess
import tempfile
import unittest


class RecoveryImagePolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).resolve().parents[2]
        self.recovery = self.pbns_root / "recovery"
        self.module = self.recovery / "dracut" / "95pbns-recovery"
        self.live_policy = (
            self.pbns_root
            / "integration"
            / "swtpm"
            / "run-recovery-policy-live.sh"
        )

    def test_runtime_is_read_only_and_network_inert(self) -> None:
        init = (self.module / "pbns-recovery-init.sh").read_text(encoding="utf-8")
        rule = (self.module / "99-pbns-block-readonly.rules").read_text(
            encoding="utf-8"
        )
        combined = init + rule
        for required in (
            "blockdev --setro",
            "/usr/bin/blockdev --setro /dev/%k",
            "/sys/class/block",
            "tmpfs",
            "/run/pbns",
            "/dev/console",
            "udevadm trigger",
            "udevadm settle",
            "PBNS RECOVERY UNAVAILABLE-MEDIA SKIP",
            "blockdev --getsize64",
        ):
            with self.subTest(required=required):
                self.assertIn(required, combined)
        for forbidden in (
            "mount -o rw",
            "fsck -y",
            "mkfs",
            "fdisk",
            "parted",
            "wipefs",
            "sgdisk",
            "dhclient",
            "NetworkManager",
            "systemctl start network",
            "exec /bin/sh",
            "/etc/fstab",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)

    def test_write_enable_requires_exact_typed_device_and_logs_only_in_ram(self) -> None:
        helper = (self.module / "pbns-write-enable").read_text(encoding="utf-8")
        for required in (
            "model=",
            "size=",
            "path=",
            "read -r confirmation",
            '[[ $confirmation == "$device" ]]',
            "/run/pbns/write-enable.log",
            "blockdev --setrw",
        ):
            with self.subTest(required=required):
                self.assertIn(required, helper)
        self.assertLess(helper.index('[[ $confirmation == "$device" ]]'), helper.index("blockdev --setrw"))
        for forbidden in ("/var/log", "logger ", "tee /dev/"):
            self.assertNotIn(forbidden, helper)

    def test_initramfs_build_is_explicit_and_omits_automatic_write_paths(self) -> None:
        script = (self.recovery / "build-initramfs.sh").read_text(encoding="utf-8")
        for required in (
            "--kernel-version",
            "--kernel-image",
            "--output",
            "--no-hostonly",
            "--no-hostonly-cmdline",
            "--reproducible",
            "pbns-recovery-init.sh",
            "pbns-recovery-init.sh\"",
            "/usr/lib/dracut/hooks/cmdline/00-pbns-recovery.sh",
            "99-pbns-block-readonly.rules",
            "fstab-sys",
            "resume",
            "network",
        ):
            with self.subTest(required=required):
                self.assertIn(required, script)
        self.assertNotIn("uname -r", script)
        self.assertNotIn("/boot/vmlinuz", script)
        cmdline = (self.recovery / "uki.conf").read_text(encoding="utf-8")
        self.assertNotIn("root=tmpfs", cmdline)
        self.assertIn("rd.shell=0", cmdline)

    def test_uki_cmdline_has_ordered_graphical_and_serial_consoles(self) -> None:
        tokens = (self.recovery / "uki.conf").read_text(encoding="utf-8").split()
        safety_tokens = (
            "ro",
            "rd.neednet=0",
            "ip=off",
            "rd.auto=0",
            "rd.luks=0",
            "rd.lvm=0",
            "rd.md=0",
            "rd.dm=0",
            "rd.shell=0",
        )
        expected = [
            *safety_tokens,
            "console=tty0",
            "console=ttyS0,115200n8",
        ]
        self.assertEqual(tokens, expected)
        for token in safety_tokens:
            with self.subTest(token=token):
                self.assertEqual(tokens.count(token), 1)
        self.assertEqual(tokens.count("console=tty0"), 1)
        self.assertEqual(tokens.count("console=ttyS0,115200n8"), 1)
        self.assertLess(tokens.index("console=tty0"), tokens.index("console=ttyS0,115200n8"))

    def test_uki_build_hashes_every_input_and_rejects_test_key_in_release(self) -> None:
        script = (self.recovery / "build-uki.sh").read_text(encoding="utf-8")
        for required in (
            "SOURCE_DATE_EPOCH",
            "ukify",
            "sbverify",
            "kernel",
            "initramfs",
            "cmdline",
            "os-release",
            "stub",
            "signed-output",
            ".inputs.sha256",
            "PBNS_BUILD_PROFILE",
            "2C:A0:2D:42:49:A2:E4:3D:EE:A5:9E:BA:8D:6D:D7:EC:0E:5F:25:CB:22:C3:FD:42:83:8F:74:63:65:EC:88:25",
        ):
            with self.subTest(required=required):
                self.assertIn(required, script)
        self.assertRegex(script, re.compile(r"PBNS_BUILD_PROFILE.*release", re.DOTALL))
        self.assertNotIn("/home/", script)

    def test_builders_emit_complete_manifests_with_disposable_tool_shims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            dracut = tools / "dracut"
            dracut.write_text(
                "#!/bin/sh\nfor argument in \"$@\"; do output=$argument; done\n"
                "printf initramfs >\"$output\"\n",
                encoding="utf-8",
            )
            ukify = tools / "ukify"
            ukify.write_text(
                "#!/bin/sh\nfor argument in \"$@\"; do\n"
                "  case $argument in --output=*) output=${argument#--output=} ;; esac\n"
                "done\nprintf MZuki >\"$output\"\n",
                encoding="utf-8",
            )
            sbverify = tools / "sbverify"
            sbverify.write_text(
                "#!/bin/sh\nprintf 'signature certificates\\n'\n",
                encoding="utf-8",
            )
            for tool in (dracut, ukify, sbverify):
                tool.chmod(0o755)
            kernel = root / "kernel"
            kernel.write_bytes(b"kernel")
            initramfs = root / "recovery.img"
            environment = os.environ.copy()
            environment["PATH"] = f"{tools}:{environment['PATH']}"
            subprocess.run(
                [
                    str(self.recovery / "build-initramfs.sh"),
                    "--kernel-version",
                    "test",
                    "--kernel-image",
                    str(kernel),
                    "--output",
                    str(initramfs),
                ],
                cwd=self.pbns_root.parent,
                env=environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            init_manifest = pathlib.Path(f"{initramfs}.inputs.sha256").read_text(
                encoding="utf-8"
            )
            self.assertIn("  kernel-image\n", init_manifest)
            self.assertIn("  initramfs\n", init_manifest)
            for name in ("cmdline", "os-release", "stub"):
                (root / name).write_text(name, encoding="utf-8")
            uki = root / "PBNSRecovery.efi"
            subprocess.run(
                [
                    str(self.recovery / "build-uki.sh"),
                    "--kernel",
                    str(kernel),
                    "--initrd",
                    str(initramfs),
                    "--cmdline",
                    str(root / "cmdline"),
                    "--os-release",
                    str(root / "os-release"),
                    "--stub",
                    str(root / "stub"),
                    "--output",
                    str(uki),
                ],
                cwd=self.pbns_root.parent,
                env=environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            uki_manifest = pathlib.Path(f"{uki}.inputs.sha256").read_text(
                encoding="utf-8"
            )
            for label in (
                "kernel",
                "initramfs",
                "cmdline",
                "os-release",
                "stub",
                "signed-output",
            ):
                self.assertRegex(uki_manifest, rf"(?m)^[0-9a-f]{{64}}  {label}$")

    def test_scripts_reject_missing_arguments_without_side_effects(self) -> None:
        for name in ("build-initramfs.sh", "build-uki.sh"):
            script = self.recovery / name
            completed = subprocess.run(
                [str(script)],
                cwd=self.pbns_root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            with self.subTest(script=name):
                self.assertEqual(completed.returncode, 2)
                self.assertIn("usage:", completed.stderr)

    def test_live_policy_helper_has_one_fixed_disposable_tpm_profile(self) -> None:
        self.assertTrue(self.live_policy.is_file())
        self.assertTrue(os.access(self.live_policy, os.X_OK))
        source = self.live_policy.read_text(encoding="utf-8")
        for marker in (
            "0x01801000",
            "0x02020008",
            "tpm2_policynvwritten",
            "tpm2_policycphash",
            "tpm2_loadexternal -C o",
            "tpm2_verifysignature",
            "tpm2_policyauthorize",
            "recovery-manifest-test-public.pem",
            "openssl ec -in",
            "--verify-live",
            "PBNS_SWTPM_STATE_V1",
            "quiesce-swtpm-runtime.py",
            'TPM2TOOLS_TCTI="swtpm:path=$socket_path"',
            "4 5 downgrade-5",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        for command in (
            "tpm2_policynvwritten",
            "tpm2_policycphash",
            "tpm2_policyauthorize",
        ):
            with self.subTest(command=command):
                self.assertRegex(
                    source,
                    re.compile(rf"{command}[^\n]*(?:\\\n[^\n]*){{0,4}}>/dev/null"),
                )
        for forbidden in ("/dev/tpm", "device:", "abrmd", "tss2-esys", "fapi"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source.lower())

    def test_live_policy_helper_rejects_invalid_commands_before_tpm_access(self) -> None:
        invalid = (
            (),
            ("initialize", "/tmp/not-pbns", "0"),
            ("initialize", "/tmp/not-pbns", "4"),
            ("authorize", "/tmp/not-pbns", "5", "5", "target-5"),
            ("authorize", "/tmp/not-pbns", "5", "7", "../unsafe"),
            ("initialize", "/tmp/not-pbns", "5", "0x01801001"),
            ("read", "/tmp/not-pbns"),
        )
        for arguments in invalid:
            completed = subprocess.run(
                [str(self.live_policy), *arguments],
                cwd=self.pbns_root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            with self.subTest(arguments=arguments):
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("/dev/tpm", completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
