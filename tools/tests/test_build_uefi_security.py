import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest


EXPECTED_COMMIT = "b03a21a63e3bd001f52c527e5a57feddb53a690b"
APPLICATIONS = (
    "PbnsProbe PbnsIdentityProbe PbnsCoseProbe PbnsTlsProbe PbnsTime "
    "PbnsTimeLive PbnsBaseline PbnsAttest PbnsEnroll PBNSLauncher "
    "PBNSRecovery PbnsBootSetup"
)


class BuildUefiSecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.source_script = pathlib.Path(__file__).parents[1] / "build-uefi.sh"

    @staticmethod
    def _write_executable(path: pathlib.Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def _fixture(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        pbns = root / "pbns"
        tools = pbns / "tools"
        application = pbns / "uefi" / "Applications" / "PbnsAttest"
        enrollment_application = pbns / "uefi" / "Applications" / "PbnsEnroll"
        fake_bin = root / "fake-bin"
        edk2 = root / "edk2"
        for directory in (
            tools,
            application,
            enrollment_application,
            fake_bin,
            edk2 / "BaseTools" / "BinWrappers" / "PosixLike",
            edk2 / "BaseTools" / "Source" / "C" / "bin",
            pbns / "gateway",
            pbns / "vendor" / "t_cose",
            pbns / "patches" / "t_cose",
            pbns / "cmake",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.source_script, tools / "build-uefi.sh")
        (tools / "build-uefi.sh").chmod(0o755)
        (application / "PbnsDeploymentTrustBuild.c").write_text(
            "#include <PbnsDeploymentTrust.c>\n", encoding="ascii"
        )
        (application / "PbnsAttest.inf").write_text("[Sources]\n", encoding="ascii")
        (enrollment_application / "PbnsDeploymentTrustBuild.c").write_text(
            "#include <PbnsDeploymentTrust.c>\n", encoding="ascii"
        )
        (enrollment_application / "PbnsEnrollmentTrustBuild.c").write_text(
            "#include <PbnsEnrollmentTrust.c>\n", encoding="ascii"
        )
        (enrollment_application / "PbnsEnroll.inf").write_text("[Sources]\n", encoding="ascii")
        (pbns / "cmake" / "PrepareTCose.cmake").write_text("fixture\n", encoding="ascii")
        for patch in (
            "0001-free-openssl-ec-temporaries.patch",
            "0002-zero-transient-encryption-material.patch",
        ):
            (pbns / "patches" / "t_cose" / patch).write_text("fixture\n", encoding="ascii")
        bundle = root / "deployment.bundle"
        bundle.write_text("fixture bundle\n", encoding="ascii")
        bundle.chmod(0o444)
        enrollment_bundle = root / "enrollment.bundle"
        enrollment_bundle.write_text("fixture enrollment bundle\n", encoding="ascii")
        enrollment_bundle.chmod(0o444)

        self._write_executable(
            fake_bin / "git",
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                case "$*" in
                    *"rev-parse HEAD"*) printf '%s\\n' '{EXPECTED_COMMIT}' ;;
                    *"submodule status --recursive"*) exit 0 ;;
                    *"status --porcelain"*) exit 0 ;;
                    *"submodule foreach"*) exit 0 ;;
                    *"show -s --format=%ct"*) printf '%s\\n' '1700000000' ;;
                    *) printf 'unexpected fake git invocation: %s\\n' "$*" >&2; exit 9 ;;
                esac
                """
            ),
        )
        self._write_executable(
            fake_bin / "go",
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                header=
                source=
                while (($#)); do
                    case "$1" in
                        --header) header=$2; shift 2 ;;
                        --source) source=$2; shift 2 ;;
                        *) shift ;;
                    esac
                done
                printf '%s\n' '#define PBNS_FIXTURE 1' >"$header"
                printf '%s\n' 'const int pbns_fixture = 1;' >"$source"
                chmod 0444 "$header" "$source"
                """
            ),
        )
        self._write_executable(
            fake_bin / "cmake",
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                destination=
                for argument in "$@"; do
                    case "$argument" in
                        -DPBNS_T_COSE_DESTINATION=*) destination=${argument#*=} ;;
                    esac
                done
                mkdir -p "$destination/src"
                printf '%s\n' 't_cose_crypto_secure_zero(cek_buffer)' >"$destination/src/t_cose_encrypt_enc.c"
                """
            ),
        )
        self._write_executable(fake_bin / "patch", "#!/usr/bin/env bash\nexit 0\n")
        self._write_executable(
            edk2 / "BaseTools" / "Source" / "C" / "bin" / "GenFw",
            "#!/usr/bin/env bash\nexit 0\n",
        )
        self._write_executable(
            edk2 / "BaseTools" / "BinWrappers" / "PosixLike" / "build",
            "#!/usr/bin/env bash\nexit 99\n",
        )
        (edk2 / "edksetup.sh").write_text(
            textwrap.dedent(
                f"""\
                build() {{
                    if [[ " $* " == *" cleanall "* ]]; then
                        return 0
                    fi
                    case "${{PBNS_TEST_BUILD_BEHAVIOR:-success}}" in
                        mutate-content)
                            chmod 0644 "$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.c"
                            printf '%s\\n' mutation >>"$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.c"
                            ;;
                        replace-symlink)
                            cp "$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.c" \\
                                "$PBNS_DEPLOYMENT_GENERATED_ABS/.replacement"
                            chmod 0444 "$PBNS_DEPLOYMENT_GENERATED_ABS/.replacement"
                            rm -f "$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.c"
                            ln -s .replacement "$PBNS_DEPLOYMENT_GENERATED_ABS/PbnsDeploymentTrust.c"
                            ;;
                        mutate-enrollment)
                            chmod 0644 "$PBNS_ENROLLMENT_GENERATED_ABS/PbnsEnrollmentTrust.c"
                            printf '%s\n' mutation >>"$PBNS_ENROLLMENT_GENERATED_ABS/PbnsEnrollmentTrust.c"
                            ;;
                        success) ;;
                        *) return 8 ;;
                    esac
                    output_root="$WORKSPACE/Build/PbnsPkg/${{BUILD_TARGET}}_GCC/X64"
                    mkdir -p "$output_root"
                    for application in {APPLICATIONS}; do
                        printf 'fixture efi\\n' >"$output_root/${{application}}.efi"
                    done
                }}
                """
            ),
            encoding="ascii",
        )
        return tools / "build-uefi.sh", bundle, enrollment_bundle, edk2

    def _run(
        self,
        root: pathlib.Path,
        behavior: str = "success",
        unsafe_build_parent: str | None = None,
        include_enrollment_bundle: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        script, bundle, enrollment_bundle, edk2 = self._fixture(root)
        if unsafe_build_parent == "mode":
            (root / "pbns" / "build").mkdir(mode=0o755)
        elif unsafe_build_parent == "symlink":
            (root / "build-victim").mkdir(mode=0o700)
            (root / "pbns" / "build").symlink_to(root / "build-victim")
        elif unsafe_build_parent is not None:
            raise ValueError(f"unknown unsafe build parent: {unsafe_build_parent}")
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{root / 'fake-bin'}:{environment['PATH']}",
                "PBNS_EDK2_DIR": str(edk2),
                "PBNS_DEPLOYMENT_BUNDLE": str(bundle),
                "PBNS_TEST_BUILD_BEHAVIOR": behavior,
            }
        )
        if include_enrollment_bundle:
            environment["PBNS_ENROLLMENT_BUNDLE"] = str(enrollment_bundle)
        return subprocess.run(
            [str(script)],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def _assert_generation_cleaned(self, root: pathlib.Path) -> None:
        build_parent = root / "pbns" / "build"
        self.assertTrue(build_parent.is_dir())
        self.assertEqual(stat.S_IMODE(build_parent.lstat().st_mode), 0o700)
        self.assertEqual(list(build_parent.glob("deployment.*")), [])
        self.assertEqual(list(build_parent.glob("enrollment.*")), [])

    def test_fake_build_success_and_failures_always_cleanup(self) -> None:
        for behavior, expected_success in (
            ("success", True),
            ("mutate-content", False),
            ("replace-symlink", False),
            ("mutate-enrollment", False),
        ):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory(
                prefix="pbns-build-uefi-"
            ) as directory:
                root = pathlib.Path(directory) / "repo"
                root.mkdir()
                result = self._run(root, behavior)
                if expected_success:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("UEFI BUILD PASS", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Unsafe post-build trust input", result.stderr)
                    self.assertNotIn("UEFI BUILD PASS", result.stdout)
                self._assert_generation_cleaned(root)

    def test_requires_enrollment_bundle_before_edk_setup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pbns-build-uefi-") as directory:
            root = pathlib.Path(directory) / "repo"
            root.mkdir()
            result = self._run(root, include_enrollment_bundle=False)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("PBNS_ENROLLMENT_BUNDLE is required", result.stderr)
            self.assertFalse((root / "pbns" / "build").exists())

    def test_rejects_unsafe_existing_build_parents(self) -> None:
        for unsafe_kind in ("mode", "symlink"):
            with self.subTest(unsafe_kind=unsafe_kind), tempfile.TemporaryDirectory(
                prefix="pbns-build-uefi-"
            ) as directory:
                root = pathlib.Path(directory) / "repo"
                root.mkdir()
                result = self._run(root, unsafe_build_parent=unsafe_kind)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("mode 0700 directory", result.stderr)
                self.assertNotIn("UEFI BUILD PASS", result.stdout)

    def test_rejects_differentiated_shell_unsafe_edk_paths(self) -> None:
        malicious_components = (
            "edk space",
            "edk'quote",
            "edk\"doublequote",
            "edk;semicolon",
            "edk$dollar",
            "edk`backtick",
            "edk\nnewline",
            "edk*glob",
        )
        with tempfile.TemporaryDirectory(prefix="pbns-build-uefi-") as directory:
            root = pathlib.Path(directory) / "repo"
            root.mkdir()
            script, bundle, enrollment_bundle, _ = self._fixture(root)
            for component in malicious_components:
                with self.subTest(component=component):
                    malicious = root / component
                    malicious.mkdir()
                    environment = os.environ.copy()
                    environment.update(
                        {
                            "PATH": f"{root / 'fake-bin'}:{environment['PATH']}",
                            "PBNS_EDK2_DIR": str(malicious),
                            "PBNS_DEPLOYMENT_BUNDLE": str(bundle),
                            "PBNS_ENROLLMENT_BUNDLE": str(enrollment_bundle),
                        }
                    )
                    result = subprocess.run(
                        [str(script)], cwd=root, env=environment, text=True,
                        capture_output=True, check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("Unsafe absolute path PBNS_EDK2_DIR", result.stderr)

    def test_rejects_unsafe_checkout_root_before_build(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pbns-build-uefi-") as directory:
            root = pathlib.Path(directory) / "repo with space"
            root.mkdir()
            script, bundle, enrollment_bundle, edk2 = self._fixture(root)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{root / 'fake-bin'}:{environment['PATH']}",
                    "PBNS_EDK2_DIR": str(edk2),
                    "PBNS_DEPLOYMENT_BUNDLE": str(bundle),
                    "PBNS_ENROLLMENT_BUNDLE": str(enrollment_bundle),
                }
            )
            result = subprocess.run(
                [str(script)], cwd=root, env=environment, text=True,
                capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("Unsafe absolute path PBNS_ROOT", result.stderr)
            self.assertFalse((root / "pbns" / "build").exists())


if __name__ == "__main__":
    unittest.main()
