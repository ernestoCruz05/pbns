#!/usr/bin/env python3
import importlib.util
import os
import pathlib
import signal
import subprocess
import tempfile
import types
import unittest
from unittest import mock


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER_PATH = PBNS_ROOT / "integration" / "qemu" / "attestation-passthrough-driver.py"
PROVISIONER_PATH = PBNS_ROOT / "integration" / "qemu" / "provision-swtpm-ek.py"
RUNNER_PATH = PBNS_ROOT / "integration" / "qemu" / "run-attestation.sh"


def load_module(path: pathlib.Path, name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AttestationPassthroughTests(unittest.TestCase):
    def make_device(
        self,
        root: pathlib.Path,
        name: str,
        *,
        bus: str = "1",
        address: str = "7",
        vendor: str = "cafe",
        product_id: str = "4011",
        product: str = "PBNS Proxy v1",
        serial: str = "E66130100F527A26",
        bcd_device: str = "0100",
    ) -> pathlib.Path:
        device = root / name
        device.mkdir()
        values = {
            "busnum": bus,
            "devnum": address,
            "idVendor": vendor,
            "idProduct": product_id,
            "product": product,
            "serial": serial,
            "bcdDevice": bcd_device,
        }
        for key, value in values.items():
            (device / key).write_text(value + "\n", encoding="ascii")
        return device

    def test_exact_pico_becomes_one_bus_address_pair(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_passthrough")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_device(root, "1-2")
            self.make_device(root, "1-3", serial="WRONG")
            self.assertEqual(driver.select_pico(root), (1, 7))

    def test_selector_rejects_zero_or_multiple_complete_matches(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_passthrough_selection")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with self.assertRaises(driver.SelectionError):
                driver.select_pico(root)
            self.make_device(root, "1-2", bus="1", address="7")
            self.make_device(root, "2-1", bus="2", address="4")
            with self.assertRaises(driver.SelectionError):
                driver.select_pico(root)

    def test_stock_qemu_command_uses_only_exact_numeric_passthrough(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_passthrough_command")
        command = driver.build_qemu_command(
            code=pathlib.Path("/run/pbns/OVMF_CODE.fd"),
            variables=pathlib.Path("/run/pbns/OVMF_VARS.fd"),
            esp=pathlib.Path("/run/pbns/esp"),
            swtpm_control=pathlib.Path("/run/pbns/swtpm.ctrl"),
            hostbus=1,
            hostaddr=7,
        )
        joined = " ".join(command)
        self.assertEqual(command[0], "qemu-system-x86_64")
        for marker in (
            "q35,accel=tcg",
            "-nic none",
            "qemu-xhci,id=xhci",
            "usb-host,bus=xhci.0,hostbus=1,hostaddr=7",
            "tpm-tis,tpmdev=tpm0",
            "if=pflash,format=raw,readonly=on,file=/run/pbns/OVMF_CODE.fd",
            "if=pflash,format=raw,file=/run/pbns/OVMF_VARS.fd",
            "format=raw,file=fat:rw:/run/pbns/esp",
        ):
            self.assertIn(marker, joined)
        for forbidden in (
            "vendorid=",
            "productid=",
            "-enable-kvm",
            "/dev/tpm",
            "/dev/sd",
            "/dev/nvme",
        ):
            self.assertNotIn(forbidden, joined)

    def test_provisioner_rejects_relative_tcti_before_tool_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private = pathlib.Path(directory)
            private.chmod(0o700)
            completed = subprocess.run(
                [
                    "python3",
                    str(PROVISIONER_PATH),
                    "--tcti",
                    "swtpm:path=relative.sock",
                    "--private-dir",
                    str(private),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("absolute", completed.stderr)

    def test_selected_pico_is_revalidated_before_launch(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_passthrough_revalidation")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            device = self.make_device(root, "1-2", bus="1", address="7")
            driver.validate_selected_pico(root, 1, 7)
            (device / "serial").write_text("REPLACED\n", encoding="ascii")
            with self.assertRaises(driver.SelectionError):
                driver.validate_selected_pico(root, 1, 7)

    def test_driver_requires_clean_return_and_zero_qemu_exit(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_passthrough_result")
        valid = (
            b"PBNS ENROLL TPM CHECKPOINT PASS\r\n"
            b"PBNS ENROLL EFI RETURN 0x0\r\n"
        )
        self.assertIsNone(driver.enrollment_result_error(valid, 0, True, True))
        self.assertIsNotNone(driver.enrollment_result_error(valid, -15, True, True))
        for status in (b"0x1", b"0x8000000000000002", b"10"):
            self.assertIsNotNone(
                driver.enrollment_result_error(
                    valid.replace(b"0x0", status), 0, True, True
                )
            )
        self.assertIsNotNone(
            driver.enrollment_result_error(
                b"PBNS ENROLL TPM CHECKPOINT PASS\r\n", 0, True, True
            )
        )

    def test_token_is_redacted_before_failure_log_write(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_passthrough_redaction")
        token = bytearray(b"A" * 43)
        output = bytearray(b"prefix " + token + b" suffix " + token)
        self.assertTrue(driver.redact_token(output, token))
        self.assertNotIn(token, output)
        self.assertEqual(output.count(b"*" * 43), 2)

    def test_exact_nv_public_profile_rejects_extra_attribute(self) -> None:
        provisioner = load_module(PROVISIONER_PATH, "pbns_swtpm_ek_public")
        exact = """0x1c0000a:
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: ppwrite|writedefine|ppread|ownerread|authread|no_da|written|platformcreate
    value: 0x62072001
  size: 424
"""
        provisioner.validate_nv_public(exact, 424)
        with self.assertRaises(SystemExit):
            provisioner.validate_nv_public(
                exact.replace("ppwrite|", "ppwrite|authwrite|"), 424
            )

    def test_provisioner_uses_standard_ecc_index_and_verifies_readback(self) -> None:
        source = PROVISIONER_PATH.read_text(encoding="utf-8")
        for marker in (
            "0x01c0000a",
            "tpm2_createprimary",
            "ecc:null:aes128cfb",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt",
            "tpm2_nvdefine",
            "tpm2_nvwrite",
            "tpm2_nvreadpublic",
            "tpm2_nvread",
            "prime256v1",
            "openssl",
            "platformcreate|authread|ownerread|ppread|ppwrite|noda|writedefine",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("tpm2_nvundefine", source)

    def test_restoration_accepts_same_pico_after_usb_readdress(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_readdress")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_device(root, "1-2", bus="1", address="7")
            with mock.patch.object(driver, "checked_device_ids", return_value={1}):
                self.assertTrue(
                    driver.wait_for_pico_return(
                        root, pathlib.Path("/dev/bus/usb"), 1, 4, 0.1
                    )
                )

    def test_qemu_cleanup_kills_descendant_after_group_leader_exits(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_process_group")
        child = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            "print('ready', flush=True);time.sleep(30)"
        )
        parent = (
            "import subprocess,sys,time;"
            f"p=subprocess.Popen([sys.executable,'-c',{child!r}],stdout=subprocess.PIPE,text=True);"
            "p.stdout.readline();print('ready', flush=True);time.sleep(30)"
        )
        process = subprocess.Popen(
            ["python3", "-c", parent],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        assert process.stdout is not None
        try:
            self.assertEqual(process.stdout.readline().strip(), "ready")
            self.assertTrue(
                driver.stop_process(process, term_timeout=0.1, kill_timeout=1.0)
            )
            with self.assertRaises(ProcessLookupError):
                os.killpg(process.pid, 0)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.stdout.close()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass

    def test_driver_owns_signal_cleanup_and_pico_restoration(self) -> None:
        source = DRIVER_PATH.read_text(encoding="utf-8")
        self.assertIn("signal.SIGTERM", source)
        self.assertIn("os.killpg", source)
        self.assertIn("wait_for_pico_return", source)

    def test_preflight_accepts_only_baseline_authentication_rejection(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_passthrough_preflight")
        expected = (
            b"PBNS ATTEST FAILURE run status=-14 command=0x00000000\r\n"
            b"PBNS ATTEST EFI RETURN 0x1A\r\n"
        )
        self.assertIsNone(driver.attestation_preflight_error(expected, 0))
        for delimiter in (b"\r", b"\n", b"\r\n"):
            terminal = delimiter.join(
                (
                    b"PBNS ATTEST FAILURE run status=-14 command=0x00000000",
                    b"PBNS ATTEST EFI RETURN 0x1A",
                    b"",
                )
            )
            self.assertIsNone(driver.attestation_preflight_error(terminal, 0))
        self.assertIsNotNone(
            driver.attestation_preflight_error(
                expected.replace(b"status=-14", b"status=-11").replace(
                    b"0x1A", b"0x12"
                ),
                0,
            )
        )
        self.assertIsNotNone(
            driver.attestation_preflight_error(
                expected.replace(b"command=0x00000000", b"command=0x00000100"), 0
            )
        )
        self.assertIsNotNone(
            driver.attestation_preflight_error(
                expected.replace(b"0x1A", b"0x12"), 0
            )
        )
        marker = b"PBNS ATTEST FAILURE run status=-14 command=0x00000000"
        self.assertIsNotNone(
            driver.attestation_preflight_error(expected.replace(marker, b"prefix " + marker), 0)
        )
        self.assertIsNotNone(
            driver.attestation_preflight_error(expected.replace(marker, marker + b" suffix"), 0)
        )

    def test_attestation_requires_one_authenticated_full_receipt(self) -> None:
        driver = load_module(DRIVER_PATH, "pbns_attestation_passthrough_attest")
        valid = b"PBNS ATTEST FULL VERIFIED\r\nPBNS ATTEST EFI RETURN 0x0\r\n"
        self.assertIsNone(driver.attestation_result_error(valid, 0))
        for delimiter in (b"\r", b"\n", b"\r\n"):
            terminal = delimiter.join(
                (
                    b"PBNS ATTEST FULL VERIFIED",
                    b"PBNS ATTEST EFI RETURN 0x0",
                    b"",
                )
            )
            self.assertIsNone(driver.attestation_result_error(terminal, 0))
        self.assertIsNotNone(driver.attestation_result_error(valid.replace(b"0x0", b"0x1"), 0))
        self.assertIsNotNone(driver.attestation_result_error(valid + valid, 0))
        self.assertIsNotNone(driver.attestation_result_error(b"PBNS ATTEST FAILURE run\r\n", 0))
        marker = b"PBNS ATTEST FULL VERIFIED"
        self.assertIsNotNone(driver.attestation_result_error(valid.replace(marker, b"prefix " + marker), 0))
        self.assertIsNotNone(driver.attestation_result_error(valid.replace(marker, marker + b" suffix"), 0))

    def test_attestation_runner_rebuilds_signed_app_and_uses_one_selected_pair(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn("attestation-uefi-rebuild.log", source)
        self.assertIn("PBNS_UEFI_DEPLOYMENT_TRUST_HEADER", source)
        self.assertIn("--output \"$signed_dir/PbnsAttest.efi\" \"$pbns_attest\"", source)
        self.assertIn("stop_attestation_gateway", source)
        self.assertNotIn('--hostbus "$(python3 "$driver" select-pico', source)

    def test_attestation_runner_generates_loader_compatible_administrator_key(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn("openssl ecparam -name prime256v1 -genkey -noout", source)
        self.assertNotIn("openssl genpkey -algorithm EC", source)

    def test_attestation_runner_uses_non_hidden_temporary_go_signer(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('mktemp "$pbns_root/gateway/pbns-attestation-sign.', source)
        self.assertNotIn('gateway/.pbns-attestation-sign-', source)

    def test_attestation_runner_reads_enrollment_host_from_retained_evidence_root(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('"$evidence_dir/hosts.txt"', source)
        self.assertNotIn('"$private_dir/hosts.txt"', source)

    def test_attestation_runner_arms_cleanup_before_swtpm_resume(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        phase = source.index("if [[ $phase == attest ]]; then")
        resume = source.index("resume-swtpm.sh", phase)
        trap = source.index("trap attestation_cleanup EXIT", phase)
        active = source.index("swtpm_active=1", resume)
        self.assertLess(trap, resume)
        self.assertLess(resume, active)
        self.assertIn("if (( swtpm_active == 1 )); then", source[phase:active])

    def test_attestation_runner_requires_gateway_address_before_resuming_state(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        phase = source.index("if [[ $phase == attest ]]; then")
        resume = source.index("resume-swtpm.sh", phase)
        requirement = source.index("require_gateway_address", phase, resume)
        self.assertLess(requirement, resume)

    def test_attestation_runner_delegates_terminal_validation_to_driver(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("grep -ac 'PBNS ATTEST FULL VERIFIED'", source)
        self.assertNotIn("grep -aFxc 'PBNS ATTEST FULL VERIFIED'", source)

    def test_attestation_runner_refuses_existing_serial_outputs_before_launch(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn("! -e $preflight_log", source)
        self.assertIn("! -e $attest_log", source)

    def test_attestation_phase_has_only_explicit_checkpoint_outputs(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        for marker in (
            "pbns-attestation-checkpoint",
            "baseline propose",
            "--classification security",
            "baseline approve",
            "receipt.cose",
            "candidate.cbor",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("--baseline-learn", source)

    def test_runner_retains_private_state_and_never_wildcards_or_recurses(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        for marker in (
            "--phase",
            "select-pico",
            "hostbus",
            "hostaddr",
            "q35,accel=tcg",
            "-nic none",
            "integration/state/qemu/attestation-passthrough-current.path",
            "tpm-verified",
            "PBNS_DEPLOYMENT_BUNDLE",
            "PBNS_ENROLLMENT_BUNDLE",
            "virt-fw-vars",
            "sbsign",
            "sbverify --cert",
            "administrator-private.pem",
            "PbnsAttest.efi",
        ):
            self.assertIn(marker, source)
        for forbidden in (
            "vendorid=0xcafe",
            "productid=0x4011",
            "rm -rf",
            "/dev/tpm",
            "/dev/sd",
            "/dev/nvme",
            "-enable-kvm",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
