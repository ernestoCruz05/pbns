import importlib.util
import json
import pathlib
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = (
    pathlib.Path(__file__).parents[2]
    / "integration"
    / "hil"
    / "pico-network-diagnostic.py"
)
SPEC = importlib.util.spec_from_file_location("pico_network_diagnostic", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Pico network diagnostic")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PicoNetworkDiagnosticTest(unittest.TestCase):
    def make_device(
        self,
        root: pathlib.Path,
        name: str = "1-3",
        *,
        product_id: str = "40d1",
        product: str = "PBNS Network Diagnostic v1",
        bcd_device: str = "9100",
    ) -> pathlib.Path:
        device = root / name
        device.mkdir()
        values = {
            "idVendor": "cafe\n",
            "idProduct": f"{product_id}\n",
            "bcdDevice": f"{bcd_device}\n",
            "bNumInterfaces": "2\n",
            "product": f"{product}\n",
            "serial": "E66130100F527A26\n",
        }
        for key, value in values.items():
            (device / key).write_text(value, encoding="ascii")
        for number, interface_class in (("00", "02"), ("01", "0a")):
            interface = root / f"{name}:1.{int(number)}"
            interface.mkdir()
            (interface / "bInterfaceNumber").write_text(
                f"{number}\n", encoding="ascii"
            )
            (interface / "bInterfaceClass").write_text(
                f"{interface_class}\n", encoding="ascii"
            )
        return device

    def test_exact_initial_identity_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_device(root)
            identity = module.verify_diagnostic_identity(
                root,
                expected_serial="E66130100F527A26",
                allowed_bcd=frozenset(("9100",)),
            )
            self.assertEqual(identity["product_id"], "40d1")
            self.assertEqual(identity["bcd_device"], "9100")

    def test_missing_cdc_data_interface_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_device(root)
            for path in (root / "1-3:1.1").iterdir():
                path.unlink()
            (root / "1-3:1.1").rmdir()
            with self.assertRaises(module.DiagnosticError):
                module.verify_diagnostic_identity(
                    root,
                    expected_serial="E66130100F527A26",
                    allowed_bcd=frozenset(("9100",)),
                )

    def test_production_identity_and_ambiguity_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_device(
                root,
                product_id="4011",
                product="PBNS Proxy v1",
                bcd_device="0100",
            )
            with self.assertRaises(module.DiagnosticError):
                module.verify_diagnostic_identity(
                    root,
                    expected_serial="E66130100F527A26",
                    allowed_bcd=frozenset(("0100",)),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_device(root, "1-3")
            self.make_device(root, "1-4")
            with self.assertRaises(module.DiagnosticError):
                module.verify_diagnostic_identity(
                    root,
                    expected_serial="E66130100F527A26",
                    allowed_bcd=frozenset(("9100",)),
                )

    def test_unknown_or_awaiting_terminal_result_is_rejected(self) -> None:
        for code in ("9100", "9188", "0100"):
            with self.subTest(code=code):
                with self.assertRaises(module.DiagnosticError):
                    module.validate_terminal_evidence(code, ())

    def test_pre_tcp_results_require_no_gateway_events(self) -> None:
        for code in ("9110", "9120", "9130", "9140", "9141", "9142", "9143"):
            with self.subTest(code=code):
                self.assertEqual(
                    module.validate_terminal_evidence(code, ()),
                    module.EXPECTED_CODES[code],
                )
                with self.assertRaises(module.DiagnosticError):
                    module.validate_terminal_evidence(code, ("tcp-accepted",))

    def test_refined_wifi_timeouts_require_no_gateway_events(self) -> None:
        expected = {
            "9170": "wifi-timeout-down",
            "9171": "wifi-timeout-join",
            "9172": "wifi-timeout-noip",
            "9173": "wifi-timeout-unknown",
        }
        for code, name in expected.items():
            with self.subTest(code=code):
                self.assertEqual(module.validate_terminal_evidence(code, ()), name)
                with self.assertRaises(module.DiagnosticError):
                    module.validate_terminal_evidence(code, ("tcp-accepted",))

    def test_tcp_tls_and_ready_results_are_correlated(self) -> None:
        self.assertEqual(
            module.validate_terminal_evidence("9150", ()), "tcp-failure"
        )
        self.assertEqual(
            module.validate_terminal_evidence("9151", ("tcp-accepted",)),
            "tcp-timeout",
        )
        self.assertEqual(
            module.validate_terminal_evidence("9160", ("tcp-accepted",)),
            "tls-failure",
        )
        self.assertEqual(
            module.validate_terminal_evidence(
                "9190", ("tcp-accepted", "tls-established")
            ),
            "tls-ready",
        )
        for code, events in (
            ("9161", ()),
            ("9160", ("tcp-accepted", "tls-established")),
            ("9190", ("tcp-accepted",)),
            ("9190", ("tls-established", "tcp-accepted", "tcp-accepted")),
        ):
            with self.subTest(code=code, events=events):
                with self.assertRaises(module.DiagnosticError):
                    module.validate_terminal_evidence(code, events)

    def test_matching_san_certificate_preserves_pinned_spki(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            certificate = module.make_matching_certificate(
                pathlib.Path(directory), server_name="192.0.2.1"
            )
            details = subprocess.run(
                ["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("IP Address:192.0.2.1", details)
            self.assertEqual(
                module.certificate_spki_sha256(certificate),
                (module.TLS_FIXTURES / "tls-gateway-test-spki.sha256")
                .read_text(encoding="ascii")
                .strip(),
            )

    def test_invalid_server_name_fails_before_openssl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(module.subprocess, "run") as run:
                with self.assertRaises(module.DiagnosticError):
                    module.make_matching_certificate(
                        pathlib.Path(directory), server_name="bad;name"
                    )
                run.assert_not_called()

    def test_result_is_private_and_rejects_sensitive_keys(self) -> None:
        result = {
            "diagnostic_firmware_sha256": "a" * 64,
            "elapsed_ms": 123,
            "events": [],
            "result_code": "9141",
            "result_name": "wifi-authentication-failure",
            "usb_serial": "E66130100F527A26",
        }
        with tempfile.TemporaryDirectory() as directory:
            output, manifest = module.write_result(
                pathlib.Path(directory), result, timestamp="20260730T120000Z"
            )
            self.assertEqual(json.loads(output.read_text()), result)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o600)
            original_output = output.read_bytes()
            original_manifest = manifest.read_bytes()
            with self.assertRaises(module.DiagnosticError):
                module.write_result(
                    pathlib.Path(directory), result, timestamp="20260730T120000Z"
                )
            self.assertEqual(output.read_bytes(), original_output)
            self.assertEqual(manifest.read_bytes(), original_manifest)
            with self.assertRaises(module.DiagnosticError):
                module.write_result(
                    pathlib.Path(directory),
                    {**result, "credential_record": "forbidden"},
                    timestamp="20260730T120001Z",
                )

    def test_serial_source_never_reads_or_writes_payload(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("serial_port.write", source)
        self.assertNotIn("serial_port.read", source)
        self.assertIn("serial_port.dtr = True", source)
        self.assertIn("exclusive=True", source)
        self.assertIn("os.link(temporary, path)", source)
        self.assertIn('run.add_argument("--server-name", required=True)', source)
        self.assertNotIn("TRANSPORT PASS", source)


if __name__ == "__main__":
    unittest.main()
