import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


PBNS_ROOT = pathlib.Path(__file__).parents[2]
MAKE_PKI = PBNS_ROOT / "integration" / "tls" / "make-test-pki.sh"
VERIFY_SPKI = PBNS_ROOT / "integration" / "tls" / "verify-spki.py"
EXPECTED_PIN = PBNS_ROOT / "tests" / "fixtures" / "keys" / "tls-gateway-test-spki.sha256"


class TlsToolsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(MAKE_PKI.is_file(), "missing TLS fixture generator")
        self.assertTrue(VERIFY_SPKI.is_file(), "missing SPKI verifier")

    def _make_pki(
        self, output: pathlib.Path, server_name: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = [str(MAKE_PKI), str(output)]
        if server_name is not None:
            command.append(server_name)
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def _verify(self, certificate: pathlib.Path, pin: pathlib.Path):
        return subprocess.run(
            [sys.executable, str(VERIFY_SPKI), str(certificate), str(pin)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_reissued_certificate_preserves_pin_and_wrong_key_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            generated = self._make_pki(output)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            for name in ("gateway-cert.pem", "gateway-reissued-cert.pem"):
                result = self._verify(output / name, EXPECTED_PIN)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "SPKI PASS\n")

            wrong = self._verify(output / "wrong-key-cert.pem", EXPECTED_PIN)
            self.assertNotEqual(wrong.returncode, 0)
            self.assertEqual(wrong.stderr, "SPKI verification failed\n")

    def test_ip_san_preserves_pin_and_isolates_wrong_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            generated = self._make_pki(output, "192.0.2.1")
            self.assertEqual(generated.returncode, 0, generated.stderr)
            for name in ("gateway-reissued-cert.pem", "wrong-key-cert.pem"):
                details = subprocess.run(
                    [
                        "openssl",
                        "x509",
                        "-in",
                        str(output / name),
                        "-noout",
                        "-ext",
                        "subjectAltName",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
                self.assertIn("IP Address:192.0.2.1", details)
            matching = self._verify(output / "gateway-reissued-cert.pem", EXPECTED_PIN)
            self.assertEqual(matching.returncode, 0, matching.stderr)
            wrong = self._verify(output / "wrong-key-cert.pem", EXPECTED_PIN)
            self.assertNotEqual(wrong.returncode, 0)

    def test_invalid_server_name_fails_before_openssl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "openssl-invoked"
            openssl = fake_bin / "openssl"
            openssl.write_text(
                "#!/bin/sh\n: >\"$PBNS_OPENSSL_MARKER\"\nexit 1\n",
                encoding="ascii",
            )
            openssl.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["PBNS_OPENSSL_MARKER"] = str(marker)
            result = subprocess.run(
                [str(MAKE_PKI), str(root / "output"), "bad;name"],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "invalid TLS server name\n")
            self.assertFalse(marker.exists())

    def test_generator_preserves_unrelated_output_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            unrelated = output / "unrelated.txt"
            unrelated.write_text("retain\n", encoding="ascii")
            nested = output / "nested"
            nested.mkdir()
            marker = nested / "marker.txt"
            marker.write_text("retain\n", encoding="ascii")
            matching_names = tuple(
                output / name
                for name in ("unrelated.csr", "unrelated.ext", "unrelated-key.pem")
            )
            for path in matching_names:
                path.write_text("retain\n", encoding="ascii")
                path.chmod(0o644)

            generated = self._make_pki(output)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertEqual(unrelated.read_text(encoding="ascii"), "retain\n")
            self.assertEqual(marker.read_text(encoding="ascii"), "retain\n")
            for path in matching_names:
                self.assertEqual(path.read_text(encoding="ascii"), "retain\n")
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_verifier_rejects_bad_pin_and_malformed_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            generated = self._make_pki(output)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            bad_pin = output / "bad-pin.sha256"
            bad_pin.write_text("00" * 32 + "\n", encoding="ascii")
            malformed = output / "malformed.pem"
            malformed.write_text("not a certificate\n", encoding="ascii")

            for certificate, pin in (
                (output / "gateway-cert.pem", bad_pin),
                (malformed, EXPECTED_PIN),
            ):
                result = self._verify(certificate, pin)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, "SPKI verification failed\n")
                self.assertNotIn("not a certificate", result.stderr)


if __name__ == "__main__":
    unittest.main()
