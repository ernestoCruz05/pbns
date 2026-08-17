import hashlib
import json
import pathlib
import unittest


class IdentityTimeGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).parents[2]
        self.live = self.pbns_root / "integration" / "qemu" / "run-enrollment-time.sh"
        self.verify = self.pbns_root / "tools" / "verify-identity-time.sh"
        self.schema = (
            self.pbns_root / "eval" / "schema" / "identity-time-result.schema.json"
        )
        self.preparation = self.pbns_root / "docs" / "hardware" / "bm1-platform.md"

    def test_qemu_live_gate_is_private_bounded_and_uses_exact_proxy(self) -> None:
        driver = self.pbns_root / "integration" / "qemu" / "enrollment-time-driver.py"
        contents = self.live.read_text(encoding="utf-8") + driver.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            "umask 077",
            "PBNS_GATEWAY_SERVER_NAME",
            "verify-spki.py",
            "enrollment-recipient-1",
            "enrollment-signer-1",
            "time-key-1",
            "openssl ec -in",
            "PbnsEnroll.efi",
            "PbnsTimeLive.efi",
            "start-swtpm.sh",
            "stop-swtpm.sh",
            "qemu-xhci",
            "vendorid=0xcafe",
            "productid=0x4011",
            '"-nic",\n        "none"',
            "sys.stdin.buffer.readline",
            "terminal_offset = output.find(terminal)",
            "enrollment_token=",
            "unset TOKEN",
            "PBNS ENROLL TOTAL MS",
            "PBNS TIME LIVE INTERVAL PASS",
            "PBNS TIME LIVE REPLAY REJECT PASS",
            "hosts=1",
            "IDENTITY TIME QEMU SWTPM PASS",
        ):
            self.assertIn(marker, contents)
        for forbidden in (
            "/dev/sda",
            "/dev/nvme",
            "chmod 777",
            "chmod a+",
            "-enable-kvm",
            "TOKEN=\"$2\"",
        ):
            self.assertNotIn(forbidden, contents)

    def test_verifier_has_all_gated_stages_and_no_implicit_physical_claim(self) -> None:
        contents = self.verify.read_text(encoding="utf-8")
        for marker in (
            "store",
            "identity",
            "tpm-policy",
            "enrollment-negative",
            "time-negative",
            "qemu-swtpm",
            "physical-tpm",
            "--require-physical-tpm",
            "IDENTITY TIME SOFTWARE GATES PASS",
        ):
            self.assertIn(marker, contents)
        self.assertIn("PHYSICAL GATE REQUIRED", contents)

    def test_public_live_results_are_hash_manifested_and_bounded(self) -> None:
        result_directory = self.pbns_root / "eval" / "results"
        expected = {
            "identity-time-20260801-software-qemu-pico.json": (
                "software-reduced",
                "software",
                "emulated-system-with-physical-proxy",
            ),
            "identity-time-20260801-tpm-qemu-pico.json": (
                "tpm",
                "tpm-unverified-ek",
                "emulated-system-with-physical-proxy",
            ),
            "identity-time-20260802-tpm-physical-msi-pico.json": (
                "tpm",
                "tpm-unverified-ek",
                "physical-platform",
            ),
        }
        manifest_entries = {}
        for line in (result_directory / "SHA256SUMS").read_text(
            encoding="ascii"
        ).splitlines():
            digest, name = line.split("  ", 1)
            manifest_entries[name] = digest
        self.assertEqual(set(manifest_entries), set(expected))
        for name, (identity_mode, assurance, evidence_class) in expected.items():
            encoded = (result_directory / name).read_bytes()
            self.assertEqual(
                hashlib.sha256(encoded).hexdigest(), manifest_entries[name]
            )
            result = json.loads(encoded)
            self.assertEqual(result["schema"], "pbns-identity-time-result-v1")
            self.assertEqual(result["evidence_class"], evidence_class)
            self.assertEqual(result["identity_mode"], identity_mode)
            self.assertEqual(result["assurance"], assurance)
            self.assertEqual(
                set(result["timing_ms"]),
                {
                    "baseline_local",
                    "init_crypto",
                    "begin_exchange",
                    "proof_crypto",
                    "complete_exchange",
                    "enrollment_total",
                    "trusted_time_total",
                },
            )
            self.assertTrue(
                all(value >= 0 for value in result["timing_ms"].values())
            )
            if evidence_class == "physical-platform":
                self.assertEqual(
                    result["checks"]["encrypted_token_capture"], "not-run"
                )
                self.assertEqual(
                    result["checks"]["raw_usb_secret_capture"], "not-run"
                )
                self.assertIn("pass", set(result["checks"].values()))
            else:
                self.assertEqual(set(result["checks"].values()), {"pass"})

    def test_result_schema_and_physical_preparation_bound_claims(self) -> None:
        schema = self.schema.read_text(encoding="utf-8")
        preparation = self.preparation.read_text(encoding="utf-8")
        for marker in (
            "pbns-identity-time-result-v1",
            "evidence_class",
            "identity_mode",
            "assurance",
            "timing_ms",
            "sha256",
        ):
            self.assertIn(marker, schema)
        for marker in (
            "AMD",
            "fTPM",
            "Secure Boot",
            "SHA-256",
            "Pico W",
            "physical",
        ):
            self.assertIn(marker, preparation)


if __name__ == "__main__":
    unittest.main()
