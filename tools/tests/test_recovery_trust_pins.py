#!/usr/bin/env python3
"""Verificações estáticas dos pins de confiança e do limite do serviço de recuperação."""

import hashlib
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "keys"
SERVICE_HEADER = ROOT / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryServiceLib.h"
SERVICE_SOURCE = ROOT / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryServiceLib.c"
TRUST_SOURCE = ROOT / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryTrust.c"
ROLLBACK_SOURCE = ROOT / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryRollbackUefi.c"
ADAPTER_SOURCE = ROOT / "src" / "core" / "recovery_service_adapter.c"
ASSURANCE_HEADER = ROOT / "include" / "pbns" / "recovery_assurance.h"
SERVICE_INF = ROOT / "uefi" / "Library" / "PbnsRecoveryServiceLib" / "PbnsRecoveryServiceLib.inf"

EC_FIXTURES = {
    "manifest": (
        "recovery-manifest-test-public.pem",
        "2e5d61fe51b1ec83393e8030808bfc50598bdcc8c8a7db9f9fb498fafa48313b",
        "cad9ef86bb4ec11f17c12faf30af00efe477afc916eff79bb48774876ecda8ad",
        "5238ce8dda8e5fe899483a0c2989ec052f79a26f4003d38e0596040dda5a1bdb",
    ),
    "policy": (
        "recovery-policy-test-public.pem",
        "1eb5dc01eed68563e2643f98da59b4db720f66547aefcb3beb6996715131cb58",
        "979d6bdb23ceb0659ccfc8f1d5f1989bc30c1dcf8f13e3a556c27406e2a67335",
        "49f25105f152f7b2108bb9e67a8686770dcfe8e023495b001bedf1572fe74394",
    ),
    "time": (
        "service-signing-test-public.pem",
        "184d9282e72f5b3f6e0ea73b42ac55d41f18588ac a5cc487365805d5782ab3ca".replace(" ", ""),
        "ee410fd3afa35894f5460d822daa3a3f62c61f620eff4f65ab7d0e31b94c7893",
        "aecb47376b51eddf66847722347e4a3b17b1cc3d3bb770f55108395ae15585f9",
    ),
}
RSA_FIXTURE = (
    "uki-secureboot-test-cert.pem",
    "478a1fcf6d78f3fc1276d18add8e67a5fe75b2392e51e9da207a0c3014c0390b",
)


def openssl(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["openssl", *args], input=data, check=True, capture_output=True
    ).stdout


def public_spki(path: Path, certificate: bool = False) -> bytes:
    if certificate:
        pem = openssl("x509", "-in", str(path), "-pubkey", "-noout")
        return openssl("pkey", "-pubin", "-outform", "DER", data=pem)
    return openssl("pkey", "-pubin", "-in", str(path), "-outform", "DER")


def p256_coordinates(path: Path) -> tuple[str, str]:
    text = openssl("pkey", "-pubin", "-in", str(path), "-text", "-noout").decode()
    match = re.search(r"pub:(.*?)ASN1 OID", text, re.S | re.I)
    if match is None:
        raise AssertionError(f"{path.name}: expected uncompressed P-256 point")
    encoded = re.findall(r"[0-9a-f]{2}", match.group(1), re.I)
    if len(encoded) != 65 or encoded[0] != "04":
        raise AssertionError(f"{path.name}: expected uncompressed P-256 point")
    point = "".join(encoded[1:]).lower()
    if "prime256v1" not in text.lower() or len(point) != 128:
        raise AssertionError(f"{path.name}: expected prime256v1 coordinates")
    return point[:64], point[64:]


def c_array_hex(source: str, name: str) -> str:
    match = re.search(
        rf"static const uint8_t {name}\[32\] = \{{(.*?)\}};", source, re.S
    )
    if match is None:
        raise AssertionError(f"missing {name}")
    return "".join(re.findall(r"0x([0-9a-f]{2})U", match.group(1), re.I)).lower()


def c_function_body(source: str, name: str) -> str:
    match = re.search(rf"(?:static )?[^(;]+\b{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if match is None:
        raise AssertionError(f"missing definition for {name}")
    depth = 1
    index = match.end()
    while index < len(source) and depth > 0:
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
        index += 1
    if depth != 0:
        raise AssertionError(f"unterminated definition for {name}")
    return source[match.end():index - 1]


class RecoveryTrustPinTests(unittest.TestCase):
    def test_public_fixture_coordinates_and_spki_fingerprints(self) -> None:
        fingerprints: list[str] = []
        for role, (filename, expected_x, expected_y, expected_digest) in EC_FIXTURES.items():
            with self.subTest(role=role):
                path = FIXTURES / filename
                self.assertEqual(p256_coordinates(path), (expected_x, expected_y))
                digest = hashlib.sha256(public_spki(path)).hexdigest()
                self.assertEqual(digest, expected_digest)
                fingerprints.append(digest)
        rsa_path = FIXTURES / RSA_FIXTURE[0]
        rsa_spki = public_spki(rsa_path, certificate=True)
        self.assertEqual(hashlib.sha256(rsa_spki).hexdigest(), RSA_FIXTURE[1])
        self.assertIn(b"\x06\x09*\x86H\x86\xf7\r\x01\x01\x01", rsa_spki)
        fingerprints.append(RSA_FIXTURE[1])
        self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_service_source_preserves_the_recovery_boundary(self) -> None:
        assurance = ASSURANCE_HEADER.read_text()
        header = SERVICE_HEADER.read_text()
        source = SERVICE_SOURCE.read_text()
        trust = TRUST_SOURCE.read_text()
        rollback = ROLLBACK_SOURCE.read_text()
        adapter = ADAPTER_SOURCE.read_text()
        inf = SERVICE_INF.read_text()
        for prefix, (_, expected_x, expected_y, _) in {
            "MANIFEST": EC_FIXTURES["manifest"],
            "POLICY": EC_FIXTURES["policy"],
            "TIME": EC_FIXTURES["time"],
        }.items():
            self.assertEqual(c_array_hex(trust, f"{prefix}_KEY_X"), expected_x)
            self.assertEqual(c_array_hex(trust, f"{prefix}_KEY_Y"), expected_y)
        self.assertIn("PBNS_RECOVERY_ASSURANCE_T = 1", assurance)
        self.assertIn("PBNS_RECOVERY_ASSURANCE_S = 2", assurance)
        self.assertIn("typedef struct PBNS_RECOVERY_SERVICE PBNS_RECOVERY_SERVICE;", header)
        self.assertIn("pbns_recovery_assurance_mode mode", header)
        self.assertIn("PBNS_IDENTITY_TPM_UNVERIFIED_EK", source)
        self.assertIn("PBNS_IDENTITY_SOFTWARE", source)
        self.assertNotRegex(source, r"mode\s*==.*\?.*:")
        self.assertIn("uint8_t *broker_workspace", source)
        self.assertIn("pbns_time_interval trusted_interval", source)
        self.assertIn("trusted_time_ready", source)
        self.assertIn("!service->trusted_time_ready", source)
        self.assertIn("plan->artifact_size = service->manifest_state.manifest.image_size", source)
        self.assertIn("plan->target_version = service->manifest_state.manifest.artifact_version", source)
        self.assertIn("CopyMem(plan->artifact_digest", source)
        self.assertIn("plan->version_authorization = service->manifest_state.manifest.policy_authorization", source)
        self.assertIn("signed_manifest", source + trust)
        self.assertIn("pbns_broker_request_with_id", trust)
        self.assertIn("PBNS_SERVICE_RECOVERY_ARTIFACT", trust)
        self.assertRegex(
            trust,
            r"#define PBNS_RECOVERY_MANIFEST_DEADLINE_MS UINT32_C\(600000\)",
        )
        self.assertRegex(
            trust,
            r"#define PBNS_RECOVERY_ARTIFACT_DEADLINE_MS UINT32_C\(2700000\)",
        )
        manifest_exchange = c_function_body(trust, "manifest_exchange")
        bulk = c_function_body(trust, "bulk_begin")
        self.assertIn("PBNS_RECOVERY_MANIFEST_DEADLINE_MS", manifest_exchange)
        self.assertNotIn("PBNS_RECOVERY_ARTIFACT_DEADLINE_MS", manifest_exchange)
        self.assertIn("PBNS_RECOVERY_ARTIFACT_DEADLINE_MS", bulk)
        self.assertNotIn("PBNS_RECOVERY_MANIFEST_DEADLINE_MS", bulk)
        self.assertIn("PbnsCoreLib", inf)
        self.assertNotIn("GetTime", source + trust)
        self.assertNotIn("SetTime", source + trust)
        self.assertIn("pbns_recovery_service_stream", trust)
        self.assertNotIn("pbns_recovery_live_artifact", source + trust)
        self.assertIn("pbns_recovery_service_manifest_invalidate", source)
        self.assertGreaterEqual(source.count("pbns_recovery_service_manifest_invalidate"), 3)
        self.assertIn("pbns_recovery_service_manifest_target_matches", source + adapter)
        self.assertNotIn("Tss2_Sys", source + trust)
        self.assertNotIn("private", source.lower() + trust.lower())
        self.assertEqual(c_array_hex(rollback, "POLICY_KEY_X"), EC_FIXTURES["policy"][1])
        self.assertEqual(c_array_hex(rollback, "POLICY_KEY_Y"), EC_FIXTURES["policy"][2])
        self.assertNotIn("LoadImage", source + trust + rollback)
        self.assertNotIn("PbnsRecoveryClientRun", source + trust + rollback)
        self.assertNotIn("PbnsAntiRollbackTpmInitialize", rollback)
        self.assertNotRegex(rollback, r"#include <(?:Protocol/Tcg|IndustryStandard/Tpm)")
        self.assertIn("manifest_profile_valid", trust)
        self.assertIn("pbns_cose_uefi_sign1_verify", trust)
        destroy = source[source.index("PbnsRecoveryServiceDestroy"):]
        self.assertLess(destroy.index("pbns_broker_reset"), destroy.index("secure_zero(service->broker_workspace"))
        self.assertLess(destroy.index("secure_zero(service->broker_workspace"), destroy.index("pbns_usb_transport_destroy"))
        self.assertLess(destroy.index("pbns_usb_transport_destroy"), destroy.index("pbns_cose_key_reset"))
        self.assertLess(destroy.index("pbns_cose_key_reset"), destroy.index("PbnsRecoveryRollbackDestroy"))
        self.assertLess(destroy.index("PbnsRecoveryRollbackDestroy"), destroy.index("pbns_identity_close"))

    def test_create_failure_is_fail_terminal_and_key_pairs_are_enforced(self) -> None:
        source = SERVICE_SOURCE.read_text()
        trust = TRUST_SOURCE.read_text()
        create = c_function_body(source, "PbnsRecoveryServiceCreate")
        fail_terminal = c_function_body(source, "fail_create")
        pair_different = c_function_body(trust, "keys_pair_different")
        keys_distinct = c_function_body(trust, "public_keys_distinct")
        self.assertRegex(
            create,
            r"if\s*\(out_service != NULL\)\s*\{\s*\*out_service = NULL;",
        )
        cleanup = re.search(r"cleanup:\s*(.*?)$", create, re.S)
        self.assertIsNotNone(cleanup)
        assert cleanup is not None
        self.assertRegex(cleanup.group(1), r"return\s+fail_create\(service, status\);")
        self.assertNotRegex(cleanup.group(1), r"return\s+EFI_SUCCESS\s*;")
        self.assertEqual(fail_terminal.count("PbnsRecoveryServiceDestroy(service)"), 1)
        self.assertRegex(
            fail_terminal,
            r"return\s+EFI_ERROR\(status\)\s*\?\s*status\s*:\s*EFI_SECURITY_VIOLATION\s*;",
        )
        destroy = c_function_body(source, "PbnsRecoveryServiceDestroy")
        for flag in (
            "broker_ready",
            "usb_ready",
            "policy_key_ready",
            "manifest_key_ready",
            "time_key_ready",
            "identity_key_ready",
            "identity_open",
        ):
            self.assertRegex(destroy, rf"if\s*\(service->{flag}\)")
        self.assertRegex(
            pair_different,
            r"!bytes_equal\([^;]*\)\s*\|\|\s*!bytes_equal\([^;]*\)",
        )
        self.assertRegex(
            keys_distinct,
            r"keys_pair_different\([^;]+\)\s*&&\s*"
            r"keys_pair_different\([^;]+\)\s*&&\s*"
            r"keys_pair_different\([^;]+\)",
        )


if __name__ == "__main__":
    unittest.main()
