#!/usr/bin/env python3

import pathlib
import re
import unittest


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
APPLICATION = PBNS_ROOT / "uefi" / "Applications" / "PbnsAttest" / "PbnsAttest.c"
ADAPTER = PBNS_ROOT / "uefi" / "Library" / "PbnsAttestationClientLib"
ENROLLMENT_APPLICATION = PBNS_ROOT / "uefi" / "Applications" / "PbnsEnroll" / "PbnsEnroll.c"
ENROLLMENT_ADAPTER = PBNS_ROOT / "uefi" / "Library" / "PbnsEnrollmentClientLib"
ENROLLMENT_BASELINE = (
    PBNS_ROOT
    / "uefi"
    / "Library"
    / "PbnsEnrollmentBaselineLib"
    / "PbnsEnrollmentBaselineLib.c"
)
MEASURED_BOOT_HEADER = PBNS_ROOT / "include" / "Library" / "PbnsMeasuredBootLib.h"


class UefiAttestationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = APPLICATION.read_text(encoding="utf-8")
        self.adapter_source = (ADAPTER / "PbnsAttestationClientLib.c").read_text(
            encoding="utf-8"
        )
        self.adapter_header = (ADAPTER / "PbnsAttestationClientLib.h").read_text(
            encoding="utf-8"
        )

    def test_live_path_is_exactly_one_shared_run(self) -> None:
        self.assertEqual(self.source.count("pbns_attestation_run("), 1)
        for bypass in (
            "PbnsAttestationClientAcceptChallenge",
            "PbnsAttestationClientSubmit",
            "PbnsAttestationClientVerifyReceipt",
            "pbns_attestation_accept_challenge(",
            "pbns_attestation_submit(",
            "pbns_attestation_receipt_verify(",
        ):
            self.assertNotIn(bypass, self.source)
        self.assertIn("#include \"pbns/attestation_run.h\"", self.source)

    def test_enrollment_supplies_all_bounded_public_descriptors(self) -> None:
        enrollments = re.findall(
            r"tpm_public\s*=\s*(?:\(pbns_tpm_enrollment_public\))?\s*\{(.*?)\};",
            self.source,
            re.DOTALL,
        )
        enrollment = next(
            (value for value in enrollments if ".EkPublic" in value), None
        )
        self.assertIsNotNone(enrollment)
        assert enrollment is not None
        for field in ("EkPublic", "AkPublic", "AkName", "IdentityPublic"):
            self.assertRegex(
                enrollment,
                rf"\.{field}\s*=\s*\{{[^}}]+,\s*0U,\s*sizeof\([^)]*\)\}}",
            )
        self.assertRegex(self.source, r"tpm_public\.AkPublic\.len\s*==\s*0U")
        self.assertRegex(self.source, r"tpm_public\.AkName\.len\s*==\s*0U")
        self.assertIn("secure_zero(ek_public, sizeof(ek_public));", self.source)
        self.assertIn(
            "secure_zero(identity_public, sizeof(identity_public));", self.source
        )

    def test_enrollment_supplies_bounded_ek_certificate_evidence(self) -> None:
        source = ENROLLMENT_APPLICATION.read_text(encoding="utf-8")
        self.assertNotIn("PbnsTpmIdentityEkCertificate(", source)
        self.assertEqual(source.count("PbnsTpmIdentityEnrollmentPublic("), 1)
        self.assertIn("PBNS_TPM_EK_CERTIFICATE_MAX_SIZE", source)
        self.assertIn("tpm_public.EkCertificate =", source)
        self.assertRegex(
            source,
            r"tpm_init\.ek_certificate\s*=\s*\(pbns_view\)\{"
            r"tpm_public\.EkCertificate\.ptr,\s*"
            r"tpm_public\.EkCertificate\.len\};",
        )
        self.assertIn("free_buffer(&buffers->ek_certificate,", source)

    def test_enrollment_uses_the_attestation_controlled_baseline_shape(self) -> None:
        source = ENROLLMENT_BASELINE.read_text(encoding="utf-8")
        enrollment = ENROLLMENT_APPLICATION.read_text(encoding="utf-8")
        self.assertIn("PbnsInventoryCapture(", source)
        self.assertIn("measurement_digest", source)
        self.assertIn("pbns_controlled_baseline_from_inventory(", source)
        self.assertIn("pbns_controlled_baseline_encode(", source)
        self.assertNotIn("pbns_enrollment_baseline_encode(", source)
        self.assertIn(
            "(pbns_view){fingerprint, sizeof(fingerprint)}", enrollment
        )

    def test_enrollment_binds_verified_receipt_to_submitted_ek_certificate(self) -> None:
        source = ENROLLMENT_APPLICATION.read_text(encoding="utf-8")
        self.assertIn('"tpm-verified"', source)
        self.assertRegex(
            source,
            r"tpm_public\.EkCertificate\.len\s*>\s*0U\s*\?\s*"
            r"\(pbns_view\)\{tpm_verified_assurance",
        )
        self.assertIn("expected_receipt_assurance.ptr == tpm_verified_assurance", source)

    def test_enrollment_baseline_uses_the_inventory_scratch_bound(self) -> None:
        header = MEASURED_BOOT_HEADER.read_text(encoding="utf-8")
        self.assertIn('#include "pbns/inventory.h"', header)
        self.assertIn(
            "#define PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE"
            "                                \\\n"
            "  PBNS_INVENTORY_VARIABLE_MAX_SIZE",
            header,
        )

    def test_run_config_binds_deployment_kids_and_complete_regions(self) -> None:
        for binding in (
            ".recipient_kid = PBNS_DEPLOYMENT_TRUST.recipient.kid",
            ".challenge_kid = PBNS_DEPLOYMENT_TRUST.challenge.kid",
            ".receipt_kid = PBNS_DEPLOYMENT_TRUST.receipt.kid",
            ".identity_assurance = PBNS_IDENTITY_TPM_UNVERIFIED_EK",
            ".broker_transport_context_region = tls_region",
            ".broker_platform_context_region =",
            ".context_region =",
            ".challenge_verifier_context_region =",
            ".receipt_verifier_context_region =",
        ):
            self.assertIn(binding, self.source)
        self.assertEqual(self.source.count("PbnsTlsTransportContextRegion("), 1)
        self.assertNotRegex(
            self.source,
            r"broker_transport_context_region\s*=\s*\{[^}]*sizeof",
        )

    def test_run_callbacks_bind_real_uefi_capture_and_caller_arenas(self) -> None:
        for binding in (
            ".trusted_time = run_trusted_time",
            ".monotonic_ms = run_monotonic",
            ".cancel_requested = run_cancel_requested",
            ".capture_inventory = run_capture_inventory",
            ".capture_measured = run_capture_measured",
            ".display_authenticated = run_display_authenticated",
        ):
            self.assertIn(binding, self.source)
        self.assertIn("PbnsInventoryCapture(", self.source)
        self.assertIn(".VariableScratch = variable_scratch", self.source)
        self.assertIn("PbnsMeasuredBootCaptureSelection(", self.source)
        self.assertIn("event_log_arena", self.source)
        self.assertRegex(
            self.source,
            re.compile(
                r"run_cancel_requested\([^)]*\).*?\*requested\s*=\s*false;.*?return PBNS_OK;",
                re.DOTALL,
            ),
        )

    def test_tls_destroy_is_bounded_and_never_uses_stale_owner(self) -> None:
        self.assertNotRegex(
            self.source, r"while\s*\([^)]*PbnsTlsTransportDestroy"
        )
        self.assertRegex(
            self.source,
            re.compile(
                r"for\s*\([^;]+;\s*attempt\s*<\s*3U\s*;[^)]*\).*?"
                r"PbnsTlsTransportDestroy\(tls\).*?tls\s*=\s*NULL;",
                re.DOTALL,
            ),
        )
        cleanup = self.source[self.source.index("Cleanup:") :]
        self.assertNotIn("PbnsTlsTransportContextRegion", cleanup)
        self.assertRegex(
            cleanup,
            r"if\s*\(tls\s*==\s*NULL\)\s*\{\s*pbns_usb_transport_destroy\(usb\);",
        )

    def test_efi_status_translation_preserves_run_policy(self) -> None:
        function = re.search(
            r"static pbns_status efi_to_pbns\(EFI_STATUS status\)\s*\{(.*?)\n\}",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(function)
        assert function is not None
        body = " ".join(function.group(1).split())
        expected = {
            "EFI_INVALID_PARAMETER": "PBNS_ERR_ARGUMENT",
            "EFI_OUT_OF_RESOURCES": "PBNS_ERR_RESOURCE",
            "EFI_TIMEOUT": "PBNS_ERR_TIMEOUT",
            "EFI_UNSUPPORTED": "PBNS_ERR_UNSUPPORTED",
            "EFI_NOT_READY": "PBNS_ERR_BUSY",
            "EFI_BAD_BUFFER_SIZE": "PBNS_ERR_LIMIT",
            "EFI_BUFFER_TOO_SMALL": "PBNS_ERR_LIMIT",
            "EFI_DEVICE_ERROR": "PBNS_ERR_IO",
            "EFI_SECURITY_VIOLATION": "PBNS_ERR_AUTHENTICATION",
            "EFI_COMPROMISED_DATA": "PBNS_ERR_AUTHENTICATION",
            "EFI_NO_RESPONSE": "PBNS_ERR_TRANSPORT",
        }
        for efi_status, pbns_status in expected.items():
            self.assertRegex(
                body,
                rf"if \([^)]*{efi_status}[^)]*\) \{{ return {pbns_status}; \}}",
                f"missing explicit {efi_status} mapping",
            )

    def test_enrollment_uses_generated_trust_and_tls_adapter(self) -> None:
        self.assertTrue((ENROLLMENT_ADAPTER / "PbnsEnrollmentClientLib.c").is_file())
        source = ENROLLMENT_APPLICATION.read_text(encoding="utf-8")
        for fixture_symbol in (
            "ENROLLMENT_RECIPIENT_KEY_ID",
            "ENROLLMENT_RECIPIENT_X",
            "ENROLLMENT_RECIPIENT_Y",
            "ENROLLMENT_SIGNING_KEY_ID",
            "ENROLLMENT_SIGNING_X",
            "ENROLLMENT_SIGNING_Y",
        ):
            self.assertNotIn(fixture_symbol, source)
        for required in (
            "#include <PbnsEnrollmentTrust.h>",
            "PbnsEnrollmentClientAdapterInit(",
            "PbnsEnrollmentClientTlsOpen(",
            "PBNS_ENROLLMENT_TRUST.recipient.kid",
            "PBNS_ENROLLMENT_TRUST.signer.kid",
            "PbnsEnrollmentClientTlsDestroy(&tls_transport)",
        ):
            self.assertIn(required, source)
        broker = re.search(r"pbns_broker_init\((.*?)\)\s*!=", source, re.DOTALL)
        self.assertIsNotNone(broker)
        assert broker is not None
        self.assertIn("broker_transport", broker.group(1))
        self.assertNotIn("pbns_usb_transport_as_transport", broker.group(1))

    def test_adapter_is_initializer_reset_only_and_template_has_no_run_fields(self) -> None:
        public = self.adapter_header + self.adapter_source
        self.assertIn("PbnsAttestationClientAdapterInit", public)
        self.assertIn("PbnsAttestationClientAdapterReset", public)
        for removed in (
            "PbnsAttestationClientAcceptChallenge",
            "PbnsAttestationClientSubmit",
            "PbnsAttestationClientVerifyReceipt",
        ):
            self.assertNotIn(removed, public)
        for forbidden_initializer in (
            ".inventory_report =",
            ".measured_boot =",
            ".ak_name =",
            ".ak_reference =",
            ".consume =",
            ".send_data =",
            ".evidence_digest =",
            ".consume_context =",
            ".send_context =",
        ):
            self.assertNotIn(forbidden_initializer, self.adapter_source)


if __name__ == "__main__":
    unittest.main()
