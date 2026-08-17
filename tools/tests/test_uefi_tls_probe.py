#!/usr/bin/env python3

import pathlib
import unittest


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROBE_DIR = PBNS_ROOT / "uefi" / "Applications" / "PbnsTlsProbe"


class UefiTlsProbeTests(unittest.TestCase):
    def test_probe_manifest_links_only_side_effect_free_support(self) -> None:
        manifest = (PROBE_DIR / "PbnsTlsProbe.inf").read_text(encoding="utf-8")
        for required in (
            "MbedTlsLib",
            "PbnsIdentityLib",
            "PbnsTlsTransportCoreLib",
            "PbnsTlsTransportLib",
            "PbnsUefiPlatformLib",
            "UefiApplicationEntryPoint",
            "BaseMemoryLib",
            "IntrinsicLib",
            "MemoryAllocationLib",
        ):
            self.assertIn(required, manifest)
        for forbidden in (
            "PbnsUsbTransportLib",
            "UefiBootServicesTableLib",
            "UefiRuntimeServicesTableLib",
            "Protocol/Usb",
            "Protocol/Tcp",
        ):
            self.assertNotIn(forbidden, manifest)

    def test_probe_uses_adapter_without_external_transport_access(self) -> None:
        source = (PROBE_DIR / "PbnsTlsProbe.c").read_text(encoding="utf-8")
        for required in (
            "PbnsTlsTransportCreate",
            "PbnsTlsTransportDestroy",
            "PbnsTlsTransportAllocationStats",
            "local_transport_ops",
            "probe_allocate_pool",
            "probe_free_pool",
            "PBNS_ERR_BUSY",
            "192.168.1.180",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "mbedtls_entropy_context",
            "mbedtls_entropy_init",
            "PbnsUsb",
            "LocateProtocol",
            "gBS->",
            "gRT->",
            "Protocol/Usb",
            "Protocol/Tcp",
        ):
            self.assertNotIn(forbidden, source)

    def test_portable_tls_edk2_layout_includes_crt_before_mbedtls(self) -> None:
        policy_header = (PBNS_ROOT / "include" / "pbns" / "tls_policy.h").read_text(
            encoding="utf-8"
        )
        transport_source = (
            PBNS_ROOT / "src" / "transport" / "tls_transport.c"
        ).read_text(encoding="utf-8")
        transport_inf = (
            PBNS_ROOT / "src" / "transport" / "PbnsTlsTransportCoreLib.inf"
        ).read_text(encoding="utf-8")
        self.assertLess(
            policy_header.index("CrtLibSupport.h"),
            policy_header.index("mbedtls/x509_crt.h"),
        )
        self.assertLess(
            transport_source.index("CrtLibSupport.h"),
            transport_source.index("mbedtls/ctr_drbg.h"),
        )
        self.assertIn("-DPBNS_EDK2", transport_inf)
        self.assertIn("IntrinsicLib", transport_inf)
        self.assertIn("tls_handshake_observer.c", transport_inf)

    def test_platform_and_build_script_require_probe(self) -> None:
        platform = (PBNS_ROOT / "PbnsPkg.dsc").read_text(encoding="utf-8")
        build_script = (PBNS_ROOT / "tools" / "build-uefi.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "pbns/uefi/Applications/PbnsTlsProbe/PbnsTlsProbe.inf", platform
        )
        self.assertIn("PbnsTlsProbe", build_script)
        self.assertIn('GenFw" -z -r "$OUTPUT"', build_script)
        self.assertIn('grep -aFq "$REPO_ROOT" "$OUTPUT"', build_script)


if __name__ == "__main__":
    unittest.main()
