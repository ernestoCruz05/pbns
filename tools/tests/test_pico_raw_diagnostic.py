import pathlib
import re
import unittest


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]


class PicoRawDiagnosticSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cmake = (PBNS_ROOT / "pico" / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        cls.header = (
            PBNS_ROOT
            / "pico"
            / "include"
            / "pbns_proxy"
            / "raw_tunnel_diagnostic.h"
        ).read_text(encoding="utf-8")
        cls.network_header = (
            PBNS_ROOT / "pico" / "include" / "pbns_proxy" / "network.h"
        ).read_text(encoding="utf-8")
        cls.network_source = (
            PBNS_ROOT / "pico" / "src" / "pico_network.c"
        ).read_text(encoding="utf-8")
        cls.main = (
            PBNS_ROOT / "pico" / "src" / "raw_tunnel_diagnostic_main.c"
        ).read_text(encoding="utf-8")
        cls.descriptors = (
            PBNS_ROOT
            / "pico"
            / "src"
            / "raw_tunnel_diagnostic_usb_descriptors.c"
        ).read_text(encoding="utf-8")
        cls.production_descriptors = (
            PBNS_ROOT / "pico" / "src" / "usb_descriptors.c"
        ).read_text(encoding="utf-8")
        cls.build_script = (
            PBNS_ROOT / "tools" / "build-pico-raw-diagnostic.sh"
        ).read_text(encoding="utf-8")

    def test_distinct_single_cdc_identity(self) -> None:
        self.assertIn("UINT16_C(0x40d2)", self.descriptors)
        self.assertIn('"PBNS Raw Tunnel Diagnostic v1"', self.descriptors)
        self.assertIn("PBNS_RAW_DIAGNOSTIC_AWAITING_BCD", self.descriptors)
        self.assertEqual(self.descriptors.count("TUD_CDC_DESCRIPTOR("), 1)
        self.assertRegex(
            self.descriptors,
            r"INTERFACE_CDC_CONTROL\s*=\s*0,\s*INTERFACE_CDC_DATA,"
            r"\s*INTERFACE_COUNT",
        )
        for forbidden in ("Provision", "PROVISION", "CDC1", "0x40d1", "0x4011"):
            self.assertNotIn(forbidden, self.descriptors)

    def test_production_identity_and_two_cdc_roles_are_unchanged(self) -> None:
        self.assertIn("UINT16_C(0x4011)", self.production_descriptors)
        self.assertIn("UINT16_C(0x0100)", self.production_descriptors)
        self.assertIn('"PBNS Proxy v1"', self.production_descriptors)
        self.assertEqual(
            self.production_descriptors.count("TUD_CDC_DESCRIPTOR("), 2
        )
        self.assertIn('"PBNS Data"', self.production_descriptors)
        self.assertIn('"PBNS Provision"', self.production_descriptors)

    def test_target_is_opt_in_and_has_no_tls_or_flash_mutation_link(self) -> None:
        self.assertIn("option(PBNS_BUILD_RAW_TUNNEL_DIAGNOSTIC", self.cmake)
        target = re.search(
            r"if\(PBNS_BUILD_RAW_TUNNEL_DIAGNOSTIC\)(.*?)\nendif\(\)",
            self.cmake,
            re.DOTALL,
        )
        self.assertIsNotNone(target)
        assert target is not None
        body = target.group(1)
        self.assertIn("add_executable(pbns-raw-tunnel-diagnostic", body)
        self.assertIn("PBNS_RAW_TUNNEL_DIAGNOSTIC", body)
        self.assertIn("src/pico_network.c", body)
        self.assertIn("src/raw_tunnel_diagnostic_main.c", body)
        self.assertIn("src/raw_tunnel_diagnostic_usb_descriptors.c", body)
        links = re.search(
            r"target_link_libraries\(pbns-raw-tunnel-diagnostic PRIVATE(.*?)\n    \)",
            body,
            re.DOTALL,
        )
        self.assertIsNotNone(links)
        assert links is not None
        for forbidden in (
            "hardware_flash",
            "pico_flash",
            "pico_mbedtls_tls",
            "pico_mbedtls_x509",
        ):
            self.assertNotIn(forbidden, links.group(1))
        for forbidden in (
            "tls_client.c",
            "entropy.c",
            "src/main.c",
            "src/usb_descriptors.c",
        ):
            self.assertNotIn(forbidden, body)

    def test_main_is_read_only_tls_opaque_and_bounded(self) -> None:
        self.assertIn("DIAGNOSTIC_DTR_TIMEOUT_MS UINT64_C(120000)", self.main)
        self.assertIn("DIAGNOSTIC_SESSION_TIMEOUT_MS UINT64_C(90000)", self.main)
        self.assertIn("TUNNEL_AGGREGATION_THRESHOLD 2048U", self.main)
        self.assertIn("TUNNEL_AGGREGATION_DEADLINE_US UINT64_C(5000)", self.main)
        self.assertIn("pbns_diagnostic_storage_init", self.main)
        self.assertIn("pbns_credentials_load", self.main)
        self.assertIn("pbns_byte_pump_batch_with_policy", self.main)
        self.assertIn("pbns_pico_network_tcp_endpoint", self.main)
        for forbidden in (
            "flash_range_erase",
            "flash_range_program",
            "flash_safe_execute",
            "hardware/flash.h",
            "pico/flash.h",
            "mbedtls",
            "TLS_READY",
            "ClientHello",
            "expected_spki",
            "PROVISION",
            "tud_cdc_n_connected(1",
            "printf(",
        ):
            self.assertNotIn(forbidden, self.main)

    def test_scratch_layout_and_magic_last_are_explicit(self) -> None:
        self.assertIn("PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS 8U", self.header)
        self.assertRegex(
            self.main,
            r"(?s)watchdog_hw->scratch\[0\]\s*=\s*0U;.*?"
            r"for \(size_t index = 1U;.*?__compiler_memory_barrier\(\);.*?"
            r"watchdog_hw->scratch\[0\]\s*=\s*words\[0\];",
        )
        arm = self.main.index("watchdog_reboot(0U, 0U, 10U);")
        commit = self.main.index("watchdog_hw->scratch[0] = 0U;")
        self.assertLess(arm, commit)
        self.assertNotIn("watchdog_reboot(0U, 0U, 0U);", self.main)

    def test_cdc_observer_avoids_unobservable_tinyusb_auto_flush(self) -> None:
        self.assertIn("DIAGNOSTIC_CDC_WRITE_MAX 63U", self.main)
        self.assertRegex(
            self.main,
            r"(?s)static pbns_status usb_write.*?"
            r"if \(cdc_flush_pending \|\| cdc_transfer_pending\) \{\s*"
            r"return PBNS_ERR_WOULD_BLOCK;\s*\}.*?"
            r"amount > DIAGNOSTIC_CDC_WRITE_MAX.*?"
            r"amount = DIAGNOSTIC_CDC_WRITE_MAX;",
        )

    def test_cdc_in_completion_is_observed_after_explicit_flush(self) -> None:
        self.assertRegex(
            self.main,
            r"(?s)void tud_cdc_tx_complete_cb\(uint8_t instance\).*?"
            r"instance != DIAGNOSTIC_CDC_INSTANCE.*?return;.*?"
            r"cdc_transfer_pending.*?PBNS_RAW_OBSERVE_CDC_TX_COMPLETE.*?"
            r"cdc_transfer_pending = false",
        )

    def test_network_instrumentation_is_compile_guarded(self) -> None:
        self.assertRegex(
            self.network_header,
            r"(?s)#if defined\(PBNS_RAW_TUNNEL_DIAGNOSTIC\).*?"
            r"pbns_raw_diagnostic_state \*diagnostic;.*?#endif",
        )
        self.assertRegex(
            self.network_source,
            r"(?s)#if defined\(PBNS_RAW_TUNNEL_DIAGNOSTIC\).*?"
            r"pbns_raw_diagnostic_observe_tcp_rx.*?#endif",
        )
        self.assertRegex(
            self.network_source,
            r"(?s)#if defined\(PBNS_RAW_TUNNEL_DIAGNOSTIC\).*?"
            r"pbns_raw_diagnostic_observe_tcp_io.*?#endif",
        )
        self.assertIn("pbns_pico_network_attach_diagnostic", self.network_source)

    def test_build_script_locks_production_and_audits_diagnostic(self) -> None:
        for required in (
            "build-pico.sh",
            "SOURCE_DATE_EPOCH",
            "e99ced85ba0c91c3b8d914ec3fcd7b7b5531e81a87a72830e181eb43de3ecd14",
            "792576",
            "PBNS_RAW_TUNNEL_DIAGNOSTIC",
            "00001000",
            "0x001fe000",
            "verify_uf2_range.py",
            "flash_range_erase",
            "mbedtls_ssl_",
            "PICO RAW TUNNEL DIAGNOSTIC BUILD PASS",
        ):
            self.assertIn(required, self.build_script)

    def test_no_sensitive_vocabulary_in_terminal_interface(self) -> None:
        for forbidden in (
            "ssid",
            "psk",
            "hostname",
            "spki",
            "token",
            "nonce",
            "payload",
            "certificate",
        ):
            self.assertNotIn(forbidden, self.descriptors.lower())


if __name__ == "__main__":
    unittest.main()
