import pathlib
import unittest


class PicoDiagnosticBuildTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(__file__).parents[2]

    def test_diagnostic_is_opt_in_and_distinct(self) -> None:
        cmake = (self.root / "pico" / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("option(PBNS_BUILD_NETWORK_DIAGNOSTIC", cmake)
        self.assertIn("add_executable(pbns-proxy-diagnostic", cmake)
        self.assertIn("PBNS_NETWORK_DIAGNOSTIC", cmake)
        self.assertIn("pico_add_linker_script_override_path", cmake)
        diagnostic_block = cmake.split("if(PBNS_BUILD_NETWORK_DIAGNOSTIC)", 1)[1]
        self.assertNotRegex(diagnostic_block, r"(?m)^\s+hardware_flash\s*$")
        self.assertNotRegex(diagnostic_block, r"(?m)^\s+pico_flash\s*$")

    def test_descriptor_has_exact_identity_and_one_cdc(self) -> None:
        source = (
            self.root / "pico" / "src" / "diagnostic_usb_descriptors.c"
        ).read_text(encoding="utf-8")
        for marker in (
            "UINT16_C(0xcafe)",
            "UINT16_C(0x40d1)",
            '"PBNS Network Diagnostic v1"',
            "TUD_CDC_DESCRIPTOR",
            "PBNS_DIAGNOSTIC_AWAITING_DTR",
        ):
            self.assertIn(marker, source)
        self.assertEqual(source.count("TUD_CDC_DESCRIPTOR"), 1)
        self.assertNotIn("PBNS Provision", source)

    def test_main_uses_dtr_without_cdc_payload_io(self) -> None:
        source = (
            self.root / "pico" / "src" / "diagnostic_main.c"
        ).read_text(encoding="utf-8")
        self.assertIn("tud_cdc_n_connected", source)
        self.assertNotIn("tud_cdc_n_write", source)
        self.assertNotIn("tud_cdc_n_read", source)
        self.assertIn("watchdog_hw->scratch[0]", source)
        self.assertIn("PBNS_DIAGNOSTIC_MAGIC", source)
        self.assertIn("pbns_network_step", source)
        self.assertIn("UINT32_C(300000)", source)
        for marker in (
            "cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA)",
            "CYW43_LINK_DOWN",
            "CYW43_LINK_JOIN",
            "CYW43_LINK_NOIP",
            "cyw43_arch_lwip_begin()",
            "cyw43_arch_lwip_end()",
            "PBNS_DIAGNOSTIC_WIFI_PENDING_UNKNOWN",
            "pbns_diagnostic_result_for_wifi_timeout",
        ):
            self.assertIn(marker, source)

    def test_build_script_checks_flash_and_reproducibility(self) -> None:
        source = (
            self.root / "tools" / "build-pico-diagnostic.sh"
        ).read_text(encoding="utf-8")
        for marker in (
            "build-pico.sh",
            "SOURCE_DATE_EPOCH",
            "0x001fe000",
            "pbns-proxy-diagnostic.uf2",
            "PICO NETWORK DIAGNOSTIC BUILD PASS",
            "tud_cdc_n_available",
            "tud_cdc_n_peek",
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
