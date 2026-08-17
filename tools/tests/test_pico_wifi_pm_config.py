import pathlib
import re
import unittest


class PicoWifiNoPowerSaveConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(__file__).parents[2]
        self.network = (self.root / "pico" / "src" / "pico_network.c").read_text(
            encoding="utf-8"
        )
        self.tusb_config = (
            self.root / "pico" / "include" / "tusb_config.h"
        ).read_text(encoding="utf-8")
        self.descriptors = (
            self.root / "pico" / "src" / "usb_descriptors.c"
        ).read_text(encoding="utf-8")
        self.main = (self.root / "pico" / "src" / "main.c").read_text(
            encoding="utf-8"
        )

    def test_sta_setup_disables_power_saving_and_fails_closed(self) -> None:
        self.assertRegex(
            self.network,
            r"cyw43_arch_lwip_begin\(\);\s*"
            r"cyw43_arch_enable_sta_mode\(\);\s*"
            r"const int pm_status =\s*"
            r"cyw43_wifi_pm\(&cyw43_state, CYW43_NONE_PM\);\s*"
            r"cyw43_arch_lwip_end\(\);\s*"
            r"if \(pm_status != 0\) \{\s*"
            r"cyw43_arch_deinit\(\);\s*"
            r"secure_zero\(network, sizeof\(\*network\)\);\s*"
            r"return PBNS_ERR_TRANSPORT;\s*"
            r"\}\s*"
            r"return PBNS_OK;",
        )

    def test_cdc_roles_packets_and_buffers_remain_unchanged(self) -> None:
        self.assertRegex(
            self.tusb_config, r"(?m)^#define CFG_TUD_CDC_RX_BUFSIZE 4096$"
        )
        self.assertRegex(
            self.tusb_config, r"(?m)^#define CFG_TUD_CDC_TX_BUFSIZE 4096$"
        )
        self.assertRegex(
            self.tusb_config, r"(?m)^#define CFG_TUD_CDC_EP_BUFSIZE 4096$"
        )
        self.assertEqual(self.descriptors.count("TUD_CDC_DESCRIPTOR("), 2)
        self.assertIn("0x02, 0x82, 64)", self.descriptors)
        self.assertIn("0x04, 0x84, 64)", self.descriptors)
        self.assertRegex(self.main, r"(?m)^#define DATA_CDC_INSTANCE UINT8_C\(0\)$")
        self.assertRegex(
            self.main, r"(?m)^#define PROVISION_CDC_INSTANCE UINT8_C\(1\)$"
        )


if __name__ == "__main__":
    unittest.main()
