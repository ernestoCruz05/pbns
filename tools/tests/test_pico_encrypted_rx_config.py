import pathlib
import re
import unittest


def extract_static_function_body(source: str, name: str) -> str:
    declaration = re.compile(
        rf"(?m)^[ \t]*static\b[^;{{}}]*\b{re.escape(name)}\s*\(",
    )
    matches = list(declaration.finditer(source))
    if len(matches) != 1:
        raise AssertionError(f"expected one static {name} definition, found {len(matches)}")

    opening = source.find("{", matches[0].end())
    if opening < 0:
        raise AssertionError(f"missing opening brace for {name}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated static {name} definition")


class PicoTcpRxConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(__file__).parents[2]
        self.network_header = (
            self.root / "pico" / "include" / "pbns_proxy" / "network.h"
        ).read_text(encoding="utf-8")
        self.lwipopts = (self.root / "pico" / "include" / "lwipopts.h").read_text(
            encoding="utf-8"
        )
        self.mbedtls_config = (
            self.root / "pico" / "include" / "mbedtls_config.h"
        ).read_text(encoding="utf-8")
        self.network_source = (self.root / "pico" / "src" / "pico_network.c").read_text(
            encoding="utf-8"
        )
        self.readme = (self.root / "pico" / "README.md").read_text(encoding="utf-8")

    def test_capacity_retains_stage_six_tcp_flow_control_margin(self) -> None:
        self.assertRegex(
            self.network_header,
            r"(?m)^#define PBNS_PICO_TCP_RX_CAPACITY 18432U$",
        )
        self.assertEqual(18432 - 16 * 1024, 2048)

    def test_capacity_tracks_tcp_window_while_baseline_tls_config_remains(self) -> None:
        self.assertRegex(self.lwipopts, r"(?m)^#define TCP_WND \(16U \* 1024U\)$")
        self.assertRegex(
            self.mbedtls_config, r"(?m)^#define MBEDTLS_SSL_IN_CONTENT_LEN 16384$"
        )
        self.assertIn("MBEDTLS_SSL_PROTO_TLS1_2", self.mbedtls_config)
        self.assertIn(
            "MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", self.mbedtls_config
        )

    def test_readme_states_raw_flow_control_and_uefi_tls_ownership(self) -> None:
        self.assertIn("18,432-byte raw TCP receive ring", self.readme)
        self.assertIn("UEFI owns TLS", self.readme)
        self.assertIn("SPKI field is decoded only for record compatibility", self.readme)

    def test_receive_callback_retains_oversized_pbuf_without_partial_commit(self) -> None:
        callback = extract_static_function_body(self.network_source, "tcp_received")
        capacity_check = re.search(
            r"if \(\(size_t\)packet->tot_len > available\) \{\s*"
            r"return ERR_MEM;\s*\}",
            callback,
        )
        self.assertIsNotNone(capacity_check)
        assert capacity_check is not None
        self.assertNotIn("pbuf_free(packet)", capacity_check.group(0))
        self.assertNotIn(
            "pbns_byte_ring_commit(&network->tcp_rx", capacity_check.group(0)
        )

    def test_receive_callback_rolls_back_before_aborting_copy_errors(self) -> None:
        callback = extract_static_function_body(self.network_source, "tcp_received")
        self.assertIn("const pbns_byte_ring ring_before = network->tcp_rx;", callback)
        self.assertRegex(
            callback,
            r"pbuf_copy_partial\(packet, writable\.ptr, amount_u16, copied\) !=\s*"
            r"amount_u16 \|\|\s*"
            r"pbns_byte_ring_commit\(&network->tcp_rx, amount\) != PBNS_OK\) "
            r"\{\s*network->tcp_rx = ring_before;\s*"
            r"network->asynchronous_status = PBNS_ERR_STATE;\s*"
            r"\(void\)pbuf_free\(packet\);\s*network->connection = NULL;\s*"
            r"tcp_abort\(pcb\);\s*return ERR_ABRT;",
        )
        success_free = callback.rindex("(void)pbuf_free(packet);")
        success_return = callback.index("return ERR_OK;", success_free)
        self.assertLess(success_free, success_return)


if __name__ == "__main__":
    unittest.main()
