import pathlib
import re
import unittest


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]


def cmake_call(source: str, command: str, target: str) -> str:
    match = re.search(
        rf"{re.escape(command)}\(\s*{re.escape(target)}\b(.*?)\n\s*\)",
        source,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing {command}({target} ...)")
    return match.group(1)


def braced_block_after(source: str, pattern: str) -> str:
    match = re.search(pattern, source, re.DOTALL)
    if match is None:
        raise AssertionError(f"missing block matching {pattern}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"missing opening brace after {pattern}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated block after {pattern}")


def static_function(source: str, name: str) -> str:
    match = re.search(rf"(?m)^static\b[^;{{}}]*\b{re.escape(name)}\s*\(", source)
    if match is None:
        raise AssertionError(f"missing static function {name}")
    return braced_block_after(source[match.start() :], rf"\b{re.escape(name)}\s*\(")


def assert_tcp_output_failure_integration(
    test_case: unittest.TestCase, pico_network: str
) -> None:
    classifier = static_function(pico_network, "tcp_io_result")
    test_case.assertRegex(
        classifier,
        r"if\s*\(\s*status\s*==\s*ERR_OK\s*\)\s*\{\s*"
        r"return\s+PBNS_TCP_IO_OK\s*;\s*\}",
    )
    test_case.assertRegex(
        classifier,
        r"return\s+status\s*==\s*ERR_MEM\s*\?\s*PBNS_TCP_IO_RETRY\s*:"
        r"\s*PBNS_TCP_IO_FAILED\s*;",
    )

    endpoint = static_function(pico_network, "tcp_write_endpoint")
    test_case.assertEqual(endpoint.count("tcp_write("), 1)
    test_case.assertEqual(endpoint.count("tcp_output("), 1)
    write_call = endpoint.index("tcp_write(")
    output_guard = braced_block_after(
        endpoint,
        r"if\s*\(\s*write_result\s*==\s*PBNS_TCP_IO_OK\s*\)",
    )
    test_case.assertIn(
        "output_result = tcp_io_result(tcp_output(pcb));", output_guard
    )
    test_case.assertNotIn("PBNS_ERR_WOULD_BLOCK", endpoint[write_call:])

    terminal_guard = braced_block_after(
        endpoint,
        r"if\s*\(\s*write_result\s*==\s*PBNS_TCP_IO_FAILED\s*\|\|"
        r".*?output_result\s*!=\s*PBNS_TCP_IO_OK\s*\)",
    )
    test_case.assertIn(
        "network->asynchronous_status = PBNS_ERR_TRANSPORT;", terminal_guard
    )

    outcome = endpoint.index("pbns_tcp_write_outcome(", write_call)
    test_case.assertRegex(
        endpoint[outcome:],
        r"pbns_tcp_write_outcome\(\s*write_result,\s*output_result,\s*amount,"
        r"\s*written\s*\)",
    )
    release = endpoint.index("cyw43_arch_lwip_end();", outcome)
    returned = endpoint.index("return status;", release)
    async_transport = endpoint.index(
        "network->asynchronous_status = PBNS_ERR_TRANSPORT;", write_call
    )
    test_case.assertLess(async_transport, outcome)
    test_case.assertLess(outcome, release)
    test_case.assertLess(release, returned)


class PicoRawTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cmake = (PBNS_ROOT / "pico" / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        self.root_cmake = (PBNS_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.header = (
            PBNS_ROOT / "pico" / "include" / "pbns_proxy" / "network.h"
        ).read_text(encoding="utf-8")
        self.network = (PBNS_ROOT / "pico" / "src" / "network.c").read_text(
            encoding="utf-8"
        )
        self.pico_network = (
            PBNS_ROOT / "pico" / "src" / "pico_network.c"
        ).read_text(encoding="utf-8")
        self.main = (PBNS_ROOT / "pico" / "src" / "main.c").read_text(
            encoding="utf-8"
        )
        self.credentials = (
            PBNS_ROOT / "pico" / "src" / "credentials.c"
        ).read_text(encoding="utf-8")
        self.tusb = (
            PBNS_ROOT / "pico" / "include" / "tusb_config.h"
        ).read_text(encoding="utf-8")
        self.descriptors = (
            PBNS_ROOT / "pico" / "src" / "usb_descriptors.c"
        ).read_text(encoding="utf-8")

    def test_production_excludes_pico_tls_but_baselines_retain_it(self) -> None:
        production_sources = cmake_call(self.cmake, "add_executable", "pbns-proxy")
        production_links = cmake_call(
            self.cmake, "target_link_libraries", "pbns-proxy"
        )
        self.assertNotIn("src/tls_client.c", production_sources)
        self.assertNotIn("src/entropy.c", production_sources)
        self.assertNotIn("pico_mbedtls_tls", production_links)
        self.assertNotIn("pico_mbedtls_x509", production_links)
        self.assertIn("pico_mbedtls_crypto", production_links)

        diagnostic_sources = cmake_call(
            self.cmake, "add_executable", "pbns-proxy-diagnostic"
        )
        diagnostic_links = cmake_call(
            self.cmake, "target_link_libraries", "pbns-proxy-diagnostic"
        )
        self.assertIn("src/tls_client.c", diagnostic_sources)
        self.assertIn("src/entropy.c", diagnostic_sources)
        self.assertIn("pico_mbedtls_tls", diagnostic_links)
        self.assertIn("pico_mbedtls_x509", diagnostic_links)
        self.assertIn("pico/src/tls_client.c", self.root_cmake)
        self.assertIn("pbns-pico-tls-replay", self.root_cmake)

    def test_diagnostic_uses_authenticated_tls_baseline_adapter(self) -> None:
        baseline_header_path = (
            PBNS_ROOT
            / "pico"
            / "include"
            / "pbns_proxy"
            / "pico_tls_diagnostic_baseline.h"
        )
        baseline_source_path = (
            PBNS_ROOT / "pico" / "src" / "pico_tls_diagnostic_baseline.c"
        )
        self.assertTrue(baseline_header_path.is_file())
        self.assertTrue(baseline_source_path.is_file())

        baseline_header = baseline_header_path.read_text(encoding="utf-8")
        baseline_source = baseline_source_path.read_text(encoding="utf-8")
        diagnostic_main = (
            PBNS_ROOT / "pico" / "src" / "diagnostic_main.c"
        ).read_text(encoding="utf-8")
        diagnostic_sources = cmake_call(
            self.cmake, "add_executable", "pbns-proxy-diagnostic"
        )

        self.assertIn("src/pico_tls_diagnostic_baseline.c", diagnostic_sources)
        self.assertNotIn("src/pico_network.c", diagnostic_sources)
        self.assertIn(
            '#include "pbns_proxy/pico_tls_diagnostic_baseline.h"',
            diagnostic_main,
        )
        self.assertIn("pbns_pico_tls_diagnostic_baseline", diagnostic_main)
        for expected in (
            "expected_spki",
            "pbns_tls_client tls",
            "pbns_tls_client_init",
            "pbns_tls_client_step",
            "pbns_tls_client_plaintext_endpoint",
            "credentials->spki_sha256",
            ".session_poll = pico_tls_session_poll",
        ):
            self.assertIn(expected, baseline_header + baseline_source)

    def test_production_network_is_raw_and_has_no_trust_state(self) -> None:
        combined = self.header + self.pico_network
        for expected in (
            "PBNS_NETWORK_SESSION_CONNECTING",
            "session_poll",
            "pbns_pico_network_tcp_endpoint",
            "PBNS_PICO_TCP_RX_CAPACITY 18432U",
            "tcp_rx_storage",
        ):
            self.assertIn(expected, combined)
        for forbidden in (
            "PBNS_NETWORK_TLS_HANDSHAKE",
            "tls_poll",
            "expected_spki",
            "pbns_tls_client",
            "pbns_pico_network_tls_endpoint",
            "PBNS_TLS_SPKI_SHA256_SIZE",
        ):
            self.assertNotIn(forbidden, combined)
        init_body = self.pico_network[
            self.pico_network.index("pbns_pico_network_init(") :
            self.pico_network.index("void pbns_pico_network_deinit")
        ]
        self.assertNotIn("spki_sha256", init_body)

    def test_received_pbuf_is_not_partially_visible_on_copy_failure(self) -> None:
        callback = static_function(self.pico_network, "tcp_received")
        self.assertIn("const pbns_byte_ring ring_before = network->tcp_rx;", callback)
        self.assertIn("network->tcp_rx = ring_before;", callback)
        capacity = callback.index("packet->tot_len > available")
        first_commit = callback.index("pbns_byte_ring_commit", capacity)
        self.assertLess(capacity, first_commit)
        self.assertRegex(callback, r"packet->tot_len > available\) \{\s*return ERR_MEM;")

    def test_tcp_write_err_ok_output_err_rte_is_terminal_in_production_adapter(
        self,
    ) -> None:
        assert_tcp_output_failure_integration(self, self.pico_network)

    def test_cdc_roles_and_stage_six_buffers_remain_fixed(self) -> None:
        self.assertRegex(self.main, r"(?m)^#define DATA_CDC_INSTANCE UINT8_C\(0\)$")
        self.assertRegex(
            self.main, r"(?m)^#define PROVISION_CDC_INSTANCE UINT8_C\(1\)$"
        )
        self.assertRegex(self.main, r"(?m)^#define TUNNEL_RING_CAPACITY 4096U$")
        self.assertRegex(
            self.main, r"(?m)^#define TUNNEL_AGGREGATION_THRESHOLD 2048U$"
        )
        self.assertRegex(
            self.main,
            r"(?m)^#define TUNNEL_AGGREGATION_DEADLINE_US UINT64_C\(5000\)$",
        )
        self.assertRegex(self.tusb, r"(?m)^#define CFG_TUD_CDC_RX_BUFSIZE 4096$")
        self.assertRegex(self.tusb, r"(?m)^#define CFG_TUD_CDC_TX_BUFSIZE 4096$")
        self.assertRegex(self.tusb, r"(?m)^#define CFG_TUD_CDC_EP_BUFSIZE 4096$")
        self.assertEqual(self.descriptors.count("TUD_CDC_DESCRIPTOR("), 2)
        self.assertIn("0x02, 0x82, 64)", self.descriptors)
        self.assertIn("0x04, 0x84, 64)", self.descriptors)
        self.assertIn(".bcdDevice = UINT16_C(0x0100)", self.descriptors)
        self.assertIn('"PBNS Proxy v1"', self.descriptors)

    def test_credential_layout_still_decodes_spki_and_reserves_two_sectors(self) -> None:
        self.assertIn("item.uDataType != QCBOR_TYPE_BYTE_STRING", self.credentials)
        self.assertIn("sizeof(parsed.spki_sha256)", self.credentials)
        self.assertIn("memcpy(parsed.spki_sha256", self.credentials)
        self.assertIn("PBNS_CREDENTIALS_SLOT_COUNT 2U", (
            PBNS_ROOT / "pico" / "include" / "pbns_proxy" / "credentials.h"
        ).read_text(encoding="utf-8"))
        self.assertIn("2 * 4096", self.cmake)
        self.assertIn("PBNS_CREDENTIALS_SLOT_COUNT", self.main)

    def test_lifecycle_uses_session_poll_in_ready_state(self) -> None:
        self.assertIn("ops->session_poll", self.network)
        ready = self.network[self.network.index("case PBNS_NETWORK_READY") :]
        self.assertIn("ops->session_poll", ready)
        self.assertNotIn("ops->tls_poll", self.network)


if __name__ == "__main__":
    unittest.main()
