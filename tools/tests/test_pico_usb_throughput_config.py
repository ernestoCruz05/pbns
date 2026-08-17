import pathlib
import re
import unittest


def extract_static_function_body(source: str, name: str) -> str:
    """Return one static C function body while ignoring braces in literals/comments."""
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
    index = opening
    state = "code"
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if character == '"':
                state = "string"
            elif character == "'":
                state = "character"
            elif character == "/" and following == "/":
                state = "line-comment"
                index += 1
            elif character == "/" and following == "*":
                state = "block-comment"
                index += 1
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return source[opening + 1 : index]
        elif state in ("string", "character"):
            if character == "\\":
                index += 1
            elif (state == "string" and character == '"') or (
                state == "character" and character == "'"
            ):
                state = "code"
        elif state == "line-comment":
            if character == "\n":
                state = "code"
        elif state == "block-comment" and character == "*" and following == "/":
            state = "code"
            index += 1
        index += 1

    raise AssertionError(f"unterminated static {name} definition")


class PicoUsbThroughputConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(__file__).parents[2]
        self.config = (self.root / "pico" / "include" / "tusb_config.h").read_text(
            encoding="utf-8"
        )
        self.descriptors = (
            self.root / "pico" / "src" / "usb_descriptors.c"
        ).read_text(encoding="utf-8")
        self.main = (self.root / "pico" / "src" / "main.c").read_text(
            encoding="utf-8"
        )
        self.byte_pump_header = (
            self.root / "pico" / "include" / "pbns_proxy" / "byte_pump.h"
        ).read_text(encoding="utf-8")
        self.byte_pump = (self.root / "pico" / "src" / "byte_pump.c").read_text(
            encoding="utf-8"
        )
        self.tail_deadline = (
            self.root / "pico" / "src" / "tail_deadline.c"
        ).read_text(encoding="utf-8")
        self.dependencies_lock = (self.root / "dependencies.lock").read_text(
            encoding="utf-8"
        )
        self.rp2040_dcd = (
            self.root
            / ".deps"
            / "pico_sdk"
            / "lib"
            / "tinyusb"
            / "src"
            / "portable"
            / "raspberrypi"
            / "rp2040"
            / "rp2040_usb.c"
        ).read_text(encoding="utf-8")

    def assert_tunnel_deadline_contract(self, source: str) -> None:
        tunnel_task = extract_static_function_body(source, "tunnel_task")
        for required in (
            "pbns_tail_deadline_should_force",
            "pbns_tail_deadline_observe_input",
            "usb_to_tls_read_generation",
            "pbns_tail_deadline_reset",
            "TUNNEL_AGGREGATION_DEADLINE_US",
        ):
            self.assertIn(required, tunnel_task)

    def macro_definitions(self, name: str) -> list[str]:
        return re.findall(
            rf"(?m)^#define[ \t]+{re.escape(name)}[ \t]+([^\r\n/]+)",
            self.config,
        )

    def test_tinyusb_internal_cdc_queues_are_exactly_4096_bytes(self) -> None:
        for name in ("CFG_TUD_CDC_RX_BUFSIZE", "CFG_TUD_CDC_TX_BUFSIZE"):
            with self.subTest(name=name):
                self.assertEqual(self.macro_definitions(name), ["4096"])

    def test_cdc_count_transfer_buffer_and_descriptor_packet_size_do_not_drift(self) -> None:
        self.assertEqual(self.macro_definitions("CFG_TUD_CDC"), ["2"])
        self.assertEqual(self.macro_definitions("CFG_TUD_CDC_EP_BUFSIZE"), ["4096"])

        descriptors = re.sub(r"\s+", " ", self.descriptors)
        self.assertEqual(descriptors.count("TUD_CDC_DESCRIPTOR("), 2)
        self.assertIn(
            "TUD_CDC_DESCRIPTOR(INTERFACE_CDC_DATA_CONTROL, "
            "STRING_DATA_INTERFACE, 0x81, 8, 0x02, 0x82, 64)",
            descriptors,
        )
        self.assertIn(
            "TUD_CDC_DESCRIPTOR(INTERFACE_CDC_PROVISION_CONTROL, "
            "STRING_PROVISION_INTERFACE, 0x83, 8, 0x04, 0x84, 64)",
            descriptors,
        )

    def test_buffer_configuration_rejects_queue_transfer_and_descriptor_mutants(self) -> None:
        descriptor_64 = "0x02, 0x82, 64)"
        mutants = {
            "RX queue reduced": self.config.replace(
                "CFG_TUD_CDC_RX_BUFSIZE 4096", "CFG_TUD_CDC_RX_BUFSIZE 512", 1
            ),
            "TX queue reduced": self.config.replace(
                "CFG_TUD_CDC_TX_BUFSIZE 4096", "CFG_TUD_CDC_TX_BUFSIZE 512", 1
            ),
            "transfer buffer reduced": self.config.replace(
                "CFG_TUD_CDC_EP_BUFSIZE 4096", "CFG_TUD_CDC_EP_BUFSIZE 1024", 1
            ),
        }
        for name, mutant in mutants.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutant, self.config)
                with self.assertRaises(AssertionError):
                    if name == "transfer buffer reduced":
                        self.assertEqual(
                            re.findall(
                                r"(?m)^#define[ \t]+CFG_TUD_CDC_EP_BUFSIZE[ \t]+(\d+)$",
                                mutant,
                            ),
                            ["4096"],
                        )
                    else:
                        self.assertEqual(
                            re.findall(
                                r"(?m)^#define[ \t]+CFG_TUD_CDC_(?:RX|TX)_BUFSIZE[ \t]+4096$",
                                mutant,
                            ),
                            [
                                "#define CFG_TUD_CDC_RX_BUFSIZE 4096",
                                "#define CFG_TUD_CDC_TX_BUFSIZE 4096",
                            ],
                        )
        descriptor_mutant = self.descriptors.replace(descriptor_64, "0x02, 0x82, 512)", 1)
        self.assertNotEqual(descriptor_mutant, self.descriptors)
        with self.assertRaises(AssertionError):
            self.assertIn(descriptor_64, descriptor_mutant)

    def test_pinned_rp2040_dcd_chains_4096_byte_transfers_over_64_byte_packets(self) -> None:
        self.assertIn(
            "tinyusb|https://github.com/hathach/tinyusb.git|"
            "86ad6e56c1700e85f1c5678607a762cfe3aa2f47|",
            self.dependencies_lock,
        )
        self.assertIn("ep->remaining_len = total_len;", self.rp2040_dcd)
        self.assertIn(
            "tu_min16(ep->remaining_len, ep->wMaxPacketSize)", self.rp2040_dcd
        )
        self.assertIn(
            "ep->remaining_len = (uint16_t) (ep->remaining_len - buflen);",
            self.rp2040_dcd,
        )
        self.assertIn("hw_endpoint_xfer_continue", self.rp2040_dcd)
        self.assertIn("hw_endpoint_start_next_buffer(ep);", self.rp2040_dcd)

    def test_data_and_provisioning_roles_remain_separate(self) -> None:
        self.assertRegex(
            self.main,
            r"(?m)^#define DATA_CDC_INSTANCE UINT8_C\(0\)$",
        )
        self.assertRegex(
            self.main,
            r"(?m)^#define PROVISION_CDC_INSTANCE UINT8_C\(1\)$",
        )
        self.assertRegex(
            self.main,
            r"(?m)^#define TUNNEL_RING_CAPACITY 4096U$",
        )
        self.assertIn("tud_cdc_n_write_flush(PROVISION_CDC_INSTANCE)", self.main)

        data_io = self.main.split("static pbns_status data_usb_read", 1)[1].split(
            "static void tunnel_init", 1
        )[0]
        provisioning_io = self.main.split("static bool send_text", 1)[1].split(
            "static char hexadecimal_digit", 1
        )[0]
        self.assertIn("DATA_CDC_INSTANCE", data_io)
        self.assertNotIn("PROVISION_CDC_INSTANCE", data_io)
        self.assertIn("PROVISION_CDC_INSTANCE", provisioning_io)
        self.assertNotIn("DATA_CDC_INSTANCE", provisioning_io)

    def test_tunnel_uses_nonblocking_usb_and_bounded_batch_pacing(self) -> None:
        self.assertRegex(self.main, r"tud_task_ext\(0U,\s*false\);")
        self.assertNotIn("sleep_ms(1U)", self.main)
        self.assertRegex(
            self.main,
            r"#define TUNNEL_IDLE_PACING_US 50U\n",
        )
        self.assertRegex(
            self.main,
            r"if \(tunnel_task\(\)\) \{\s*sleep_us\(TUNNEL_IDLE_PACING_US\);\s*\}",
        )
        self.assertIn("pbns_byte_pump_batch", self.main)

    def assert_data_flush_contract(self, source: str) -> None:
        data_write = extract_static_function_body(source, "data_usb_write")
        tunnel_task = extract_static_function_body(source, "tunnel_task")
        write_call = "tud_cdc_n_write(DATA_CDC_INSTANCE, source.ptr, (uint32_t)amount)"
        nonzero_write = re.search(
            r"if\s*\(\s*actual\s*==\s*0U\s*\)\s*\{\s*"
            r"return\s+PBNS_ERR_WOULD_BLOCK\s*;\s*\}",
            data_write,
        )
        self.assertIsNotNone(nonzero_write)
        self.assertIn(write_call, data_write)
        queue_assignments = list(
            re.finditer(r"(?m)^[ \t]*data_usb_bytes_queued\s*=\s*true\s*;", source)
        )
        self.assertEqual(len(queue_assignments), 1)
        queue_assignment = queue_assignments[0]
        data_write_start = source.index(data_write)
        queue_offset = queue_assignment.start() - data_write_start
        self.assertGreaterEqual(queue_offset, 0)
        self.assertLess(queue_offset, len(data_write))
        self.assertLess(data_write.index(write_call), queue_offset)
        self.assertLess(nonzero_write.end(), queue_offset)

        flush = "tud_cdc_n_write_flush(DATA_CDC_INSTANCE)"
        self.assertNotIn("tud_cdc_n_write_flush", data_write)
        self.assertEqual(source.count(flush), 1)
        flush_guard = re.search(
            r"if\s*\(\s*data_usb_bytes_queued\s*\)\s*\{\s*"
            r"tud_cdc_n_write_flush\(DATA_CDC_INSTANCE\)\s*;\s*\}",
            tunnel_task,
        )
        self.assertIsNotNone(flush_guard)
        self.assertEqual(tunnel_task.count(flush), 1)
        batch_call = tunnel_task.index("pbns_byte_pump_batch_with_policy(")
        queue_reset = tunnel_task.index("data_usb_bytes_queued = false;")
        terminal_handling = tunnel_task.index(
            "if (status != PBNS_OK || pbns_byte_pump_is_complete(&tunnel_pump))"
        )
        self.assertLess(queue_reset, batch_call)
        self.assertLess(batch_call, flush_guard.start())
        self.assertLess(flush_guard.end(), terminal_handling)

    def test_data_flush_is_coalesced_after_each_batch(self) -> None:
        self.assert_data_flush_contract(self.main)

    def test_data_flush_contract_rejects_queue_and_flush_mutants(self) -> None:
        queue_assignment = "  data_usb_bytes_queued = true;\n"
        flush_guard = (
            "  if (data_usb_bytes_queued) {\n"
            "    tud_cdc_n_write_flush(DATA_CDC_INSTANCE);\n"
            "  }\n"
        )
        removed_assignment = self.main.replace(queue_assignment, "", 1)
        before_write = removed_assignment.replace(
            "  const uint32_t actual =\n",
            queue_assignment + "  const uint32_t actual =\n",
            1,
        )
        unconditional_assignment = removed_assignment.replace(
            "  data_usb_bytes_queued = false;\n",
            "  data_usb_bytes_queued = false;\n" + queue_assignment,
            1,
        )
        unconditional_flush = self.main.replace(
            flush_guard, "  tud_cdc_n_write_flush(DATA_CDC_INSTANCE);\n", 1
        )
        duplicate_flush = self.main.replace(flush_guard, flush_guard + flush_guard, 1)
        after_terminal_handling = self.main.replace(flush_guard, "", 1).replace(
            "  return usb_connected;\n}",
            "  tud_cdc_n_write_flush(DATA_CDC_INSTANCE);\n  return usb_connected;\n}",
            1,
        )
        mutants = {
            "removed queue assignment": removed_assignment,
            "queue assignment before write": before_write,
            "unconditional queue assignment": unconditional_assignment,
            "unconditional flush": unconditional_flush,
            "duplicated flush": duplicate_flush,
            "flush after terminal handling": after_terminal_handling,
        }
        for name, mutant in mutants.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutant, self.main)
                with self.assertRaises(AssertionError):
                    self.assert_data_flush_contract(mutant)

    def test_function_body_extractor_ignores_nested_literals_and_comments(self) -> None:
        source = '''
static void sample(void) {
  const char *literal = "brace }";
  /* { comment } */
  if (true) { // }
    char quote = '\\'';
  }
}
'''
        self.assertIn('const char *literal = "brace }";', extract_static_function_body(source, "sample"))

    def test_portable_batch_contract_remains_bounded(self) -> None:
        self.assertRegex(
            self.byte_pump_header,
            r"#define PBNS_BYTE_PUMP_BATCH_MAX_STEPS 8U\n",
        )
        self.assertIn("pbns_byte_pump_batch", self.byte_pump_header)
        self.assertIn("pbns_byte_pump_batch", self.byte_pump)
        self.assertIn("step_count < PBNS_BYTE_PUMP_BATCH_MAX_STEPS", self.byte_pump)

    def test_tunnel_aggregation_policy_and_deadline_are_locked(self) -> None:
        self.assertRegex(
            self.main, r"(?m)^#define TUNNEL_AGGREGATION_THRESHOLD 2048U$"
        )
        self.assertRegex(
            self.main,
            r"(?m)^#define TUNNEL_AGGREGATION_DEADLINE_US UINT64_C\(5000\)$",
        )
        tunnel_task = extract_static_function_body(self.main, "tunnel_task")
        self.assertIn("time_us_64()", tunnel_task)
        self.assert_tunnel_deadline_contract(self.main)
        self.assertIn("pbns_byte_pump_batch_with_policy", tunnel_task)
        self.assertIn(".usb_to_tls_minimum_write = TUNNEL_AGGREGATION_THRESHOLD", tunnel_task)
        self.assertIn(".tls_to_usb_minimum_writable = TUNNEL_AGGREGATION_THRESHOLD", tunnel_task)
        self.assertIn("!network_progress && !pump_progress && !rings_pending", tunnel_task)
        self.assertNotIn("time_us_64", self.tail_deadline)

        mutants = {
            "fresh input omitted": self.main.replace(
                "pbns_tail_deadline_observe_input", "tail_deadline_observe_input", 1
            ),
            "deadline force omitted": self.main.replace(
                "pbns_tail_deadline_should_force", "tail_deadline_should_force", 1
            ),
            "reset omitted": self.main.replace(
                "pbns_tail_deadline_reset", "tail_deadline_reset"
            ),
        }
        for name, mutant in mutants.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutant, self.main)
                with self.assertRaises(AssertionError):
                    self.assert_tunnel_deadline_contract(mutant)

    def test_policy_contract_rejects_directional_mutants(self) -> None:
        self.assertIn("pbns_byte_pump_policy", self.byte_pump_header)
        self.assertIn("should_hold_write", self.byte_pump)
        self.assertIn("size < direction->minimum_write", self.byte_pump)
        self.assertIn("!direction->force_write", self.byte_pump)
        self.assertIn("!*direction->source_closed", self.byte_pump)
        self.assertIn("size < pbns_byte_ring_capacity(direction->ring)", self.byte_pump)
        self.assertIn("writable.cap < direction->minimum_writable", self.byte_pump)
        self.assertIn("pbns_byte_ring_size(direction->ring) != 0U", self.byte_pump)

        mutants = {
            "deadline force": (
                self.byte_pump.replace("!direction->force_write &&\n", "", 1),
                "!direction->force_write",
            ),
            "source close": (
                self.byte_pump.replace("!*direction->source_closed &&\n", "", 1),
                "!*direction->source_closed",
            ),
            "inbound watermark": (
                self.byte_pump.replace(
                    "writable.cap < direction->minimum_writable", "false", 1
                ),
                "writable.cap < direction->minimum_writable",
            ),
        }
        for name, (mutant, required) in mutants.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutant, self.byte_pump)
                self.assertNotIn(required, mutant)


if __name__ == "__main__":
    unittest.main()
