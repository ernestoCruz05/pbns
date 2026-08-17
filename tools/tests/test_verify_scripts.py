import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest


STAGES = (
    "dependency-lock",
    "dev",
    "sanitize",
    "go",
    "race",
    "interop",
)
DEFERRED = (
    "[DEFERRED] parser-robustness: blocked by platform execution policy; "
    "no campaign evidence"
)
TRANSPORT_STAGES = (
    "byte-pump",
    "pico-build",
    "uefi-build",
    "gateway-race",
    "proxy-sim",
    "pico-loopback",
    "qemu-probe",
)


class VerifyFoundationsScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).parents[2]
        self.script = self.pbns_root / "tools" / "verify-foundations.sh"

    def test_declares_every_required_stage_and_conditional_result(self) -> None:
        contents = self.script.read_text(encoding="utf-8")
        for stage in STAGES:
            self.assertIn(f'run_stage "{stage}"', contents)
        self.assertIn("set -euo pipefail", contents)
        self.assertIn(DEFERRED, contents)
        self.assertIn("FOUNDATIONS CONDITIONAL PASS", contents)
        self.assertIn("/usr/lib/llvm/22/bin", contents)
        self.assertIn("go vet -mod=readonly ./...", contents)
        self.assertIn("byte-pump", contents)
        self.assertIn("usb-transport", contents)
        self.assertIn("uefi-clock-math", contents)
        self.assertIn("identity", contents)
        self.assertIn("identity-record", contents)
        self.assertIn("software-identity", contents)
        self.assertIn("broker", contents)
        self.assertIn("credentials", contents)
        self.assertIn("pico-record-validate", contents)
        self.assertIn("spki-pin", contents)
        self.assertIn("reconnect", contents)
        self.assertIn("provision-gate", contents)
        self.assertIn("entropy", contents)
        self.assertIn("diagnostic", contents)

    def test_transport_gate_declares_every_required_stage(self) -> None:
        script = self.pbns_root / "tools" / "verify-transport.sh"
        contents = script.read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", contents)
        self.assertIn("--require-hardware", contents)
        self.assertIn("--provision-now", contents)
        self.assertIn("PICO PROVISIONING CHECKPOINT PASS", contents)
        self.assertIn("pbns-pico-record-validate", contents)
        self.assertIn("provision-pico.py", contents)
        self.assertNotIn('pico-loopback.py\" validate-record', contents)
        loopback_start = contents.index("verify_pico_loopback()")
        loopback_end = contents.index("\n}\n\nverify_qemu_probe", loopback_start)
        loopback = contents[loopback_start:loopback_end]
        self.assertNotIn("PBNS_PROVISION_RECORD", loopback)
        self.assertNotIn("PBNS_PROVISION_PORT", loopback)
        self.assertNotIn("provision-pico.py", loopback)
        for stage in TRANSPORT_STAGES:
            self.assertIn(f'run_stage "{stage}"', contents)
        self.assertIn("TRANSPORT PASS", contents)
        for marker in ("PBNS_ECHO_SERVER_NAME", "PBNS_GATEWAY_SERVER_NAME"):
            self.assertIn(marker, contents)

        hil_script = (
            self.pbns_root / "integration" / "hil" / "pico-loopback.sh"
        ).read_text(encoding="utf-8")
        for marker in (
            "PBNS_GATEWAY_SERVER_NAME",
            "PBNS_PROVISION_PORT",
            "uefi-tls-tunnel.py",
            "gateway-reissued-cert.pem",
            "wrong-san",
            "wrong-spki",
            "wrong-alpn",
            "wrong-cipher",
            "truncation",
            "digest-mismatch",
        ):
            self.assertIn(marker, hil_script)
        self.assertNotIn("PBNS_ECHO_SERVER_NAME", hil_script)
        self.assertNotIn("provision-pico.py", hil_script)
        self.assertNotIn("PBNS_ECHO_CERT:-", hil_script)

    def test_transport_modes_are_mutually_exclusive_before_any_stage(self) -> None:
        script = self.pbns_root / "tools" / "verify-transport.sh"
        result = subprocess.run(
            [str(script), "--software-only", "--provision-now"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("[RUN]", result.stdout)
        contents = script.read_text(encoding="utf-8")
        provision = contents.index("if [[ $MODE == --provision-now ]]")
        first_stage = contents.index('run_stage "byte-pump"')
        self.assertLess(provision, first_stage)
        self.assertIn("exit 0", contents[provision:first_stage])

    def test_pico_build_checks_dependencies_and_memory_layout(self) -> None:
        contents = (self.pbns_root / "tools" / "build-pico.sh").read_text(
            encoding="utf-8"
        )
        for dependency in ("pico_sdk", "mbedtls", "tinyusb", "picotool"):
            self.assertIn(f"verify_checkout {dependency}", contents)
        self.assertIn("submodule status --recursive", contents)
        self.assertIn("SOURCE_DATE_EPOCH", contents)
        self.assertIn("PICOTOOL_GIT_REPOSITORY_URL", contents)
        self.assertIn('"00001000"', contents)
        self.assertIn('"0x001fe000"', contents)
        self.assertIn("arm-none-eabi-nm", contents)
        self.assertIn("PBNS_INSECURE", contents)
        self.assertIn("lwip_socket", contents)
        self.assertIn("MBEDTLS_CONFIG_FILE", contents)
        self.assertIn("mbedtls_hardware_poll", contents)
        self.assertIn("mbedtls_ssl_", contents)
        self.assertIn("mbedtls_x509_", contents)
        self.assertIn("pbns_tls_", contents)
        self.assertNotIn("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256", contents)
        self.assertIn(".su", contents)
        self.assertIn("arm-none-eabi-size -A", contents)
        self.assertIn("section_size()", contents)
        self.assertIn("text_size=$(section_size .text)", contents)
        self.assertIn("data_size=$(section_size .data)", contents)
        self.assertIn("raw_bss_size=$(section_size .bss)", contents)
        self.assertIn("ram_vector_table_size=$(section_size .ram_vector_table)", contents)
        self.assertIn("uninitialized_data_size=$(section_size .uninitialized_data)", contents)
        self.assertIn("heap_size=$(section_size .heap)", contents)
        self.assertIn("main_sram_bytes=262144", contents)
        self.assertIn("minimum_heap_bytes=2048", contents)
        self.assertIn("expected_data_bytes=6208", contents)
        self.assertIn("expected_bss_bytes=165036", contents)
        self.assertIn("expected_free_sram_bytes=88852", contents)
        self.assertIn(
            "free_sram_bytes=$((main_sram_bytes - data_size - bss_size - heap_size))",
            contents,
        )
        self.assertIn('if [[ "$free_sram_bytes" != "$expected_free_sram_bytes" ]]', contents)
        self.assertNotIn("stage5_encrypted_rx_capacity", contents)
        pico_cmake = (self.pbns_root / "pico" / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("-fstack-usage", pico_cmake)
        self.assertIn("set(PICO_MBEDTLS_CONFIG_FILE", pico_cmake)
        self.assertIn(
            '"${CMAKE_CURRENT_LIST_DIR}/include/mbedtls_config.h"', pico_cmake
        )
        self.assertIn("src/entropy.c", pico_cmake)
        self.assertNotIn("\n    pico_mbedtls\n", pico_cmake)
        tls_config = (
            self.pbns_root / "pico" / "include" / "mbedtls_config.h"
        ).read_text(encoding="utf-8")
        self.assertIn("MBEDTLS_SSL_PROTO_TLS1_2", tls_config)
        self.assertIn(
            "MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls_config
        )
        lwip_options = (
            self.pbns_root / "pico" / "include" / "lwipopts.h"
        ).read_text(encoding="utf-8")
        self.assertIn("#define LWIP_SOCKET 0", lwip_options)
        self.assertIn("#define LWIP_ALTCP 0", lwip_options)
        firmware = (self.pbns_root / "pico" / "src" / "main.c").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "PICO_FLASH_SIZE_BYTES == PBNS_FLASH_TOTAL_SIZE_BYTES", firmware
        )
        self.assertIn("to_ms_64_since_boot", firmware)
        self.assertNotIn(
            "const bool provisioning_mode = bootsel_is_pressed()", firmware
        )
        for marker in (
            "pbns_provision_gate_sample_due",
            "pbns_provision_gate_observe",
            "pbns_provision_session_activate",
            "pbns_provision_session_observe",
            "tud_cdc_n_read_flush(PROVISION_CDC_INSTANCE)",
            "pbns_pico_network_deinit",
            "secure_zero(usb_to_tcp_storage",
            "secure_zero(tcp_to_usb_storage",
        ):
            self.assertIn(marker, firmware)

    def test_pico_wifi_poll_uses_tcpip_readiness(self) -> None:
        source = (
            self.pbns_root / "pico" / "src" / "pico_network.c"
        ).read_text(encoding="utf-8")
        start = source.index("static pbns_status pico_wifi_poll")
        end = source.index("static pbns_status pico_tcp_poll", start)
        poll = source[start:end]
        self.assertIn(
            "cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA)", poll
        )
        self.assertNotIn("cyw43_wifi_link_status", poll)

    def test_proxy_sim_self_test_is_race_checked(self) -> None:
        script = self.pbns_root / "integration" / "run-proxy-sim.sh"
        contents = script.read_text(encoding="utf-8")
        for marker in (
            "set -euo pipefail",
            '"$1" != --self-test',
            "go test -race",
            "./internal/proxysim",
            "./internal/server",
            "PROXY SIM PASS",
        ):
            self.assertIn(marker, contents)

    def test_executes_every_required_stage(self) -> None:
        fixture, environment, log = self._fixture()
        self.addCleanup(fixture.cleanup)

        result = subprocess.run(
            [str(pathlib.Path(fixture.name) / "pbns" / "tools" / self.script.name)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        for stage in STAGES:
            self.assertIn(f"[PASS] {stage}", lines)
        self.assertIn(DEFERRED, lines)
        self.assertEqual(lines[-1], "FOUNDATIONS CONDITIONAL PASS")
        self.assertNotIn("FOUNDATIONS PASS", lines)
        invoked = log.read_text(encoding="utf-8")
        for command in ("python3", "cmake", "ctest", "go", "sha256sum"):
            self.assertIn(command, invoked)

    def test_fails_when_any_child_command_fails(self) -> None:
        for command in ("python3", "cmake", "ctest", "go", "sha256sum"):
            with self.subTest(command=command):
                fixture, environment, _log = self._fixture()
                with fixture:
                    environment["PBNS_TEST_FAIL_COMMAND"] = command
                    result = subprocess.run(
                        [
                            str(
                                pathlib.Path(fixture.name)
                                / "pbns"
                                / "tools"
                                / self.script.name
                            )
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("FOUNDATIONS CONDITIONAL PASS", result.stdout)

    def _fixture(self):
        fixture = tempfile.TemporaryDirectory()
        root = pathlib.Path(fixture.name)
        tools = root / "pbns" / "tools"
        gateway = root / "pbns" / "gateway"
        vectors = root / "pbns" / "tests" / "vectors" / "cose-encrypt-v1"
        fake_bin = root / "bin"
        tools.mkdir(parents=True)
        gateway.mkdir(parents=True)
        vectors.mkdir(parents=True)
        fake_bin.mkdir()
        shutil.copy2(self.script, tools / self.script.name)

        log = root / "commands.log"
        fake_command = fake_bin / "fake-command"
        fake_command.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "name=$(basename -- \"$0\")\n"
            "printf '%s\\n' \"$name\" >>\"$PBNS_TEST_COMMAND_LOG\"\n"
            "if [[ $name == sha256sum ]]; then cat >/dev/null; fi\n"
            "if [[ ${PBNS_TEST_FAIL_COMMAND:-} == \"$name\" ]]; then exit 9; fi\n",
            encoding="utf-8",
        )
        fake_command.chmod(fake_command.stat().st_mode | stat.S_IXUSR)
        for command in ("python3", "cmake", "ctest", "go", "sha256sum"):
            (fake_bin / command).symlink_to(fake_command)

        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
        environment["PBNS_TEST_COMMAND_LOG"] = str(log)
        environment.pop("PBNS_TEST_FAIL_COMMAND", None)
        return fixture, environment, log


if __name__ == "__main__":
    unittest.main()
