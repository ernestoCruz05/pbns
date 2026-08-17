import importlib
import json
import pathlib
import stat
import tempfile
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class HostedTLSReplaySourcePolicyTest(unittest.TestCase):
    def test_tls_observer_is_conditional_and_wired_to_every_boundary(self) -> None:
        source = (ROOT / "pico/src/tls_client.c").read_text(encoding="utf-8")
        for marker in (
            "#if defined(PBNS_TLS_REPLAY_OBSERVER)",
            "PBNS_TLS_REPLAY_ALLOCATOR_INSTALLED",
            "PBNS_TLS_REPLAY_PIN_VERIFIER_INITIALIZED",
            "PBNS_TLS_REPLAY_DRBG_SEEDED",
            "PBNS_TLS_REPLAY_TLS_DEFAULTS_CONFIGURED",
            "PBNS_TLS_REPLAY_SSL_CONTEXT_CONFIGURED",
            "PBNS_TLS_REPLAY_HOSTNAME_INSTALLED",
            "PBNS_TLS_REPLAY_ENCRYPTED_BIO_INSTALLED",
            "PBNS_TLS_REPLAY_FIRST_CLIENT_BYTES_WRITTEN",
            "PBNS_TLS_REPLAY_FIRST_SERVER_BYTES_RECEIVED",
            "PBNS_TLS_REPLAY_CERTIFICATE_VERIFIER_ENTERED",
            "PBNS_TLS_REPLAY_LEAF_SPKI_MATCHED",
            "PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED",
            "PBNS_TLS_REPLAY_PROFILE_VALIDATED",
            "pbns_tls_replay_observe_handshake_error",
        ):
            self.assertIn(marker, source)

    def test_selected_version_and_profile_discriminators_precede_validation(
        self,
    ) -> None:
        source = (ROOT / "pico/src/tls_client.c").read_text(encoding="utf-8")
        start = source.index("static pbns_status validate_handshake")
        version = source.index("mbedtls_ssl_get_version_number", start)
        classifier = source.index("PBNS_TLS_REPLAY_SELECTED_VERSION", version)
        cipher = source.index("mbedtls_ssl_get_ciphersuite_id_from_ssl", classifier)
        profile = source.index("PBNS_TLS_REPLAY_SELECTED_PROFILE", cipher)
        production = source.index("pbns_tls_validate_profile", profile)
        self.assertLess(version, classifier)
        self.assertLess(classifier, cipher)
        self.assertLess(cipher, profile)
        self.assertLess(profile, production)
        for marker in (
            "mbedtls_ssl_is_handshake_over",
            "MBEDTLS_SSL_VERSION_UNKNOWN",
            "MBEDTLS_SSL_VERSION_TLS1_2",
            "MBEDTLS_SSL_VERSION_TLS1_3",
            "PBNS_TLS_VERSION_1_2",
        ):
            self.assertIn(marker, source)

    def test_alpn_configuration_and_validation_order_is_explicit(self) -> None:
        source = (ROOT / "pico/src/tls_client.c").read_text(encoding="utf-8")
        init = source.index("pbns_status pbns_tls_client_init")
        protocols = source.index("approved_alpn_protocols")
        defaults = source.index("mbedtls_ssl_config_defaults", init)
        configure = source.index("mbedtls_ssl_conf_alpn_protocols", defaults)
        setup = source.index("mbedtls_ssl_setup", configure)
        validate = source.index("static pbns_status validate_handshake")
        selected = source.index("mbedtls_ssl_get_alpn_protocol", validate)
        observer = source.index("PBNS_TLS_REPLAY_SELECTED_ALPN", selected)
        profile = source.index("pbns_tls_validate_profile", observer)
        self.assertLess(protocols, init)
        self.assertLess(defaults, configure)
        self.assertLess(configure, setup)
        self.assertLess(selected, observer)
        self.assertLess(observer, profile)

    def test_heap_default_is_overrideable_only_by_build_definition(self) -> None:
        header = (ROOT / "pico/include/pbns_proxy/tls_client.h").read_text(
            encoding="utf-8"
        )
        self.assertIn("#ifndef PBNS_TLS_HEAP_WORDS", header)
        self.assertIn("#define PBNS_TLS_HEAP_WORDS 16384U", header)

    def test_physical_targets_never_define_replay_observer(self) -> None:
        cmake = (ROOT / "pico/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertNotIn("PBNS_TLS_REPLAY_OBSERVER", cmake)
        self.assertNotIn("MBEDTLS_MEMORY_ALIGN_MULTIPLE", cmake)

    def test_host_mbedtls_config_is_propagated_by_imported_targets(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        loop = cmake.index("foreach(component IN ITEMS mbedcrypto mbedx509 mbedtls)")
        propagation = cmake.index(
            "target_compile_definitions(pbns-${component}-host INTERFACE", loop
        )
        end = cmake.index("endforeach()", propagation)
        self.assertLess(loop, propagation)
        self.assertLess(propagation, end)
        self.assertIn('MBEDTLS_CONFIG_FILE="${PBNS_MBEDTLS_CONFIG}"', cmake)

    def test_host_mbedtls_alignment_matches_pointer_abi(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("CMAKE_SIZEOF_VOID_P", cmake)
        self.assertIn("MBEDTLS_MEMORY_ALIGN_MULTIPLE=8", cmake)
        self.assertIn("MBEDTLS_MEMORY_ALIGN_MULTIPLE=4", cmake)

    def test_host_debug_paths_are_reproducibly_mapped(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        warnings = (ROOT / "cmake/PbnsWarnings.cmake").read_text(encoding="utf-8")
        for marker in ("-ffile-prefix-map", "-fdebug-prefix-map", "-fmacro-prefix-map"):
            self.assertIn(marker, cmake)
            self.assertIn(marker, warnings)


class HostedTLSReplayOracleTest(unittest.TestCase):
    @staticmethod
    def modules() -> tuple[types.ModuleType, types.ModuleType]:
        identity = importlib.import_module("pbns.integration.tls.test_identity")
        replay = importlib.import_module("pbns.integration.tls.hosted_replay")
        return identity, replay

    def test_matching_ip_san_preserves_committed_spki(self) -> None:
        identity, _ = self.modules()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            certificate = identity.make_matching_certificate(
                root, server_name="127.0.0.1"
            )
            expected = (
                identity.TLS_FIXTURES / "tls-gateway-test-spki.sha256"
            ).read_text(encoding="ascii").strip()
            self.assertEqual(identity.certificate_spki_sha256(certificate), expected)
            self.assertEqual(stat.S_IMODE(certificate.stat().st_mode), 0o600)

    def test_invalid_identity_fails_before_openssl(self) -> None:
        identity, _ = self.modules()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with self.assertRaises(identity.TLSIdentityError):
                identity.make_matching_certificate(
                    root, server_name="bad/name.example"
                )
            self.assertEqual(tuple(root.iterdir()), ())

    def test_ready_requires_exact_typed_events_and_milestones(self) -> None:
        _, replay = self.modules()
        result = replay.validate_replay_result(
            "ready",
            [True] * 13,
            ["tcp-accepted", "tls-handshake-complete", "alpn-selected"],
        )
        self.assertEqual(result.terminal, "ready")
        self.assertEqual(result.server_events[-1], "alpn-selected")
        with self.assertRaises(replay.ReplayError):
            replay.validate_replay_result(
                "ready",
                [True] * 13,
                ["tcp-accepted", "tls-handshake-complete", "alpn-absent"],
            )
        for events in (
            ["tcp-accepted", "tcp-accepted"],
            ["tls-handshake-complete"],
            ["tcp-accepted", "tls-handshake-complete", "alpn-selected", "alpn-absent"],
            ["tcp-accepted", "unknown"],
        ):
            with self.subTest(events=events), self.assertRaises(replay.ReplayError):
                replay.validate_replay_result("ready", [True] * 13, events)
        with self.assertRaises(replay.ReplayError):
            replay.validate_replay_result(
                "ready", [True] * 12 + [False],
                ["tcp-accepted", "tls-handshake-complete", "alpn-absent"],
            )

    def test_profile_component_terminals_require_completed_handshake(self) -> None:
        _, replay = self.modules()
        events = ["tcp-accepted", "tls-handshake-complete", "alpn-absent"]
        for terminal in (
            "profile-version-handshake-incomplete",
            "profile-version-unknown",
            "profile-version-tls13",
            "profile-version-conversion-inconsistent",
            "profile-version-other",
            "profile-version-unsupported",
            "profile-cipher-unsupported",
        ):
            with self.subTest(terminal=terminal):
                result = replay.validate_replay_result(
                    terminal, [True] * 12 + [False], events
                )
                self.assertEqual(result.terminal, terminal)
                selected = replay.validate_replay_result(
                    terminal,
                    [True] * 12 + [False],
                    ["tcp-accepted", "tls-handshake-complete", "alpn-selected"],
                )
                self.assertEqual(selected.terminal, terminal)
                for milestones, invalid_events in (
                    ([True] * 13, events),
                    ([True] * 11 + [False, False], events),
                    ([True] * 12 + [False], []),
                    ([True] * 12 + [False], ["tcp-accepted"]),
                    (
                        [True] * 12 + [False],
                        [
                            "tcp-accepted",
                            "tls-handshake-complete",
                            "alpn-selected",
                            "alpn-absent",
                        ],
                    ),
                ):
                    with self.assertRaises(replay.ReplayError):
                        replay.validate_replay_result(
                            terminal, milestones, invalid_events
                        )

    def test_alpn_terminal_requires_absent_negotiation(self) -> None:
        _, replay = self.modules()
        absent = ["tcp-accepted", "tls-handshake-complete", "alpn-absent"]
        result = replay.validate_replay_result(
            "profile-alpn-unsupported", [True] * 12 + [False], absent
        )
        self.assertEqual(result.terminal, "profile-alpn-unsupported")
        for milestones, events in (
            ([True] * 13, absent),
            ([True] * 11 + [False, False], absent),
            (
                [True] * 12 + [False],
                ["tcp-accepted", "tls-handshake-complete", "alpn-selected"],
            ),
        ):
            with self.assertRaises(replay.ReplayError):
                replay.validate_replay_result(
                    "profile-alpn-unsupported", milestones, events
                )

    def test_missing_server_alpn_is_typed(self) -> None:
        identity, replay = self.modules()
        executable = ROOT / "build/dev/pbns-pico-tls-replay"
        pin = (
            identity.TLS_FIXTURES / "tls-gateway-test-spki.sha256"
        ).read_text(encoding="ascii").strip()
        result = replay.run_replay_scenario(executable, pin, server_alpn=False)
        self.assertEqual(result.terminal, "profile-alpn-unsupported")
        self.assertEqual(result.milestones, (True,) * 12 + (False,))
        self.assertEqual(
            result.server_events,
            ("tcp-accepted", "tls-handshake-complete", "alpn-absent"),
        )

    def test_exact_replay_entropy_and_wrong_pin_are_typed(self) -> None:
        identity, replay = self.modules()
        executable = ROOT / "build/dev/pbns-pico-tls-replay"
        self.assertTrue(executable.is_file())
        pin = (
            identity.TLS_FIXTURES / "tls-gateway-test-spki.sha256"
        ).read_text(encoding="ascii").strip()

        entropy = replay.run_replay_scenario(
            executable, pin, arguments=("--entropy-fail",)
        )
        self.assertEqual(entropy.terminal, "init-entropy")
        self.assertEqual(entropy.server_events, ())

        baseline = replay.run_replay_scenario(executable, pin)
        self.assertIn(baseline.terminal, replay.TERMINALS)
        if baseline.terminal == "ready":
            self.assertEqual(
                baseline.server_events,
                ("tcp-accepted", "tls-handshake-complete", "alpn-selected"),
            )

        wrong_pin = replay.run_replay_scenario(executable, "0" * 64)
        self.assertEqual(wrong_pin.terminal, "handshake-pin")
        self.assertEqual(
            wrong_pin.server_events,
            ("tcp-accepted", "tls-handshake-failed"),
        )

    def test_self_test_requires_all_fault_classifications(self) -> None:
        identity, replay = self.modules()
        executable = ROOT / "build/dev/pbns-pico-tls-replay"
        pin = (
            identity.TLS_FIXTURES / "tls-gateway-test-spki.sha256"
        ).read_text(encoding="ascii").strip()
        baseline = replay.self_test(executable, pin)
        self.assertIn(baseline.terminal, replay.TERMINALS)

    def test_reduced_heap_boundaries_and_ten_run_determinism(self) -> None:
        identity, replay = self.modules()
        executable = ROOT / "build/dev/pbns-pico-tls-replay"
        pin = (
            identity.TLS_FIXTURES / "tls-gateway-test-spki.sha256"
        ).read_text(encoding="ascii").strip()
        boundaries = replay.find_reduced_heap_boundaries(executable, pin)
        self.assertEqual(boundaries.initialization.terminal, "init-resource")
        self.assertEqual(
            boundaries.handshake.terminal, "handshake-allocator"
        )
        baseline = replay.run_determinism_campaign(
            executable, pin, repetitions=10
        )
        self.assertEqual(baseline.terminal, "ready")

    def test_final_campaign_writes_only_redacted_typed_evidence(self) -> None:
        identity, replay = self.modules()
        executable = ROOT / "build/dev/pbns-pico-tls-replay"
        pin = (
            identity.TLS_FIXTURES / "tls-gateway-test-spki.sha256"
        ).read_text(encoding="ascii").strip()
        with tempfile.TemporaryDirectory() as directory:
            results = pathlib.Path(directory) / "results"
            result, result_path, digest_path = replay.run_evidence_campaign(
                executable,
                pin,
                results,
                repetitions=2,
                timestamp="20260730T161500Z",
            )
            self.assertEqual(result.terminal, "ready")
            self.assertEqual(stat.S_IMODE(result_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(digest_path.stat().st_mode), 0o600)
            decoded = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(decoded["terminal"], result.terminal)
            self.assertEqual(decoded["repetitions"], 2)
            self.assertEqual(set(decoded), replay.EVIDENCE_FIELDS)

    def test_private_atomic_evidence_rejects_sensitive_fields(self) -> None:
        _, replay = self.modules()
        evidence = {
            "config_sha256": "1" * 64,
            "elapsed_ms": 10,
            "executable_sha256": "2" * 64,
            "heap_selector": "exact",
            "mbedtls_revision": "0bebf8b8c7f07abe3571ded48a11aa907a1ffb20",
            "milestones": [True] * 13,
            "repetitions": 10,
            "server_events": [
                "tcp-accepted",
                "tls-handshake-complete",
                "alpn-selected",
            ],
            "source_sha256": "3" * 64,
            "terminal": "ready",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "results"
            result_path, digest_path = replay.write_replay_evidence(
                root, evidence, timestamp="20260730T160000Z"
            )
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(result_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(digest_path.stat().st_mode), 0o600)
            decoded = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(decoded, evidence)
            bad = dict(evidence)
            bad["nested"] = {"private_key": "forbidden"}
            with self.assertRaises(replay.ReplayError):
                replay.write_replay_evidence(
                    root, bad, timestamp="20260730T160001Z"
                )


if __name__ == "__main__":
    unittest.main()
