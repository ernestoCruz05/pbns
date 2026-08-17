import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


CASES = (
    "signed-trusted", "unsigned-untrusted", "truncated", "gateway-interruption",
    "forged-manifest", "forged-digest", "forged-chunk", "downgrade",
    "normal-launcher", "pico-absent",
)
RECOVERY_CASES = CASES[:8]
EVALUATION_CASES = ("gateway-interruption", "forged-digest", "forged-chunk")
ARTIFACT_CASES = RECOVERY_CASES
CHUNK_BYTES = 16 * 1024
ARTIFACT_BYTES = b"A" * 123
DIGEST = hashlib.sha256(ARTIFACT_BYTES).hexdigest()


class RecoveryMatrixEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).resolve().parents[2]
        self.tool = self.pbns_root / "integration" / "qemu" / "recovery-matrix-evidence.py"
        spec = importlib.util.spec_from_file_location("recovery_matrix_evidence", self.tool)
        assert spec is not None and spec.loader is not None
        self.validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.validator)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _private_file(self, root: pathlib.Path, name: str, data: bytes) -> pathlib.Path:
        path = root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def _immutable_repository_metadata(self, root: pathlib.Path, digest: str = DIGEST, data: bytes = b'{"metadata":"public"}\n') -> pathlib.Path:
        directory = root / "repository" / "metadata"
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        (root / "repository").chmod(0o700)
        directory.chmod(0o700)
        path = directory / f"{digest}.json"
        path.write_bytes(data)
        path.chmod(0o444)
        return path

    def _lines(self, case: str, size: int = 123) -> list[str]:
        states = [f"PBNS RECOVERY STATE {value}" for value in range(7)]
        if case == "signed-trusted":
            return [
                *states,
                "PBNS RECOVERY MEMORY LOAD BEGIN size=123 version=7",
                "PBNS RECOVERY MEMORY LOAD PASS",
                "PBNS RECOVERY STATE 7",
                "PBNS RECOVERY ROLLBACK ADVANCE BEGIN current=5 target=7",
                "PBNS RECOVERY ROLLBACK ADVANCE PASS",
                "PBNS RECOVERY STATE 8",
                "PBNS RECOVERY STARTIMAGE BEGIN",
                "PBNS RECOVERY READ-ONLY MODE",
            ]
        if case in ("unsigned-untrusted", "truncated"):
            return [
                *states,
                "PBNS RECOVERY MEMORY LOAD BEGIN size=123 version=7",
                "PBNS RECOVERY MEMORY LOAD REJECT status=0x800000000000001a",
                f"PBNS RECOVERY FREE BEGIN size={size}",
                "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9",
                "PBNS RECOVERY FAILED stage=6 status=-8",
            ]
        if case == "forged-manifest":
            return [
                *states[:3],
                "PBNS RECOVERY STATE 9",
                "PBNS RECOVERY FAILED stage=2 status=-8",
            ]
        if case in ("gateway-interruption", "forged-chunk"):
            return [
                *states[:5],
                f"PBNS RECOVERY FREE BEGIN size={size}",
                "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9",
                "PBNS RECOVERY FAILED stage=4 status=-8",
            ]
        if case in ("forged-digest", "downgrade"):
            return [
                *states[:6],
                f"PBNS RECOVERY FREE BEGIN size={size}",
                "PBNS RECOVERY FREE PASS",
                "PBNS RECOVERY STATE 9",
                f"PBNS RECOVERY FAILED stage=5 status={-8 if case == 'forged-digest' else -15}",
            ]
        return [
            "PBNS NORMAL FIXTURE PASS",
            "PBNS RECOVERY FALLBACK stage=1 loader_status=0x800000000000000e",
            "Type RECOVER to download a RAM-only recovery image: ",
        ]

    def _event(self, case: str, fault: str, sequence: int, outcome: str, operation: str = "artifact", frame: str = "DATA", next_value: int = 0, window: int = 0, connection: int = 1) -> dict:
        return {
            "schema": "pbns-recovery-evaluation-v1", "case": case,
            "connection": connection, "operation": operation, "frame": frame,
            "sequence": sequence, "next": next_value, "window": window,
            "fault": fault, "outcome": outcome,
        }

    def _manifest_event(self, case: str, fault: str) -> dict:
        return self._event(case, fault, 0, "sent", "manifest", "RESPONSE")

    def _artifact_bytes(self, case: str) -> bytes:
        if case == "forged-digest":
            return b"D" * (9 * CHUNK_BYTES + 1)
        if case == "forged-chunk":
            return b"C" * (2 * CHUNK_BYTES)
        if case == "gateway-interruption":
            return b"I" * (8 * CHUNK_BYTES)
        return ARTIFACT_BYTES

    def _events(self, case: str, fault: str, size: int, restart: bool = False) -> list[dict]:
        events = [self._manifest_event(case, fault)]
        if restart:
            return [*events, self._event(case, fault, 0, "sent", connection=2)]
        if fault == "interrupt-after-data-7":
            return [*events, *[self._event(case, fault, sequence, "interrupt-ready" if sequence == 7 else "sent", connection=2) for sequence in range(8)]]
        if fault == "chunk-sequence":
            return [*events, self._event(case, fault, 0, "sent", connection=2), self._event(case, fault, 2, "injected", connection=2)]
        chunks = (size + CHUNK_BYTES - 1) // CHUNK_BYTES
        for sequence in range(chunks):
            events.append(self._event(case, fault, sequence, "injected" if sequence == 0 else "sent", connection=2))
            if (sequence + 1) % 8 == 0:
                events.append(self._event(case, fault, 0, "accepted", frame="ACK", next_value=sequence + 1, window=8, connection=2))
        events.append(self._event(case, fault, chunks, "sent", frame="COMPLETE", connection=2))
        return events

    def _make_case(self, case: str) -> tuple[pathlib.Path, list[str]]:
        root = self.root / case
        if root.exists() or root.is_symlink():
            shutil.rmtree(root)
        root.mkdir(mode=0o700)
        artifact_data = self._artifact_bytes(case)
        lines = self._lines(case, len(artifact_data))
        serial = self._private_file(root, "serial.log", ("\r\n".join(lines) + "\r\n").encode())
        before = self._private_file(root, "nv-before.bin", (5).to_bytes(8, "big"))
        after = self._private_file(root, "nv-after.bin", (7 if case == "signed-trusted" else 5).to_bytes(8, "big"))
        disk_before = self._private_file(root, "disk-before.sha256", (DIGEST + "\n").encode())
        disk_after = self._private_file(root, "disk-after.sha256", (DIGEST + "\n").encode())
        arguments = [
            "case", "--case", case, "--case-root", str(root), "--serial", str(serial),
            "--nv-before", str(before), "--nv-after", str(after), "--disk-before", str(disk_before),
            "--disk-after", str(disk_after),
        ]
        if case in ARTIFACT_CASES:
            metadata = {"artifact_sha256": hashlib.sha256(artifact_data).hexdigest(), "artifact_size": len(artifact_data), "version": 5 if case == "downgrade" else 7}
            artifact = self._private_file(root, "artifact-publication.json", (json.dumps(metadata) + "\n").encode())
            artifact_bytes = self._private_file(root, "artifact.efi", artifact_data)
            arguments.extend(("--artifact-metadata", str(artifact), "--artifact", str(artifact_bytes)))
        if case == "gateway-interruption":
            events = self._events(case, "interrupt-after-data-7", len(artifact_data))
            event_path = self._private_file(root, "events.jsonl", ("\n".join(json.dumps(item, separators=(",", ":")) for item in events) + "\n").encode())
            restart_events = self._events(case, "interrupt-after-data-7", len(artifact_data), restart=True)
            restart = self._private_file(root, "events-restart.jsonl", ("\n".join(json.dumps(item, separators=(",", ":")) for item in restart_events) + "\n").encode())
            restart_serial = self._private_file(root, "serial-restart.log", ("\r\n".join(lines) + "\r\n").encode())
            arguments.extend(("--events", str(event_path), "--events-restart", str(restart), "--serial-restart", str(restart_serial)))
        elif case == "forged-digest":
            events = self._events(case, "artifact-digest-mismatch", len(artifact_data))
            event_path = self._private_file(root, "events.jsonl", ("\n".join(json.dumps(item, separators=(",", ":")) for item in events) + "\n").encode())
            arguments.extend(("--events", str(event_path)))
        elif case == "forged-chunk":
            events = self._events(case, "chunk-sequence", len(artifact_data))
            event_path = self._private_file(root, "events.jsonl", ("\n".join(json.dumps(item, separators=(",", ":")) for item in events) + "\n").encode())
            arguments.extend(("--events", str(event_path)))
        return root, arguments

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.tool), *arguments], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_all_closed_cases_create_private_passed_summaries(self) -> None:
        for case in CASES:
            with self.subTest(case=case):
                root, arguments = self._make_case(case)
                completed = self._run(arguments)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                summary = root / "recovery-matrix-summary.json"
                self.assertEqual(completed.stdout, f"{summary}\n")
                self.assertEqual(summary.stat().st_mode & 0o777, 0o600)
                value = json.loads(summary.read_text())
                self.assertEqual(value["status"], "passed")
                self.assertEqual(value["case"], case)

    def test_failure_chronology_requires_cleanup_then_failed_state_then_failure(self) -> None:
        for case in ("unsigned-untrusted", "truncated", "downgrade"):
            with self.subTest(case=case):
                root, arguments = self._make_case(case)
                lines = self._lines(case)
                state = lines.index("PBNS RECOVERY STATE 9")
                failure = next(index for index, line in enumerate(lines) if "PBNS RECOVERY FAILED" in line)
                lines[state], lines[failure] = lines[failure], lines[state]
                self._private_file(root, "serial.log", ("\r\n".join(lines) + "\r\n").encode())
                self.assertNotEqual(self._run(arguments).returncode, 0)
        root, arguments = self._make_case("forged-manifest")
        lines = self._lines("forged-manifest")
        failed_state = lines.index("PBNS RECOVERY STATE 9")
        lines[failed_state:failed_state] = [
            "PBNS RECOVERY FREE BEGIN size=123", "PBNS RECOVERY FREE PASS"
        ]
        self._private_file(root, "serial.log", ("\r\n".join(lines) + "\r\n").encode())
        self.assertNotEqual(self._run(arguments).returncode, 0)

    def test_each_case_fails_closed_on_its_evidence_mutation(self) -> None:
        mutations = {
            "signed-trusted": lambda root, args: (root / "serial.log").write_text("\n".join(self._lines("signed-trusted")[1:])),
            "unsigned-untrusted": lambda root, args: (root / "serial.log").write_text("\n".join([self._lines("unsigned-untrusted")[0], self._lines("unsigned-untrusted")[2], *self._lines("unsigned-untrusted")[1:2], *self._lines("unsigned-untrusted")[3:]])),
            "truncated": lambda root, args: (root / "nv-after.bin").write_bytes((6).to_bytes(8, "big")),
            "gateway-interruption": lambda root, args: (root / "events-restart.jsonl").write_text(json.dumps(self._event("gateway-interruption", "interrupt-after-data-7", 0, "sent", connection=1)) + "\n"),
            "forged-manifest": lambda root, args: (root / "disk-after.sha256").write_text("b" + DIGEST[1:] + "\n"),
            "forged-digest": lambda root, args: (root / "events.jsonl").write_text(json.dumps(self._event("forged-digest", "chunk-sequence", 0, "injected")) + "\n"),
            "forged-chunk": lambda root, args: (root / "serial.log").write_text("\n".join(self._lines("forged-chunk") + ["PBNS RECOVERY STATE 4"])),
            "downgrade": lambda root, args: (root / "serial.log").write_text("\n".join(self._lines("downgrade") + ["private key material"])),
            "normal-launcher": lambda root, args: self._private_file(root, "events.jsonl", b"{}\n"),
            "pico-absent": lambda root, args: self._private_file(root, "artifact-publication.json", b"{}\n"),
        }
        for case, mutate in mutations.items():
            with self.subTest(case=case):
                root, arguments = self._make_case(case)
                mutate(root, arguments)
                for path in root.iterdir():
                    if path.is_file():
                        path.chmod(0o600)
                completed = self._run(arguments)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, "")
                self.assertFalse((root / "recovery-matrix-summary.json").exists())

    def test_evaluation_events_require_separate_manifest_and_artifact_connections(self) -> None:
        root, arguments = self._make_case("forged-digest")
        events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
        # The old parent-only ordinal check accepted this complete same-
        # connection trace; the validator must require every artifact event to
        # use the second connection.
        for event in events[1:]:
            event["connection"] = 1
        self._private_file(root, "events.jsonl", ("\n".join(json.dumps(item, separators=(",", ":")) for item in events) + "\n").encode())
        self.assertNotEqual(self._run(arguments).returncode, 0)

        root, arguments = self._make_case("gateway-interruption")
        (root / "serial-restart.log").unlink()
        self.assertNotEqual(self._run(arguments).returncode, 0)

    def test_rejects_unexpected_events_and_unsafe_private_evidence(self) -> None:
        root, arguments = self._make_case("unsigned-untrusted")
        self._private_file(root, "events.jsonl", b"{}\n")
        self.assertNotEqual(self._run(arguments).returncode, 0)
        (root / "events.jsonl").unlink()
        (root / "serial.log").chmod(0o644)
        self.assertNotEqual(self._run(arguments).returncode, 0)

    def test_audits_only_exact_immutable_repository_metadata(self) -> None:
        root, arguments = self._make_case("unsigned-untrusted")
        metadata = self._immutable_repository_metadata(root)
        completed = self._run(arguments)
        self.assertEqual(completed.returncode, 0, completed.stderr)

        mutations = {
            "mutable-metadata": lambda path, case_root: path.chmod(0o600),
            "metadata-secret": lambda path, case_root: (path.chmod(0o600), path.write_text("private key material"), path.chmod(0o444)),
            "metadata-symlink": lambda path, case_root: (path.unlink(), path.symlink_to(case_root / "serial.log")),
            "malformed-digest": lambda path, case_root: self._immutable_repository_metadata(case_root, "A" * 64),
            "nested-metadata": lambda path, case_root: (case_root / "repository" / "metadata" / "extra").mkdir(mode=0o700),
            "read-only-retained-text": lambda path, case_root: (self._private_file(case_root, "read-only.json", b"{}\n"), (case_root / "read-only.json").chmod(0o444)),
            "unexpected-events": lambda path, case_root: self._private_file(case_root, "events.jsonl", b"{}\n"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                root, arguments = self._make_case("unsigned-untrusted")
                metadata = self._immutable_repository_metadata(root)
                mutate(metadata, root)
                completed = self._run(arguments)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, "")
                self.assertFalse((root / "recovery-matrix-summary.json").exists())

    def test_retained_text_empty_policy_allows_only_case_root_gateway_log(self) -> None:
        accepted_root, accepted_arguments = self._make_case("unsigned-untrusted")
        self._immutable_repository_metadata(accepted_root)
        self._private_file(accepted_root, "gateway.log", b"")
        accepted = self._run(accepted_arguments)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertTrue((accepted_root / "recovery-matrix-summary.json").is_file())

        rejected = {
            "empty-ordinary-json": lambda root: self._private_file(root, "retained.json", b""),
            "empty-ordinary-log": lambda root: self._private_file(root, "retained.log", b""),
            "empty-immutable-metadata": lambda root: self._immutable_repository_metadata(root, data=b""),
            "nested-gateway-log": lambda root: (
                (root / "nested").mkdir(mode=0o700),
                self._private_file(root / "nested", "gateway.log", b""),
            ),
            "renamed-gateway-log": lambda root: self._private_file(root, "gateway-output.log", b""),
        }
        for name, mutate in rejected.items():
            with self.subTest(name=name):
                root, arguments = self._make_case("unsigned-untrusted")
                mutate(root)
                completed = self._run(arguments)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, "")
                self.assertFalse((root / "recovery-matrix-summary.json").exists())

    def test_result_is_private_create_exclusive_and_recomputed(self) -> None:
        state = self.root / "state"
        cases = state / "cases"
        cases.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        for case in CASES:
            root, arguments = self._make_case(case)
            self.assertEqual(self._run(arguments).returncode, 0)
            shutil.move(str(root), str(cases / case))
        base = state / "recovery-base"
        base.mkdir(mode=0o700)
        self._private_file(base, "OVMF_CODE.fd", b"copied code")
        self._private_file(base, "OVMF_VARS.fd", b"copied variables")
        output = state / "candidate.json"
        result = self._run(["result", "--state-root", str(state), "--output", str(output)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{output}\n")
        public = json.loads(output.read_text())
        self.assertEqual(set(public["artifacts"]), {"signed-trusted", "unsigned-untrusted", "truncated"})
        self.assertEqual(set(public["cases"]), set(CASES))
        self.assertEqual(public["checks"]["physical-recovery"], "not-run")
        self.assertNotEqual(self._run(["result", "--state-root", str(state), "--output", str(output)]).returncode, 0)
        verified = self._run(["verify-result", "--state-root", str(state), "--result", str(output)])
        self.assertEqual(verified.returncode, 0, verified.stderr)
        public["platform"] = "forged"
        output.write_text(json.dumps(public) + "\n")
        output.chmod(0o600)
        self.assertNotEqual(self._run(["verify-result", "--state-root", str(state), "--result", str(output)]).returncode, 0)
        public["limitations"] = [{"malformed": "object"}]
        output.write_text(json.dumps(public) + "\n")
        output.chmod(0o600)
        malformed = self._run(["verify-result", "--state-root", str(state), "--result", str(output)])
        self.assertNotEqual(malformed.returncode, 0)
        self.assertEqual(malformed.stdout, "")

    def test_rejects_exact_nv_artifact_and_retained_log_false_passes(self) -> None:
        for case in CASES:
            if case == "signed-trusted":
                continue
            with self.subTest(case=case):
                root, arguments = self._make_case(case)
                (root / "nv-before.bin").write_bytes((4).to_bytes(8, "big"))
                (root / "nv-after.bin").write_bytes((4).to_bytes(8, "big"))
                (root / "nv-before.bin").chmod(0o600)
                (root / "nv-after.bin").chmod(0o600)
                self.assertNotEqual(self._run(arguments).returncode, 0)
        for name, content in {
            "artifact-bytes": None,
            "metadata-version": json.dumps({"artifact_sha256": DIGEST, "artifact_size": 123, "version": 6}),
            "metadata-duplicate": '{"artifact_sha256":"' + DIGEST + '","artifact_sha256":"' + DIGEST + '","artifact_size":123,"version":7}',
            "serial-size": None,
            "gateway-ticket": "TPM ticket=secret",
            "gateway-scalar": "private scalar=secret",
            "gateway-tls": "TLS plaintext transcript=secret",
        }.items():
            with self.subTest(name=name):
                root, arguments = self._make_case("unsigned-untrusted")
                if name == "artifact-bytes":
                    (root / "artifact.efi").write_bytes(b"B" + ARTIFACT_BYTES[1:])
                    (root / "artifact.efi").chmod(0o600)
                elif name.startswith("metadata"):
                    (root / "artifact-publication.json").write_text(content)
                    (root / "artifact-publication.json").chmod(0o600)
                elif name == "serial-size":
                    (root / "serial.log").write_text("\n".join(self._lines("unsigned-untrusted")).replace("size=123", "size=122"))
                    (root / "serial.log").chmod(0o600)
                else:
                    self._private_file(root, "gateway.log", content.encode())
                self.assertNotEqual(self._run(arguments).returncode, 0)

    def test_rejects_event_order_and_private_reader_mutations(self) -> None:
        root, arguments = self._make_case("forged-digest")
        event_lines = (root / "events.jsonl").read_text().splitlines()
        (root / "events.jsonl").write_text("\n".join([event_lines[1], event_lines[0], *event_lines[2:]]) + "\n")
        (root / "events.jsonl").chmod(0o600)
        self.assertNotEqual(self._run(arguments).returncode, 0)
        for name, mutate in {
            "symlink": lambda root: ((root / "serial.log").unlink(), (root / "serial.log").symlink_to(root / "disk-before.sha256")),
            "mode": lambda root: (root / "serial.log").chmod(0o644),
            "bounds": lambda root: self._private_file(root, "serial.log", b"x" * (self.validator.MAX_LOG + 1)),
            "utf8": lambda root: self._private_file(root, "events.jsonl", b"\xff\n"),
        }.items():
            with self.subTest(name=name):
                root, arguments = self._make_case("forged-digest")
                mutate(root)
                self.assertNotEqual(self._run(arguments).returncode, 0)

    def test_rejects_exact_chunk_ack_and_private_log_profiles(self) -> None:
        root, arguments = self._make_case("forged-digest")
        events = (root / "events.jsonl").read_text().splitlines()
        ack_index = next(index for index, line in enumerate(events) if '"frame":"ACK"' in line)
        (root / "events.jsonl").write_text("\n".join([events[0], events[ack_index], *events[1:ack_index], *events[ack_index + 1:]]) + "\n")
        (root / "events.jsonl").chmod(0o600)
        self.assertNotEqual(self._run(arguments).returncode, 0)
        for case, mutate in {
            "forged-digest": lambda records: records[-1].update(sequence=999),
            "forged-chunk": lambda records: records[-1].update(sequence=1),
            "gateway-interruption": lambda records: records[-1].update(outcome="sent"),
        }.items():
            with self.subTest(fault=case):
                root, arguments = self._make_case(case)
                event_path = root / "events.jsonl"
                records = [json.loads(line) for line in event_path.read_text().splitlines()]
                mutate(records)
                event_path.write_text("\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n")
                event_path.chmod(0o600)
                self.assertNotEqual(self._run(arguments).returncode, 0)
        for case, size in (("forged-chunk", CHUNK_BYTES), ("gateway-interruption", 7 * CHUNK_BYTES)):
            with self.subTest(case=case):
                root, arguments = self._make_case(case)
                bytes_value = b"X" * size
                self._private_file(root, "artifact.efi", bytes_value)
                self._private_file(root, "artifact-publication.json", (json.dumps({"artifact_sha256": hashlib.sha256(bytes_value).hexdigest(), "artifact_size": size, "version": 7}) + "\n").encode())
                self.assertNotEqual(self._run(arguments).returncode, 0)
        root, arguments = self._make_case("unsigned-untrusted")
        private = root / "private"
        private.mkdir(mode=0o700)
        self._private_file(private, "key.pem", b"private key bytes are deliberately not scanned")
        self._private_file(private, "leak.LOG", b"TLS plaintext transcript=secret")
        self.assertNotEqual(self._run(arguments).returncode, 0)
        root, arguments = self._make_case("forged-digest")
        serial = root / "serial.log"
        serial.write_text(serial.read_text().replace(f"size={9 * CHUNK_BYTES + 1}", "size=123"))
        serial.chmod(0o600)
        self.assertNotEqual(self._run(arguments).returncode, 0)

    def test_summary_root_descriptor_survives_deterministic_replacement(self) -> None:
        root, arguments = self._make_case("signed-trusted")
        self.assertEqual(self._run(arguments).returncode, 0)
        replacement = self.root / "replacement"
        shutil.copytree(root, replacement)
        replacement.chmod(0o700)
        original_utf8 = self.validator._utf8
        swapped = False

        def replace_after_summary(path, *args):
            nonlocal swapped
            value = original_utf8(path, *args)
            if path.name == self.validator.SUMMARY_NAME and not swapped:
                swapped = True
                root.rename(self.root / "original-root")
                replacement.rename(root)
            return value

        self.validator._utf8 = replace_after_summary
        try:
            derived, _ = self.validator._summary(root, "signed-trusted")
        finally:
            self.validator._utf8 = original_utf8
        self.assertTrue(swapped)
        self.assertEqual(derived["case"], "signed-trusted")

    def test_summary_and_same_size_artifact_tampering_are_recomputed(self) -> None:
        state = self.root / "state-tamper"
        cases = state / "cases"
        cases.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        for case in CASES:
            root, arguments = self._make_case(case)
            self.assertEqual(self._run(arguments).returncode, 0)
            shutil.move(str(root), str(cases / case))
        base = state / "recovery-base"
        base.mkdir(mode=0o700)
        self._private_file(base, "OVMF_CODE.fd", b"copied code")
        self._private_file(base, "OVMF_VARS.fd", b"copied variables")
        output = state / "candidate.json"
        self.assertEqual(self._run(["result", "--state-root", str(state), "--output", str(output)]).returncode, 0)
        summary = cases / "signed-trusted" / "recovery-matrix-summary.json"
        changed = json.loads(summary.read_text())
        changed["artifact_size"] += 1
        summary.write_text(json.dumps(changed) + "\n")
        summary.chmod(0o600)
        self.assertNotEqual(self._run(["verify-result", "--state-root", str(state), "--result", str(output)]).returncode, 0)
        changed["artifact_size"] -= 1
        summary.write_text(json.dumps(changed) + "\n")
        summary.chmod(0o600)
        artifact = cases / "signed-trusted" / "artifact.efi"
        artifact.write_bytes(b"B" + ARTIFACT_BYTES[1:])
        artifact.chmod(0o600)
        self.assertNotEqual(self._run(["verify-result", "--state-root", str(state), "--result", str(output)]).returncode, 0)

    def test_schema_equivalent_validates_policy_and_complete_candidate(self) -> None:
        policy = json.loads((self.pbns_root / "eval" / "results" / "recovery-uki-policy-20260802-qemu.json").read_text())
        self.assertTrue(self.validator.validate_schema_equivalent(policy))
        invalid_policy = dict(policy)
        invalid_policy["checks"] = dict(policy["checks"], launcher="invalid")
        self.assertFalse(self.validator.validate_schema_equivalent(invalid_policy))
        schema = json.loads((self.pbns_root / "eval" / "schema" / "recovery-result.schema.json").read_text())
        state = self.root / "state-schema"
        cases = state / "cases"
        cases.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        for case in CASES:
            root, arguments = self._make_case(case)
            self.assertEqual(self._run(arguments).returncode, 0)
            shutil.move(str(root), str(cases / case))
        base = state / "recovery-base"
        base.mkdir(mode=0o700)
        self._private_file(base, "OVMF_CODE.fd", b"code")
        self._private_file(base, "OVMF_VARS.fd", b"variables")
        candidate = self.validator._candidate(state, "2026-08-09T00:00:00Z")
        self.assertTrue(self.validator.validate_schema_equivalent(candidate))
        invalid_candidate = dict(candidate)
        invalid_candidate["artifacts"] = dict(candidate["artifacts"])
        invalid_candidate["artifacts"]["signed-trusted"] = {"sha256": "bad", "size": 0}
        self.assertFalse(self.validator.validate_schema_equivalent(invalid_candidate))
        invalid_candidate["limitations"] = {"not": "an array"}
        self.assertFalse(self.validator.validate_schema_equivalent(invalid_candidate))
        invalid_candidate = dict(candidate, nv_version_before=True)
        self.assertFalse(self.validator.validate_schema_equivalent(invalid_candidate))
        altered = self.root / "altered-schema.json"
        schema["properties"]["platform"]["maxLength"] = 1
        altered.write_text(json.dumps(schema))
        original_path = self.validator.SCHEMA_PATH
        self.validator.SCHEMA_PATH = altered
        try:
            self.assertFalse(self.validator.validate_schema_equivalent(policy))
            self.assertFalse(self.validator.validate_schema_equivalent(candidate))
        finally:
            self.validator.SCHEMA_PATH = original_path

    def test_schema_numeric_and_rfc3339_semantics(self) -> None:
        validate = self.validator._validate_schema
        integer = {"type": "integer"}
        number = {"type": "number"}
        self.assertTrue(validate(1.0, integer, integer))
        self.assertTrue(validate(-0.0, integer, integer))
        self.assertFalse(validate(True, integer, integer))
        self.assertFalse(validate(False, number, number))

        self.assertFalse(validate(1.0, {"oneOf": [integer, number]}, {}))
        self.assertTrue(validate(1.5, {"oneOf": [integer, number]}, {}))
        self.assertFalse(validate(1, {"oneOf": [{"const": 1}, {"const": 1.0}]}, {}))
        self.assertTrue(validate({"value": [1.0]}, {"const": {"value": [1]}}, {}))
        self.assertTrue(validate(1.0, {"enum": [1]}, {}))
        self.assertTrue(validate(-0.0, {"const": 0}, {}))
        self.assertFalse(validate(True, {"const": 1}, {}))
        self.assertFalse(validate(True, {"enum": [1]}, {}))
        self.assertFalse(validate([1, 1.0], {"type": "array", "uniqueItems": True}, {}))
        self.assertFalse(validate([{"value": [1]}, {"value": [1.0]}], {"type": "array", "uniqueItems": True}, {}))
        self.assertTrue(validate([True, 1], {"type": "array", "uniqueItems": True}, {}))

        loaded_schema = self.validator._committed_schema()
        date_time = loaded_schema["properties"]["recorded_utc"]
        for value in ("2024-02-29T23:59:59Z", "2024-02-29t00:00:00z", "2024-02-29T00:00:00.123+05:30"):
            with self.subTest(valid=value):
                self.assertTrue(validate(value, date_time, loaded_schema))
        for value in ("2024-02-29X00:00:00Z", "2024-02-29 00:00:00Z", "2024-02-29T00:00:00", "2023-02-29T00:00:00Z", "2024-01-01T24:00:00Z", "2024-01-01T00:60:00Z", "2024-01-01T00:00:61Z", "2024-01-01T00:00:00+24:00", "2024-01-01T00:00:00+01:60", "2024-01-01T00:00:00.", "٢٠٢٤-02-29T00:00:00Z", "２０２４-02-29T00:00:00Z", "2024-02-29T00:00:00.١Z"):
            with self.subTest(invalid=value):
                self.assertFalse(validate(value, date_time, loaded_schema))

        one_of_with_siblings = {
            "oneOf": [{"type": "integer"}, {"type": "null"}],
            "type": "integer",
            "minimum": 5,
        }
        self.assertTrue(validate(5, one_of_with_siblings, loaded_schema))
        self.assertFalse(validate(4, one_of_with_siblings, loaded_schema))
        self.assertFalse(validate(None, one_of_with_siblings, loaded_schema))


if __name__ == "__main__":
    unittest.main()
