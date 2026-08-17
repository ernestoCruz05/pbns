import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


STAGES = (
    "privacy",
    "quote-binding",
    "eventlog-replay",
    "baseline",
    "receipt",
    "ciphertext-capture",
    "swtpm",
    "physical-full-2",
)
CAPABILITIES = (
    "tpm2",
    "p256-identity",
    "ecc-p256-ak-quote",
    "makecredential-activatecredential",
    "sha256-pcr-bank",
    "tcg-event-log",
    "approved-rng",
)


class AttestationGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns = pathlib.Path(__file__).parents[2]
        self.checker = self.pbns / "integration" / "security" / "check-ciphertext-capture.py"
        self.verifier = self.pbns / "tools" / "verify-attestation.sh"
        self.schema = self.pbns / "eval" / "schema" / "attestation-result.schema.json"

    def _write_private(self, path: pathlib.Path, data: bytes) -> None:
        path.write_bytes(data)
        path.chmod(0o600)

    def _capture_fixture(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        root.chmod(0o700)
        vector = self.pbns / "tests" / "vectors" / "cose-encrypt-v1" / "tcose-to-cosec.cbor"
        envelope = root / "envelope.cbor"
        self._write_private(envelope, vector.read_bytes())
        now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        captures = []
        for boundary in ("usb", "pico-raw-tcp", "tls-records", "dispatcher", "production-logs"):
            path = root / f"{boundary}.bin"
            data = b"opaque-runtime-capture:" + boundary.encode()
            if boundary == "dispatcher":
                data += b"\x00" + envelope.read_bytes() + b"\x00"
            self._write_private(path, data)
            captures.append({
                "boundary": boundary,
                "path": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "capturedAt": now,
                "mediaType": "application/octet-stream",
            })
        manifest = root / "captures.json"
        self._write_private(manifest, (json.dumps({"schemaVersion": 1, "captures": captures}) + "\n").encode())
        oracle = root / "oracle.json"
        self._write_private(oracle, (json.dumps({
            "schemaVersion": 1,
            "encryptedEnvelope": {"path": envelope.name, "sha256": hashlib.sha256(envelope.read_bytes()).hexdigest()},
            "forbiddenHex": {
                "inventory": [b"PBNS-INVENTORY-UNIQUE-SENTINEL".hex()],
                "eventLog": [b"event-log-binary-fragment".hex()],
                "activatedCredential": [b"activated-credential".hex()],
                "rawIdentifiers": [b"RAW-SERIAL-SENTINEL".hex()],
            },
        }) + "\n").encode())
        return manifest, oracle

    def test_ciphertext_checker_requires_every_fresh_boundary_and_real_cose(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest, oracle = self._capture_fixture(root)
            valid = subprocess.run([str(self.checker), "--capture-manifest", str(manifest), "--oracle", str(oracle)], text=True, capture_output=True, check=False)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn("CIPHERTEXT CAPTURE PASS", valid.stdout)

            document = json.loads(manifest.read_text())
            document["captures"] = document["captures"][:-1]
            self._write_private(manifest, (json.dumps(document) + "\n").encode())
            missing = subprocess.run([str(self.checker), "--capture-manifest", str(manifest), "--oracle", str(oracle)], text=True, capture_output=True, check=False)
            self.assertNotEqual(missing.returncode, 0)
            self.assertNotIn("PASS", missing.stdout)

    def test_ciphertext_checker_rejects_plaintext_at_each_boundary_and_encoding_substitute(self) -> None:
        for target in ("usb", "pico-raw-tcp", "tls-records", "dispatcher", "production-logs"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                manifest, oracle = self._capture_fixture(root)
                document = json.loads(manifest.read_text())
                entry = next(item for item in document["captures"] if item["boundary"] == target)
                path = root / entry["path"]
                data = path.read_bytes() + b"PBNS-INVENTORY-UNIQUE-SENTINEL"
                self._write_private(path, data)
                entry["sha256"] = hashlib.sha256(data).hexdigest()
                entry["size"] = len(data)
                self._write_private(manifest, (json.dumps(document) + "\n").encode())
                rejected = subprocess.run([str(self.checker), "--capture-manifest", str(manifest), "--oracle", str(oracle)], text=True, capture_output=True, check=False)
                self.assertNotEqual(rejected.returncode, 0)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest, oracle = self._capture_fixture(root)
            envelope = root / "envelope.cbor"
            self._write_private(envelope, b"base64-is-not-ciphertext")
            oracle_doc = json.loads(oracle.read_text())
            oracle_doc["encryptedEnvelope"]["sha256"] = hashlib.sha256(envelope.read_bytes()).hexdigest()
            self._write_private(oracle, (json.dumps(oracle_doc) + "\n").encode())
            document = json.loads(manifest.read_text())
            dispatcher = next(item for item in document["captures"] if item["boundary"] == "dispatcher")
            path = root / dispatcher["path"]
            self._write_private(path, b"base64-is-not-ciphertext")
            dispatcher["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            dispatcher["size"] = len(path.read_bytes())
            self._write_private(manifest, (json.dumps(document) + "\n").encode())
            rejected = subprocess.run([str(self.checker), "--capture-manifest", str(manifest), "--oracle", str(oracle)], text=True, capture_output=True, check=False)
            self.assertNotEqual(rejected.returncode, 0)

    def _stage(self, root: pathlib.Path, name: str, status: str) -> dict:
        if status == "not-run":
            return {"status": status, "command": "", "startedAt": None, "finishedAt": None, "evidence": []}
        artifact = root / f"{name}-{os.urandom(4).hex()}.txt"
        data = f"runtime evidence {name} {os.urandom(16).hex()}\n".encode()
        self._write_private(artifact, data)
        now = datetime.datetime.now(datetime.timezone.utc)
        return {
            "status": status,
            "command": f"runtime-{name}",
            "startedAt": (now - datetime.timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "finishedAt": now.isoformat().replace("+00:00", "Z"),
            "evidence": [{"path": artifact.name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "provenance": "live-runtime"}],
        }

    def _manifest(self, root: pathlib.Path, name: str, kind: str, passed: set[str], platform_class: str | None = None, fingerprint: str | None = None) -> pathlib.Path:
        now = datetime.datetime.now(datetime.timezone.utc)
        platform = None
        if kind == "physical":
            platform = {
                "class": platform_class,
                "fingerprintDigest": fingerprint,
                "capabilities": {capability: True for capability in CAPABILITIES},
                "restorationProof": True,
            }
        document = {
            "schemaVersion": 1,
            "kind": kind,
            "runId": hashlib.sha256(os.urandom(32)).hexdigest(),
            "createdAt": now.isoformat().replace("+00:00", "Z"),
            "expiresAt": (now + datetime.timedelta(hours=6)).isoformat().replace("+00:00", "Z"),
            "platform": platform,
            "stages": {stage: self._stage(root, stage, "passed" if stage in passed else "not-run") for stage in STAGES},
        }
        path = root / name
        self._write_private(path, (json.dumps(document, sort_keys=True) + "\n").encode())
        return path

    def test_gate_requires_runtime_stage_evidence_and_two_distinct_capable_platforms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            self._manifest(root, "qemu.json", "qemu", set(STAGES) - {"physical-full-2"})
            self._manifest(root, "physical-intel.json", "physical", {"physical-full-2"}, "intel-ptt", "1" * 64)
            self._manifest(root, "physical-amd.json", "physical", {"physical-full-2"}, "amd-ftpm", "2" * 64)
            passed = subprocess.run([str(self.verifier), "--require-hardware=2", "--evidence-dir", str(root)], text=True, capture_output=True, check=False)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertIn("ATTESTATION PASS", passed.stdout)
            self.assertIn("[PASS] swtpm-valid-and-mutations", passed.stdout)

            amd = json.loads((root / "physical-amd.json").read_text())
            amd["platform"]["fingerprintDigest"] = "1" * 64
            self._write_private(root / "physical-amd.json", (json.dumps(amd) + "\n").encode())
            duplicate = subprocess.run([str(self.verifier), "--require-hardware=2", "--evidence-dir", str(root)], text=True, capture_output=True, check=False)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertNotIn("ATTESTATION PASS", duplicate.stdout)

    def test_gate_rejects_stale_symlinked_or_prewritten_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            qemu = self._manifest(root, "qemu.json", "qemu", set(STAGES) - {"physical-full-2"})
            document = json.loads(qemu.read_text())
            old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
            document["createdAt"] = old.isoformat().replace("+00:00", "Z")
            document["expiresAt"] = (old + datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
            self._write_private(qemu, (json.dumps(document) + "\n").encode())
            stale = subprocess.run([str(self.verifier), "--require-hardware=0", "--evidence-dir", str(root)], text=True, capture_output=True, check=False)
            self.assertNotEqual(stale.returncode, 0)
            artifact = next(root.glob("privacy-*.txt"))
            victim = root / "victim"
            victim.write_bytes(artifact.read_bytes())
            victim.chmod(0o600)
            artifact.unlink()
            artifact.symlink_to(victim)
            linked = subprocess.run([str(self.verifier), "--require-hardware=0", "--evidence-dir", str(root)], text=True, capture_output=True, check=False)
            self.assertNotEqual(linked.returncode, 0)


    def test_schema_is_strict_and_accepts_only_named_stage_statuses(self) -> None:
        schema = json.loads(self.schema.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        stages = schema["properties"]["stages"]
        self.assertEqual(set(stages["required"]), set(STAGES))
        status = schema["$defs"]["stage"]["properties"]["status"]["enum"]
        self.assertEqual(status, ["passed", "failed", "not-run"])


if __name__ == "__main__":
    unittest.main()
