#!/usr/bin/env python3
"""PBNS Adversarial Attack & Fault Injection Suite Runner.

Executes the compiled C core test suites covering the 22 evaluated security
attack and fault injection specifications, recording execution timing, binary
hashes, exit status, and suite-level verification evidence.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PBNS_ROOT = SCRIPT_DIR.parent.parent
EVAL_DIR = PBNS_ROOT / "eval"
RAW_DIR = EVAL_DIR / "raw" / "adversarial"
BUILD_DIR = PBNS_ROOT / "build" / "dev"

ATTACK_SPECIFICATIONS = [
    # Tier 1: Hostile Bearer and Network Path (6 cases)
    {
        "id": "A-TLS-01",
        "tier": "Tier 1: Hostile Bearer",
        "layer": "TLS",
        "threat": "Rogue gateway / MITM attempting TLS impersonation with unpinned certificate",
        "description": "Certificate with non-pinned SPKI",
        "binary": "pbns-test-spki-pin",
        "expected_rejection": "PBNS_ERR_AUTHENTICATION",
    },
    {
        "id": "A-TLS-02",
        "tier": "Tier 1: Hostile Bearer",
        "layer": "TLS",
        "threat": "Adversary issues valid certificate with mismatched Subject Alternative Name",
        "description": "Certificate subjectAltName (SAN) mismatch",
        "binary": "pbns-test-tls-policy",
        "expected_rejection": "PBNS_ERR_AUTHENTICATION",
    },
    {
        "id": "A-TLS-03",
        "tier": "Tier 1: Hostile Bearer",
        "layer": "TLS",
        "threat": "Adversary attempts cipher downgrade or non-AEAD suite negotiation",
        "description": "Adversary offers unsupported or weak cipher suite",
        "binary": "pbns-test-tls-policy",
        "expected_rejection": "PBNS_ERR_CRYPTO",
    },
    {
        "id": "A-PATH-01",
        "tier": "Tier 1: Hostile Bearer",
        "layer": "Transport",
        "threat": "Untrusted USB bridge / network bearer mutates in-flight TLS ciphertext",
        "description": "Mutated TLS ciphertext on CDC bearer",
        "binary": "pbns-test-tls-transport",
        "expected_rejection": "PBNS_ERR_CRYPTO",
    },
    {
        "id": "A-PATH-02",
        "tier": "Tier 1: Hostile Bearer",
        "layer": "Transport",
        "threat": "Replay of previously recorded TLS handshake messages over USB",
        "description": "Replayed TLS handshake record",
        "binary": "pbns-test-tls-replay-endpoint",
        "expected_rejection": "PBNS_ERR_REPLAY",
    },
    {
        "id": "A-PATH-03",
        "tier": "Tier 1: Hostile Bearer",
        "layer": "Transport",
        "threat": "Adversary terminates USB or Wi-Fi link during streaming",
        "description": "Premature connection termination during streaming",
        "binary": "pbns-test-reconnect",
        "expected_rejection": "PBNS_ERR_TRANSPORT",
    },
    # Tier 2: Authenticated Endpoint, Backend, and Framing Faults (16 cases)
    {
        "id": "A-FRAME-01",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Framing",
        "threat": "Garbage bytes or corrupted framing synchronization preamble",
        "description": "Corrupted framing magic byte in record header",
        "binary": "pbns-test-frame",
        "expected_rejection": "PBNS_ERR_FORMAT",
    },
    {
        "id": "A-FRAME-02",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Framing",
        "threat": "Bitflips or transmission errors in encapsulated frame payload",
        "description": "CRC32C checksum mismatch in frame payload",
        "binary": "pbns-test-frame",
        "expected_rejection": "PBNS_ERR_CRC",
    },
    {
        "id": "A-FRAME-03",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Framing",
        "threat": "Oversized frame length field intended to trigger buffer overflow",
        "description": "Frame length exceeding allocated receiver buffer",
        "binary": "pbns-test-frame",
        "expected_rejection": "PBNS_ERR_LIMIT",
    },
    {
        "id": "A-FRAME-04",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Framing",
        "threat": "Premature 0x00 delimiter causing parser state desynchronization",
        "description": "Premature frame delimiter (truncated payload)",
        "binary": "pbns-test-frame",
        "expected_rejection": "PBNS_ERR_FORMAT",
    },
    {
        "id": "A-TIME-01",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Time",
        "threat": "Compromised or malicious time server returns forged signature",
        "description": "Forged ECDSA P-256 signature on time assertion",
        "binary": "pbns-test-trusted-time",
        "expected_rejection": "PBNS_ERR_AUTHENTICATION",
    },
    {
        "id": "A-TIME-02",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Time",
        "threat": "Replay of previous time assertion with stale nonce",
        "description": "Replay of previously signed time assertion",
        "binary": "pbns-test-trusted-time",
        "expected_rejection": "PBNS_ERR_REPLAY",
    },
    {
        "id": "A-TIME-03",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Time",
        "threat": "Time assertion asserting past timestamp violating monotonic progress",
        "description": "Time assertion violating monotonic progress",
        "binary": "pbns-test-trusted-time",
        "expected_rejection": "PBNS_ERR_STATE",
    },
    {
        "id": "A-REC-01",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Recovery",
        "threat": "Malicious gateway supplies forged COSE Sign1 recovery manifest",
        "description": "Forged signature on recovery manifest",
        "binary": "pbns-test-recovery-manifest",
        "expected_rejection": "PBNS_ERR_AUTHENTICATION",
    },
    {
        "id": "A-REC-02",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Recovery",
        "threat": "Corrupted or altered recovery kernel chunks streamed to host RAM",
        "description": "Streaming chunk payload SHA-256 digest mismatch",
        "binary": "pbns-test-recovery-stream",
        "expected_rejection": "PBNS_ERR_CRYPTO",
    },
    {
        "id": "A-REC-03",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Recovery",
        "threat": "Omission or reordering of recovery stream chunks",
        "description": "Out-of-order chunk sequence (skipping sequence gap)",
        "binary": "pbns-test-recovery-stream",
        "expected_rejection": "PBNS_ERR_SEQUENCE",
    },
    {
        "id": "A-REC-04",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Recovery",
        "threat": "Gateway attempts downgrade to older recovery UKI with known CVEs",
        "description": "Anti-rollback downgrade attempt (target version < NV)",
        "binary": "pbns-test-anti-rollback",
        "expected_rejection": "PBNS_ERR_STATE",
    },
    {
        "id": "A-REC-05",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Recovery",
        "threat": "Adversary streams correctly formed UKI signed by un-enrolled key",
        "description": "Unsigned or untrusted recovery UKI in memory",
        "binary": "pbns-test-recovery-assurance",
        "expected_rejection": "EFI_SECURITY_VIOLATION",
    },
    {
        "id": "A-ATT-01",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Attestation",
        "threat": "Adversary crafts synthetic TPM Quote with forged AK signature",
        "description": "Forged or corrupted TPM 2.0 Quote signature",
        "binary": "pbns-test-attestation-quote",
        "expected_rejection": "PBNS_ERR_AUTHENTICATION",
    },
    {
        "id": "A-ATT-02",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Attestation",
        "threat": "Adversary replays old TPM Quote to conceal modified host state",
        "description": "Replay of previous quote with stale nonce",
        "binary": "pbns-test-attestation-run",
        "expected_rejection": "PBNS_ERR_REPLAY",
    },
    {
        "id": "A-ATT-03",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Attestation",
        "threat": "Altered bootloader measurement in PCR 4 violating baseline",
        "description": "Controlled baseline mismatch (modified PCR 0/4/7)",
        "binary": "pbns-test-controlled-baseline",
        "expected_rejection": "PBNS_ERR_AUTHENTICATION",
    },
    {
        "id": "A-ATT-04",
        "tier": "Tier 2: Defense in Depth",
        "layer": "Attestation",
        "threat": "Adversary mutates COSE_Encrypt payload or recipient CEK structure",
        "description": "Mutated COSE_Encrypt ciphertext or AAD",
        "binary": "pbns-test-encrypt",
        "expected_rejection": "PBNS_ERR_CRYPTO",
    },
]


def get_command_for_binary(bin_name: str) -> list[str]:
    bin_path = BUILD_DIR / bin_name
    pki_dir = BUILD_DIR / "tls-test-pki"
    vectors_dir = PBNS_ROOT / "tests" / "vectors" / "tcg-event-log"

    if bin_name == "pbns-test-spki-pin":
        return [
            str(bin_path),
            str(pki_dir / "gateway-cert.der"),
            str(pki_dir / "gateway-reissued-cert.der"),
            str(pki_dir / "wrong-key-cert.der"),
            str(pki_dir / "rsa-cert.der"),
            str(pki_dir / "malformed-cert.der"),
        ]
    elif bin_name == "pbns-test-tls-policy":
        return [
            str(bin_path),
            str(pki_dir / "gateway-reissued-cert.der"),
            str(pki_dir / "ipv4-cert.der"),
            str(pki_dir / "ipv6-cert.der"),
            str(pki_dir / "wrong-san-cert.der"),
            str(pki_dir / "cn-only-cert.der"),
            str(pki_dir / "missing-ku-cert.der"),
            str(pki_dir / "wrong-ku-cert.der"),
            str(pki_dir / "missing-eku-cert.der"),
            str(pki_dir / "wrong-eku-cert.der"),
            str(pki_dir / "p384-cert.der"),
            str(pki_dir / "ca-true-cert.der"),
            str(pki_dir / "missing-basic-cert.der"),
            str(pki_dir / "noncritical-basic-cert.der"),
            str(pki_dir / "corrupt-signature-cert.der"),
            str(pki_dir / "wrong-key-cert.der"),
            str(pki_dir / "rsa-cert.der"),
            str(pki_dir / "malformed-cert.der"),
        ]
    elif bin_name == "pbns-test-tls-transport":
        return [
            str(bin_path),
            str(pki_dir / "gateway-reissued-cert.der"),
            str(pki_dir / "gateway-key.der"),
        ]
    elif bin_name in ("pbns-test-enrollment-baseline", "pbns-test-measured-boot-selection"):
        return [str(bin_path), str(vectors_dir)]
    else:
        return [str(bin_path)]


def run_unique_suite_binaries() -> dict[str, dict]:
    unique_binaries = sorted({spec["binary"] for spec in ATTACK_SPECIFICATIONS})
    suite_results = {}

    for bin_name in unique_binaries:
        cmd = get_command_for_binary(bin_name)
        bin_path = pathlib.Path(cmd[0])
        assert bin_path.is_file(), f"Compiled test binary not found: {bin_path}. Run build first."

        bin_hash = hashlib.sha256(bin_path.read_bytes()).hexdigest()
        start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        t0 = time.perf_counter()

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(PBNS_ROOT),
            check=False,
        )
        duration_s = time.perf_counter() - t0
        end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        stdout_hash = hashlib.sha256(proc.stdout).hexdigest()

        assert proc.returncode == 0, f"Suite binary {bin_path.name} failed with status {proc.returncode}:\n{proc.stdout.decode('utf-8', errors='replace')}"

        suite_results[bin_name] = {
            "binary": bin_name,
            "command": " ".join([bin_path.name] + [pathlib.Path(a).name for a in cmd[1:]]),
            "binary_sha256": bin_hash,
            "stdout_sha256": stdout_hash,
            "started_at": start_iso,
            "ended_at": end_iso,
            "duration_ms": round(duration_s * 1000.0, 2),
            "exit_code": proc.returncode,
            "suite_passed": proc.returncode == 0,
        }
    return suite_results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PBNS Covering Test Suites for Evaluated Attack Specifications")
    parser.add_argument("--out-dir", type=pathlib.Path, default=RAW_DIR, help="Output directory for raw records")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    print("================================================================================")
    print("      PBNS Test Suite Execution Covering Evaluated Attack Specifications")
    print("================================================================================")

    # 1. Execute each covering suite binary once
    suite_results = run_unique_suite_binaries()
    for bin_name, res in suite_results.items():
        print(f"[+] Executed suite: {bin_name:<30} -> Exit {res['exit_code']} (PASS, {res['duration_ms']:.1f}ms)")

    # 2. Build specification coverage records
    records = []
    for spec in ATTACK_SPECIFICATIONS:
        bin_name = spec["binary"]
        suite_info = suite_results[bin_name]
        record = {
            "id": spec["id"],
            "tier": spec["tier"],
            "domain": spec["layer"],
            "description": spec["description"],
            "threat": spec["threat"],
            "expected_rejection": spec["expected_rejection"],
            "covering_binary": bin_name,
            "command": suite_info["command"],
            "binary_sha256": suite_info["binary_sha256"],
            "stdout_sha256": suite_info["stdout_sha256"],
            "started_at": suite_info["started_at"],
            "ended_at": suite_info["ended_at"],
            "duration_ms": suite_info["duration_ms"],
            "exit_code": suite_info["exit_code"],
            "suite_passed": suite_info["suite_passed"],
            "evidence_granularity": "covering-suite",
            "testbed": "qemu-hil-pico",
        }
        records.append(record)

    out_file = args.out_dir / "attack-cases.jsonl"
    with out_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print("--------------------------------------------------------------------------------")
    print(f"ADVERSARIAL SPECIFICATION COVERAGE: 22/22 covered by passing test suites")
    print(f"[+] Saved raw verification records to: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
