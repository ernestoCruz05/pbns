#!/usr/bin/env python3
"""PBNS RQ2 Performance & Resource Measurement Summary Exporter.

Reads raw empirical trial data from eval/raw/performance/ and compiles
the benchmark metrics into JSON summary format for archival and validation.
"""

import argparse
import datetime
import json
import os
import pathlib
import sys
import numpy as np

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
EVAL_DIR = SCRIPT_DIR.parent
RAW_DIR = EVAL_DIR / "raw" / "performance"
RESULTS_DIR = EVAL_DIR / "results"

DATASET_MAP = [
    {
        "file": "launcher.jsonl",
        "operation": "PBNS Launcher Chainload Overhead",
        "phase": "Boot",
        "unit": "ms",
        "expected_samples": 100,
    },
    {
        "file": "usb-enumeration.jsonl",
        "operation": "Pico USB CDC Enumeration",
        "phase": "Transport",
        "unit": "ms",
        "expected_samples": 100,
    },
    {
        "file": "wifi-dhcp.jsonl",
        "operation": "WiFi 802.11n Association & DHCP",
        "phase": "Transport",
        "unit": "ms",
        "expected_samples": 100,
    },
    {
        "file": "tls.jsonl",
        "operation": "UEFI-Owned TLS 1.2 Handshake",
        "phase": "Security",
        "unit": "ms",
        "expected_samples": 100,
    },
    {
        "file": "time-service.jsonl",
        "operation": "Trusted Time End-to-End RTT",
        "phase": "Service",
        "unit": "ms",
        "expected_samples": 100,
    },
    {
        "file": "attestation.jsonl",
        "operation": "TPM 2.0 Attestation Quote & Encryption",
        "phase": "Service",
        "unit": "ms",
        "expected_samples": 100,
    },
    {
        "file": "recovery-stream.jsonl",
        "operation": "Authenticated UKI Stream (25.32 MiB)",
        "phase": "Recovery",
        "unit": "s",
        "expected_samples": 30,
    },
]


def load_and_calculate_benchmarks() -> list[dict]:
    benchmarks = []
    for spec in DATASET_MAP:
        path = RAW_DIR / spec["file"]
        assert path.is_file(), f"Missing raw performance file: {path}"
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").strip().split("\n") if line.strip()]
        assert len(lines) == spec["expected_samples"], f"Sample count mismatch in {path}: expected {spec['expected_samples']}, got {len(lines)}"

        vals = np.array([float(r["duration"]) for r in lines])
        q25, med, q75 = np.percentile(vals, [25, 50, 75])
        p95 = np.percentile(vals, 95)
        iqr = q75 - q25

        benchmarks.append({
            "operation": spec["operation"],
            "phase": spec["phase"],
            "unit": spec["unit"],
            "median": round(float(med), 2),
            "iqr": round(float(iqr), 2),
            "min": round(float(np.min(vals)), 2),
            "max": round(float(np.max(vals)), 2),
            "p95": round(float(p95), 2),
            "samples": len(vals),
        })
    return benchmarks


def load_resources() -> list[dict]:
    res_path = RAW_DIR / "resources.json"
    if res_path.is_file():
        return json.loads(res_path.read_text(encoding="utf-8"))
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Export PBNS RQ2 Performance Summary from Raw Trials")
    parser.add_argument("--output", type=pathlib.Path, default=RESULTS_DIR / "rq2-benchmarks.json", help="Output JSON path")
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    benchmarks = load_and_calculate_benchmarks()
    resources = load_resources()

    summary = {
        "schemaVersion": 1,
        "campaign": "PBNS-RQ2-Physical-HIL-Performance",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "latencyBenchmarks": benchmarks,
        "resourceBenchmarks": resources,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"[+] Successfully exported RQ2 summary ({len(benchmarks)} benchmarks) to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
