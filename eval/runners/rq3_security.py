#!/usr/bin/env python3
"""PBNS RQ3 Evaluation Runner: Adversarial Suite & Fuzzing Campaign Summary.

Invokes the live adversarial attack runner (integration/security/run_attack_suite.py)
and derives the fuzzing campaign results from raw campaign logs.
"""

import argparse
import datetime
import json
import os
import pathlib
import subprocess
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
EVAL_DIR = SCRIPT_DIR.parent
PBNS_ROOT = EVAL_DIR.parent
RESULTS_DIR = EVAL_DIR / "results"
RAW_FUZZ_DIR = EVAL_DIR / "raw" / "fuzzing"


def run_adversarial_suite(out_dir: pathlib.Path) -> list[dict]:
    attack_script = PBNS_ROOT / "integration" / "security" / "run_attack_suite.py"
    cmd = [sys.executable, str(attack_script), "--out-dir", str(out_dir)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError("Adversarial suite execution failed")
    
    trials_file = out_dir / "attack-cases.jsonl"
    assert trials_file.is_file(), f"Missing output file: {trials_file}"
    records = [json.loads(line) for line in trials_file.read_text(encoding="utf-8").strip().split("\n") if line.strip()]
    return records


def load_fuzz_summary() -> list[dict]:
    summary_path = RAW_FUZZ_DIR / "fuzz-summary.json"
    assert summary_path.is_file(), f"Missing fuzz summary file: {summary_path}"
    return json.loads(summary_path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PBNS RQ3 Evaluation & Export Summary")
    parser.add_argument("--out-file", type=pathlib.Path, default=RESULTS_DIR / "rq3-summary.json", help="Summary output JSON path")
    args = parser.parse_args()

    args.out_file.parent.mkdir(parents=True, exist_ok=True)
    raw_adv_dir = EVAL_DIR / "raw" / "adversarial"

    print("[*] Executing test suites covering the 22 evaluated attack and fault specifications...")
    attack_records = run_adversarial_suite(raw_adv_dir)
    print(f"[+] Verified {len(attack_records)} specifications covered by passing suites.")

    print("[*] Loading fuzzing campaign summary...")
    fuzz_targets = load_fuzz_summary()

    summary = {
        "schemaVersion": 1,
        "campaign": "PBNS-RQ3-Adversarial-and-Fuzzing",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "totalAttackSpecifications": len(attack_records),
        "specificationsCovered": sum(1 for r in attack_records if r.get("suite_passed")),
        "fuzzing": {
            "totalTargets": len(fuzz_targets),
            "totalIterations": sum(t["iterations"] for t in fuzz_targets),
            "totalCpuHours": sum(t["cpu_hours"] for t in fuzz_targets),
            "totalCrashes": sum(t["crashes"] for t in fuzz_targets),
            "totalLeaks": sum(t["leaks"] for t in fuzz_targets),
            "targets": fuzz_targets,
        },
    }

    with open(args.out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"[+] Successfully exported RQ3 summary to: {args.out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
