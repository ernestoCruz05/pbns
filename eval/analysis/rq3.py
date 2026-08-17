#!/usr/bin/env python3
"""PBNS RQ3 Security & Adversarial Analysis & LaTeX Table Generator.

Derives the 22-case attack evaluation matrix and 120.0 CPU-hour parser fuzzing
campaign tables directly from raw/adversarial/ and raw/fuzzing/ records.
"""

import json
import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
EVAL_DIR = SCRIPT_DIR.parent
RAW_ADV_DIR = EVAL_DIR / "raw" / "adversarial"
RAW_FUZZ_DIR = EVAL_DIR / "raw" / "fuzzing"
GEN_DIR = EVAL_DIR / "generated"


def generate_attacks_table() -> str:
    adv_path = RAW_ADV_DIR / "attack-cases.jsonl"
    assert adv_path.is_file(), f"Missing attack cases raw file: {adv_path}"

    cases = []
    with adv_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            cases.append(json.loads(line))

    # Rigorous validation of empirical evidence
    assert len(cases) == 22, f"Expected 22 evaluated attack cases, got {len(cases)}"
    case_ids = {c["id"] for c in cases}
    assert len(case_ids) == 22, f"Duplicate case IDs found in {adv_path}"
    assert all(c.get("suite_passed") for c in cases), "Security failure: covering test suite did not pass"

    # Separate into Tier 1 (Hostile Bearer / Network) and Tier 2 (Defense in Depth)
    tier1_ids = {"A-TLS-01", "A-TLS-02", "A-TLS-03", "A-PATH-01", "A-PATH-02", "A-PATH-03"}
    tier1_cases = [c for c in cases if c["id"] in tier1_ids]
    tier2_cases = [c for c in cases if c["id"] not in tier1_ids]

    assert len(tier1_cases) == 6, f"Expected 6 Tier 1 cases, got {len(tier1_cases)}"
    assert len(tier2_cases) == 16, f"Expected 16 Tier 2 cases, got {len(tier2_cases)}"

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\footnotesize",
        r"\renewcommand{\arraystretch}{0.92}",
        r"\caption{PBNS Adversarial Attack and Fault Specification Coverage Matrix (RQ4). 22 evaluated security specifications across two threat tiers. Each specification is mapped to a compiled validation suite exercising the corresponding fail-closed behavior; all covering suites pass.}",
        r"\label{tab:rq3-attacks}",
        r"\begin{tabularx}{\textwidth}{llXllc}",
        r"\toprule",
        r"\textbf{ID} & \textbf{Layer} & \textbf{Threat / Fault Specification} & \textbf{Expected Rejection} & \textbf{Covering Test Suite} & \textbf{Suite Result} \\",
        r"\midrule",
        r"\multicolumn{6}{l}{\textbf{Tier 1: Hostile Bearer and Network Path (Primary Threat Model)}} \\",
    ]

    for c in tier1_cases:
        rej_escaped = c["expected_rejection"].replace("_", r"\_")
        bin_escaped = c["covering_binary"].replace("_", r"\_")
        desc_escaped = c["description"].replace("_", r"\_")
        lines.append(
            f"{c['id']} & {c['domain']} & {desc_escaped} & \\texttt{{{rej_escaped}}} & \\texttt{{{bin_escaped}}} & \\checkmark\\ Pass \\\\"
        )

    lines.extend([
        r"\midrule",
        r"\multicolumn{6}{l}{\textbf{Tier 2: Authenticated Endpoint, Backend, and Framing Faults (Defense-in-Depth)}} \\",
    ])

    for c in tier2_cases:
        rej_escaped = c["expected_rejection"].replace("_", r"\_")
        bin_escaped = c["covering_binary"].replace("_", r"\_")
        desc_escaped = c["description"].replace("_", r"\_")
        lines.append(
            f"{c['id']} & {c['domain']} & {desc_escaped} & \\texttt{{{rej_escaped}}} & \\texttt{{{bin_escaped}}} & \\checkmark\\ Pass \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabularx}",
        r"\end{table*}",
    ])
    return "\n".join(lines) + "\n"


def generate_fuzz_table() -> str:
    summary_path = RAW_FUZZ_DIR / "fuzz-summary.json"
    assert summary_path.is_file(), f"Missing fuzz summary file: {summary_path}"
    targets = json.loads(summary_path.read_text(encoding="utf-8"))

    assert len(targets) == 5, f"Expected 5 fuzz targets, got {len(targets)}"

    total_cpu_hours = sum(t["cpu_hours"] for t in targets)
    total_iterations = sum(t["iterations"] for t in targets)
    total_crashes = sum(t["crashes"] for t in targets)
    total_leaks = sum(t["leaks"] for t in targets)
    avg_speed = sum(t["execs_per_sec"] for t in targets) / len(targets)

    assert total_cpu_hours >= 120.0, f"Expected >= 120 CPU hours, got {total_cpu_hours}"
    assert total_crashes == 0, f"Observed unexpected fuzz crashes: {total_crashes}"
    assert total_leaks == 0, f"Observed unexpected memory leaks: {total_leaks}"

    # Also assert that each corresponding log file exists
    for t in targets:
        log_name = f"{t['target'].replace('fuzz_', '')}.log"
        log_file = RAW_FUZZ_DIR / log_name
        assert log_file.is_file(), f"Missing expected raw fuzzer log: {log_file}"

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\footnotesize",
        r"\caption{PBNS Security-Critical Parser Fuzzing Campaign (RQ4). 120.0 cumulative CPU-hours (24.0 CPU-h per target) across five selected security-critical parser targets with the applicable sanitizers and runtime checkers enabled.}",
        r"\label{tab:rq3-fuzz}",
        r"\begin{tabularx}{\textwidth}{lrrrXl}",
        r"\toprule",
        r"\textbf{Parser Target} & \textbf{Duration} & \textbf{Total Iterations} & \textbf{Campaign Avg Exec/s} & \textbf{Active Sanitizers / Checkers} & \textbf{Observed Findings} \\",
        r"\midrule",
    ]

    for t in targets:
        target_name = t["target"].replace("_", r"\_")
        lines.append(
            f"\\texttt{{{target_name}}} & {t['cpu_hours']:.1f} CPU-h & {t['iterations']:,} & {t['execs_per_sec']:.1f} & "
            f"{t['sanitizers']} & {t['crashes']} (No crashes) \\\\"
        )

    lines.extend([
        r"\midrule",
        f"\\textbf{{Total / Cumulative}} & \\textbf{{{total_cpu_hours:.1f} CPU-h}} & \\textbf{{{total_iterations:,}}} & "
        f"\\textbf{{{avg_speed:.1f}}} & --- & \\textbf{{0 (Zero findings)}} \\\\",
        r"\bottomrule",
        r"\end{tabularx}",
        r"\end{table*}",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    attacks_tex = generate_attacks_table()
    fuzz_tex = generate_fuzz_table()

    (GEN_DIR / "rq3-attacks.tex").write_text(attacks_tex, encoding="utf-8")
    (GEN_DIR / "rq3-fuzz.tex").write_text(fuzz_tex, encoding="utf-8")

    paper_gen = EVAL_DIR.parent / "paper" / "generated"
    if paper_gen.is_dir():
        (paper_gen / "rq3-attacks.tex").write_text(attacks_tex, encoding="utf-8")
        (paper_gen / "rq3-fuzz.tex").write_text(fuzz_tex, encoding="utf-8")

    print(f"[+] Successfully derived RQ3 tables from raw data in {RAW_ADV_DIR} and {RAW_FUZZ_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
