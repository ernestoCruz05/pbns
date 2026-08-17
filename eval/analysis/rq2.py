#!/usr/bin/env python3
"""PBNS RQ2 Performance & Resource Analysis & LaTeX Table Generator.

Derives all latency percentiles, IQRs, and resource metrics directly from raw
benchmark trial records in eval/raw/performance/.
"""

import json
import math
import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
EVAL_DIR = SCRIPT_DIR.parent
RAW_PERF_DIR = EVAL_DIR / "raw" / "performance"
GEN_DIR = EVAL_DIR / "generated"


def compute_percentiles(values: list[float]) -> dict[str, float]:
    """Compute min, p25, median, p75, iqr, p95, max from an array of numbers."""
    sorted_v = sorted(values)
    n = len(sorted_v)
    assert n > 0, "Cannot compute percentiles on empty dataset"

    def get_p(p: float) -> float:
        idx = (n - 1) * p
        lower = int(math.floor(idx))
        upper = int(math.ceil(idx))
        if lower == upper:
            return sorted_v[lower]
        weight = idx - lower
        return sorted_v[lower] * (1.0 - weight) + sorted_v[upper] * weight

    p25 = get_p(0.25)
    p75 = get_p(0.75)
    median = get_p(0.50)
    p95 = get_p(0.95)
    min_v = sorted_v[0]
    max_v = sorted_v[-1]
    iqr = p75 - p25

    return {
        "min": min_v,
        "p25": p25,
        "median": median,
        "p75": p75,
        "iqr": iqr,
        "p95": p95,
        "max": max_v,
    }


def load_trials(filename: str, expected_count: int) -> list[float]:
    path = RAW_PERF_DIR / filename
    assert path.is_file(), f"Missing raw performance trial file: {path}"
    durations = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            durations.append(record["duration"])
    assert len(durations) == expected_count, (
        f"Expected {expected_count} trials in {filename}, got {len(durations)}"
    )
    return durations


def generate_latency_table() -> str:
    # 1. Load and compute statistics from raw performance records
    launcher_data = load_trials("launcher.jsonl", 100)
    usb_data = load_trials("usb-enumeration.jsonl", 100)
    wifi_data = load_trials("wifi-dhcp.jsonl", 100)
    tls_data = load_trials("tls.jsonl", 100)
    time_data = load_trials("time-service.jsonl", 100)
    attest_data = load_trials("attestation.jsonl", 100)
    rec_data = load_trials("recovery-stream.jsonl", 30)

    l_stats = compute_percentiles(launcher_data)
    u_stats = compute_percentiles(usb_data)
    w_stats = compute_percentiles(wifi_data)
    t_stats = compute_percentiles(tls_data)
    tm_stats = compute_percentiles(time_data)
    at_stats = compute_percentiles(attest_data)
    r_stats = compute_percentiles(rec_data)

    # Sanity checks on derived values
    assert l_stats["median"] < 25.0, "Launcher overhead exceeded budget"
    assert w_stats["median"] < 1000.0, "Wi-Fi association exceeded 1s budget"
    assert r_stats["median"] < 60.0, "Recovery stream exceeded 60s budget"

    rows = [
        ("PBNS Launcher Chainload Overhead", "Boot", l_stats, "ms", 1),
        ("Pico USB CDC Enumeration", "Transport", u_stats, "ms", 1),
        (r"Wi-Fi 802.11n Association \& DHCP", "Transport", w_stats, "ms", 1),
        ("UEFI-Owned TLS 1.2 Handshake", "Security", t_stats, "ms", 1),
        ("Authenticated Time End-to-End RTT", "Service", tm_stats, "ms", 1),
        ("TPM 2.0 Attestation Quote \\& Encryption", "Service", at_stats, "ms", 1),
        ("Authenticated UKI Stream (25.32 MiB)", "Recovery", r_stats, "s", 2),
    ]

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\small",
        r"\caption{PBNS Pre-Boot Service Latency Breakdown (RQ3). Measured across 100 benchmark iterations on the physical Pico W HIL testbed ($N=30$ for 25.32\,MiB recovery UKI streaming).}",
        r"\label{tab:rq2-latency}",
        r"\begin{tabular}{llrrrrr}",
        r"\toprule",
        r"\textbf{Operation} & \textbf{Phase} & \textbf{Median} & \textbf{IQR} & \textbf{Min} & \textbf{Max} & \textbf{p95} \\",
        r"\midrule",
    ]

    for op, phase, stats, unit, dec in rows:
        lines.append(
            f"{op} & {phase} & {stats['median']:.{dec}f}\\,{unit} & {stats['iqr']:.{dec}f}\\,{unit} & "
            f"{stats['min']:.{dec}f} & {stats['max']:.{dec}f} & {stats['p95']:.{dec}f} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ])
    return "\n".join(lines) + "\n"


def generate_resources_table() -> str:
    res_path = RAW_PERF_DIR / "resources.json"
    assert res_path.is_file(), f"Missing resources file: {res_path}"
    res = json.loads(res_path.read_text(encoding="utf-8"))

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\footnotesize",
        r"\renewcommand{\arraystretch}{0.92}",
        r"\caption{PBNS Host and Proxy Resource Utilization (RQ3). Demonstrates low firmware overhead and ample microcontroller headroom ($>60\%$ RAM and $>75\%$ flash on RP2040).}",
        r"\label{tab:rq2-resources}",
        r"\begin{tabularx}{\columnwidth}{lX}",
        r"\toprule",
        r"\textbf{Component / Metric} & \textbf{Measured Value (Headroom)} \\",
        r"\midrule",
        f"PBNS Core Library (C17) & {res['static_code_size_x86_64_kib']:.1f} KiB (x86\\_64 static code) \\\\",
        f"PBNSRecovery.efi Executable & {res['pe_recovery_size_kib']:.1f} KiB (PE/COFF release) \\\\",
        f"PbnsAttest.efi Executable & {res['pe_attest_size_kib']:.1f} KiB (PE/COFF release) \\\\",
        f"UEFI Dynamic Working Heap & {res['uefi_heap_peak_mib']:.2f} MiB (pool memory) \\\\",
        f"UEFI Recovery RAM Arena & {res['uefi_recovery_ram_page_mib']:.2f} MiB (page allocation) \\\\",
        f"Pico W Firmware Flash & {int(res['pico_flash_used_kib'])} KiB / {int(res['pico_flash_total_kib'])} KiB ({100.0 - res['pico_flash_used_pct']:.1f}\\% free) \\\\",
        f"Pico W SRAM Peak Memory & {res['pico_sram_used_kib']:.1f} KiB / {int(res['pico_sram_total_kib'])} KiB ({100.0 - res['pico_sram_used_pct']:.1f}\\% free) \\\\",
        f"Pico W Active Power Draw & {int(res['pico_power_ma'])} mA ({int(res['pico_power_mw'])} mW @ 5V) \\\\",
        f"Gateway Server RSS & {res['gateway_rss_mib']:.1f} MiB (Go + bbolt) \\\\",
        r"\bottomrule",
        r"\end{tabularx}",
        r"\end{table}",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    lat_table = generate_latency_table()
    res_table = generate_resources_table()

    (GEN_DIR / "rq2-latency.tex").write_text(lat_table, encoding="utf-8")
    (GEN_DIR / "rq2-resources.tex").write_text(res_table, encoding="utf-8")

    # Also update paper/generated if running in development tree
    paper_gen = EVAL_DIR.parent / "paper" / "generated"
    if paper_gen.is_dir():
        (paper_gen / "rq2-latency.tex").write_text(lat_table, encoding="utf-8")
        (paper_gen / "rq2-resources.tex").write_text(res_table, encoding="utf-8")

    print(f"[+] Successfully derived RQ2 tables from raw data in {RAW_PERF_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
