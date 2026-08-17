#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

printf '\n============================================================\n'
printf '  PBNS Evaluation and Artifact Verification Runner\n'
printf '  Target: USENIX Security ’27 Cycle 1\n'
printf '============================================================\n\n'

printf '[1/6] Scanning for anonymity leaks and untrusted secrets...\n'
python3 "$PBNS_ROOT/tools/audit-secrets.py" --root "$PBNS_ROOT"

printf '\n[2/6] Running CTest hosted C17 test suite (71 components)...\n'
ctest --test-dir "$PBNS_ROOT/build" --output-on-failure

printf '\n[3/6] Running Go gateway & CLI test suite with race detector...\n'
(
    cd "$PBNS_ROOT/gateway"
    go test -race ./...
)

printf '\n[4/6] Running RQ3 Adversarial Matrix & Fuzzing Pipeline...\n'
python3 "$PBNS_ROOT/integration/security/test_attack_oracles.py"
python3 "$PBNS_ROOT/eval/runners/rq3_security.py"
python3 "$PBNS_ROOT/eval/analysis/rq3.py"

printf '\n[5/6] Running RQ2 Performance & Resource Measurement Pipeline...\n'
python3 "$PBNS_ROOT/eval/runners/rq2_performance.py"
python3 "$PBNS_ROOT/eval/analysis/rq2.py"

printf '\n[6/6] Generating RQ4 Architectural Comparison & RQ1 Summary...\n'
python3 "$PBNS_ROOT/eval/analysis/rq4.py"

printf '\n============================================================\n'
printf '  [SUCCESS] All PBNS Verifications, Tests, and Evaluations PASS\n'
printf '============================================================\n\n'
