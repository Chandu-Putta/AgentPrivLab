#!/usr/bin/env bash
# Regenerate the deterministic results from a fresh checkout and compare with the committed release.
# Usage: bash scripts/reproduce.sh [output_dir]      (SKIP_PERF=1 skips the machine-dependent benchmark)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-results/reproduction}"
REF="results/run-001"

uv sync --locked
uv run ruff check src tests
uv run pytest -q
uv run agent-privilege scenarios validate | head -1

rm -rf "$OUT"
if [ -n "${SKIP_PERF:-}" ]; then
  uv run agent-privilege evaluate --config configs/evaluation.yaml --seed 42 --output "$OUT" --skip-performance
else
  uv run agent-privilege evaluate --config configs/evaluation.yaml --seed 42 --output "$OUT"
fi
uv run agent-privilege replay-audit --input "$OUT/deterministic/audit.jsonl"

# Deterministic outputs must be byte-identical (tolerance 0). audit.jsonl and timing files are
# machine-dependent (latency_us is recorded inside audit records) and are NOT compared.
status=0
if [ "$OUT" != "$REF" ] && [ -d "$REF" ]; then
  for f in action_decisions scenario_outcomes metrics paired_comparisons maintenance seed_stability; do
    if cmp -s "$REF/deterministic/$f.csv" "$OUT/deterministic/$f.csv"; then echo "identical: $f.csv"
    else echo "DIFFERS:   $f.csv"; status=1; fi
  done
  cmp -s "$REF/approval-simulation/sweep.csv" "$OUT/approval-simulation/sweep.csv" \
    && echo "identical: sweep.csv" || { echo "DIFFERS:   sweep.csv"; status=1; }
fi
exit $status
