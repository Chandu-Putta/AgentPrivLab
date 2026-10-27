# Results

`run-001/` is the committed release produced by `uv run agent-privilege evaluate --seed 42 --output results/run-001`
on one machine (see `run-001/manifest.json`).

| path | content | nature |
|---|---|---|
| `run-001/deterministic/` | `action_decisions.csv` (raw per-action outcomes), `scenario_outcomes.csv`, `metrics.csv`, `paired_comparisons.csv`, `maintenance.csv`, `seed_stability.csv`, `audit.jsonl`, `policy_snapshots/`, `replay_audit.json` | scripted-trace enforcement results; reproducible byte-for-byte (except `audit.jsonl`, which embeds machine-dependent `latency_us`) |
| `run-001/performance/` | `latency.csv` (raw), `latency_summary.csv`, `resources.csv` | **machine-dependent** local timing |
| `run-001/approval-simulation/` | `sweep.csv` | **synthetic** reviewer model, not human data |
| `run-001/llm-optional/` | placeholder | no LLM experiment was run |
| `run-001/figures/` | PNG + SVG generated from the CSVs | |
| `run-001/summary.md`, `manifest.json` | auto-generated tables; commit/versions/seed/config/hashes | |

Reproduce and compare: `bash scripts/reproduce.sh` (tolerance 0 for deterministic CSVs; timing is not compared).
Interpretation: [docs/findings.md](../docs/findings.md) and [docs/limitations.md](../docs/limitations.md).
