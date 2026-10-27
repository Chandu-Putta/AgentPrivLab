# Implementation status

Last updated after the final verification run (Python 3.12.15, mcp 1.30.0, macOS arm64).

## Phases
| phase | status | notes |
|---|---|---|
| 0 Docs & scaffolding | done | pyproject + `uv.lock`, ruff, pytest, LICENSE (Apache-2.0), CI workflow, CITATION, SECURITY |
| 1 Foundation | done | models, seed, SQLite banking, real MCP server/client, canonical hashing, audit journal, gateway, backend assertion checks |
| 2 Strategies | done | 7 strategies + 3 controls (naive delegation, fail-open, direct/no gateway); grants, approvals, attenuation, revocation, backend timeout |
| 3 Scenario corpus | done | 35 templates / 156 instances; validator; applicability matrix; independent state oracle |
| 4 Evaluation | done | metrics + Wilson/bootstrap CIs, exact McNemar, latency/CPU/memory, maintenance proxy, approval-fatigue sim, audit replay, 6 figures, report |
| 5 Optional realism | **not done** | `agents/optional_llm.py` is an interface stub; no LLM or human-study results exist |
| 6 Publication | done (local) | `scripts/reproduce.sh`, `results/run-001`, `docs/findings.md`, limitations, threat model |

## Test results
- `uv run pytest -q`: **63 passed** (security invariants, strategies/approval/delegation, audit tamper detection, MCP stdio integration,
  statistics, hypothesis property tests, scenario validation + ground-truth lint, full pipeline CLI incl. tampered-log replay failure).
- `uv run ruff check src tests`: clean.
- `bash scripts/reproduce.sh`: exit 0; regenerated deterministic CSVs identical (tolerance 0) to `results/run-001`; audit replay 2048/2048.
  Wall time varied between ~1 and ~10 minutes (the timing benchmark is the slow part).

## Experiment totals (results/run-001, seed 42)
156 scenario instances; 2260 action rows per full-matrix condition (primary, layered) + 244 each for the two reviewer-sensitivity conditions
= 5008 rows; 2048 audit records in the primary condition, all replay-reproducible; seed stability: 0 differing outcomes (seeds 1, 2).

## Known gaps / blockers (none blocking)
- Not a git repo with commits: `manifest.json` records `git_commit: "uncommitted"`. Commit, then re-run `evaluate` to stamp the commit.
- GitHub Actions workflow is written but **not executed** (no remote). `uv sync --locked` assumes `uv.lock` is committed.
- No real-LLM experiment, no human approval study, no remote policy-engine latency, no caller authentication.
- Maintenance effort is a proxy only; engineer time not measured. Corpus is single-author with correlated instances (see docs/limitations.md).
- Possible follow-ups: independent red-team scenario review; a scenario that separates task_capability from external_policy; adaptive attacker traces;
  template-level (cluster) confidence intervals; unstructured-log baseline for H5.
