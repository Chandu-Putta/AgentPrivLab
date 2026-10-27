# Implementation plan (as built)

Source of truth: [SPEC.md](SPEC.md) (original README) and BUILD_PROMPT.md. This file records assumptions, architecture, phases and status.

## Architecture
Agent (scripted trace) → **gateway** (identity, inputs, policy, approval, delegation, audit) → **MCP client** → **MCP banking server** (official SDK, FastMCP) →
banking service (independent assertion verification) → SQLite. See [threat-model.md](threat-model.md) for trust boundaries.

| package | role |
|---|---|
| `banking/` | SQLite store, deterministic seed (2 tenants, 6 customers), atomic idempotent transfers, assertion verification |
| `mcp_layer/` | real MCP server (stdio or in-memory) and client (named `mcp_layer` to avoid shadowing the `mcp` SDK) |
| `gateway/` | reference monitor, canonical hashing, signed grants |
| `policy/` | pure PDPs: broad/restricted role, session, task capability, external, allow-all; YAML registry with `extends` |
| `approval/`, `delegation/` | exact-action approvals + reviewer models; attenuation |
| `audit/` | hash-chained JSONL journal, replay verifier |
| `agents/` | scripted trace runner (+ optional LLM interface stub) |
| `evaluation/` | env, runner, oracle, metrics, statistics, latency, maintenance, approval simulation, plots, pipeline |

## Phase checklist
- [x] 0 Docs/scaffolding (pyproject, uv lock, ruff, pytest, CI, LICENSE)
- [x] 1 Foundation: models, seed, banking, MCP server/client, canonicalisation, audit, gateway, backend assertions + security tests
- [x] 2 Strategies: 7 + 3 controls, grants, approvals, attenuation, revocation, timeout + tests
- [x] 3 Scenario corpus: 35 templates / 156 instances, validator, applicability matrix, oracle
- [x] 4 Evaluation: metrics, CIs, paired tests, latency, maintenance, approval sim, replay, plots, report
- [~] 5 Optional realism: interface stub only (`agents/optional_llm.py`); **no LLM or human study run**
- [x] 6 Publication: reproduce script, results/run-001, findings, limitations

## Ambiguities resolved
See [assumptions.md](assumptions.md). Metric semantics: [methodology.md](methodology.md).
