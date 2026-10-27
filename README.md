# AgentPrivLab: least privilege when the caller is an AI agent

An offline, reproducible Python testbed that compares authorization strategies at an agent-to-tool boundary, supporting a proposed
ACM Queue article ("Least Privilege When the Caller Is an AI Agent"). Not affiliated with or endorsed by ACM.
Original project specification: [docs/SPEC.md](docs/SPEC.md).

**What it is:** a real gateway (reference monitor), pure policy engines, signed grants, exact-action approvals, delegation attenuation,
hash-chained audit with an independent replay verifier, a real MCP tool server/client (official Python SDK), a synthetic banking backend that
independently verifies gateway assertions, 35 scenario templates, and a paired benchmark runner.
**What it is not:** an LLM experiment. Agent behaviour is **seeded scripted traces**; results measure *enforcement*, not how often a model is tricked.

## Quickstart
```bash
uv sync                                    # Python 3.12 is fetched by uv; needs network once
uv run pytest -q                           # tests (see IMPLEMENTATION_STATUS.md)
uv run agent-privilege seed --seed 42
uv run agent-privilege scenarios validate
uv run agent-privilege test --strategy external_policy --scenario A01_cross_tenant
uv run agent-privilege evaluate --config configs/evaluation.yaml --seed 42 --output results/my-run
uv run agent-privilege replay-audit --input results/my-run/deterministic/audit.jsonl
uv run agent-privilege report --input results/my-run --format markdown
bash scripts/reproduce.sh                  # full check; SKIP_PERF=1 to skip the timing benchmark
```

## Architecture
```text
scripted trace ──► GATEWAY (PEP) ──► MCP client ──► MCP banking server ──► banking service ──► SQLite
   (untrusted)       │  inputs → PDP (pure policy) → approval → delegation
                     └─ hash-chained audit.jsonl ──► replay-audit (re-evaluates recorded inputs)
backend independently verifies a short-lived HMAC assertion: signature, tool, request hash, expiry, single-use nonce, accounts, tenant, limit
```
Trust boundaries: [docs/threat-model.md](docs/threat-model.md).

## Strategies (all run on the same scenarios, state and clock; configs in `configs/strategies/`)
| id | idea | notes |
|---|---|---|
| broad_role | one fixed all-access role | intentionally permissive baseline |
| restricted_role | static roles per task type, own-customer scope, 1000.00 cap | hand-tuned, not a straw man |
| session_scope | session template: tools, accounts, expiry, cap, budget | |
| task_capability | HMAC-signed grant bound to principal/tenant/accounts/destinations/limit/expiry/depth | |
| external_policy | independent per-call policy on trusted task intent + live state | |
| policy_plus_approval | external_policy + exact-hash, expiring, single-use approval | approval never overrides deny |
| delegated_attenuation | external_policy + delegation = parent ∩ request ∩ ceiling; amplification denied | |
| controls | delegated_naive (credential forwarding), external_policy_failopen, direct_no_gateway | |

## Implemented vs simulated vs not done
| | status |
|---|---|
| Gateway, policies, grants, approvals, attenuation, audit chain + replay, MCP server/client (stdio and in-memory), banking backend with idempotent atomic transfers | **implemented and tested** |
| Agent | **simulated**: scripted, seeded, non-adaptive traces |
| Reviewer / approval fatigue | **simulated**: scripted, rubber-stamp, always-reject; parametric fatigue sweep (not human data) |
| Caller authentication, key management, remote policy engine, network, IAM | **not implemented / local only** |
| Policy maintenance | **proxy only** (config lines, regression flips); engineer time not measured |
| Real-LLM experiment, human approval study | **not done** (`agents/optional_llm.py` is an interface stub) |

## Results and docs
Measured results, figures and the hypothesis table: [docs/findings.md](docs/findings.md) (data in [results/run-001](results/run-001/summary.md)).
[methodology](docs/methodology.md) · [limitations](docs/limitations.md) · [assumptions](docs/assumptions.md) · [implementation plan](docs/implementation-plan.md) · [status](IMPLEMENTATION_STATUS.md)

Headline (scripted traces, 104 unauthorized proposals per strategy, 95% Wilson CI, optimistic because instances are correlated): unauthorized executed
broad role 76.9%, restricted role 34.6%, session scope 26.9%, task capability / external policy 11.5%, policy + approval 7.7%, delegated attenuation 7.7%.
The remaining executions for the strongest policies are *in-policy* proposals that no intent-based policy can see. Gateway decision time is ~2 us locally;
see the caveats before citing anything.

License: Apache-2.0.
