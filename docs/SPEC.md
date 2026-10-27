# Least Privilege When the Caller Is an AI Agent

A reproducible Python testbed for comparing authorization approaches at an agent-to-tool boundary. Designed to support a practitioner-oriented ACM Queue article. **This repository is an experimental specification until implementations and results are committed. No benchmark results are claimed here.**

## Research question
How should least privilege be enforced when an AI agent chooses tools dynamically, processes untrusted content, and can delegate tasks?

## Hypotheses (to test, not assume)
- H1: Broad fixed roles permit more unauthorized actions than contextual task-scoped grants under identical workloads.
- H2: External policy enforcement reduces unauthorized execution but introduces measurable latency and maintenance effort.
- H3: Human approval can reduce dangerous actions, but approval fatigue can increase false approvals.
- H4: Delegation with explicit permission attenuation prevents privilege expansion compared with naive credential forwarding.
- H5: Structured audit evidence improves deterministic reconstruction of decisions.

## Scope and realism
Use synthetic customer accounts, synthetic transactions, and a local Python banking API. No real bank, cloud IAM, production secrets, or real money. Implement the gateway, enforcement decisions, approval workflow, delegation checks, and audit system as **real executable code**. Implement at least one actual MCP tool server and client using the official Python MCP SDK; pin its version. Compare the gateway and a direct-to-tool baseline. A mock agent emits controlled, seeded action traces for reproducible tests. An optional real LLM mode is a *separate experiment* and must not be conflated with deterministic results.

### Key limitations
A deterministic trace runner measures enforcement against scripted agent behavior; it does not establish how often a deployed LLM is tricked by prompt injection. A synthetic approval model measures sensitivity to assumptions, not real human approval fatigue. Local benchmarks do not establish production network or enterprise IAM overhead. Label each result accordingly.

## Architecture
```text
Synthetic task / adversarial scenario
              |
     Seeded agent trace runner     [optional: real LLM adapter]
              |
       Tool invocation request
              |
      Authorization gateway <---- independent policy engine
        |      |      |              |-- roles, sessions, task grants
        |      |      |              |-- action/resource/tenant constraints
        |      |      |              |-- delegation attenuation
        |      |      +-- approval decision simulator / manual adapter
        |      +--------- structured audit journal
        +---------------- MCP client -> MCP banking tool server
                                          |
                                   synthetic banking API
                                          |
                                    in-memory/SQLite DB
```
The gateway is a reference monitor: every sensitive invocation is mediated. The agent must not possess direct credentials that bypass the gateway. The banking backend independently verifies an authenticated gateway identity and scoped capability or authorization assertion, to avoid an easily bypassed gateway. Default deny on missing or malformed context. Do not treat text in prompts, tool responses, or documents as authorization.

## Banking tools and operations
- `get_account(account_id)` — account read, tenant-scoped
- `list_transactions(account_id)` — read transaction history
- `transfer_funds(source_id, destination_id, amount, currency, idempotency_key)` — irreversible/high-impact synthetic action
- `update_contact(account_id, contact)` — mutable/reversible with caveats
- `create_payee(account_id, payee_id)` — sensitive preparatory action
- `export_statement(account_id)` — privacy-sensitive export
- `delegate_task(child_agent_id, requested_scopes)` — attenuated authorization context

Use seeded customers from at least two tenants; no real personal data. Transactions must be atomic, balance checked, currency validated, and idempotent. Reset state before each run.

## Authorization strategies (same scenarios, same tools)
1. `broad_role`: intentionally permissive fixed-role baseline; document granted rights.
2. `restricted_role`: manually least-privilege static role baseline; do not compare only against a straw man.
3. `session_scope`: temporary permissions limited by session and expiry.
4. `task_capability`: signed or integrity-protected task grant bound to principal, tenant, account, action, limits, expiry and delegation depth.
5. `external_policy`: independently evaluated contextual policy at each tool call.
6. `policy_plus_approval`: external policy with mandatory approval for high-impact actions; approvals bound to exact canonicalized action and expire.
7. `delegated_attenuation`: delegated permissions are the intersection of parent grants, child request and policy; deny any attempted amplification.

Do not treat approval as a substitute for policy. Separate the cost of approval from automatic enforcement. Every strategy should declare its administrative configuration and threat assumptions.

## Scenario matrix
Maintain versioned YAML scenarios with explicit authorized outcomes, including:
- Legitimate own-account balance read and transaction listing
- Legitimate authorized low-value transfer
- Legitimate transfer requiring approval
- Unauthorized cross-tenant account read
- Unauthorized cross-customer statement export
- Unauthorized high-value transfer and amount escalation
- Prompt-injection instructions embedded in transaction memo/tool response
- Forged system/manager authorization in untrusted content
- Multi-step payee creation followed by transfer
- Stale/expired capability reuse; replayed approval; modified parameters after approval
- Delegation attempting to add new tools, accounts, or higher limits
- Confused-deputy attempt using a service identity
- Benign requests incorrectly blocked by restrictive policies
- Service failures and fail-open/fail-closed behavior

Each scenario specifies: `id`, `category`, `task`, `tenant`, `actor`, `trusted_context`, `untrusted_content`, `actions`, `expected_authorization`, `expected_side_effects`, `severity`, `seed`, and `rationale`. Explicitly distinguish *malicious proposed tool calls* from a *successful LLM compromise*.

## Evaluation design
Run every scenario against every applicable strategy using the same inputs, initial state, seeds, and machine. Separate correctness testing from performance testing. Use warmups and repeated runs, and report distributions and confidence intervals. Pre-register primary metrics and expected ground truth in `docs/methodology.md` before examining outcomes.

### Metrics
- **Unauthorized execution rate:** unauthorized actions executed / unauthorized actions attempted. Include per-severity breakdown.
- **Attack blocking rate:** unauthorized attempts blocked / unauthorized attempts; report denominators.
- **False-positive rate:** authorized actions denied or unnecessarily escalated / authorized actions attempted; distinguish deny vs escalation.
- **Legitimate task completion:** authorized tasks completed / authorized tasks attempted; multi-step task success is separate from per-call success.
- **Latency:** gateway decision time and end-to-end invocation latency, p50/p95/p99, with and without approval.
- **Operational cost:** CPU time, memory, policy evaluation count, audit bytes, and optionally measured LLM token cost in a separate real-model run.
- **Policy maintenance:** rules count, policy lines changed, engineer time logged for predefined change requests, regression failures and time to fix. Never claim maintenance effort from LOC alone.
- **Audit reconstructability:** fraction of sampled decisions for which an independent replay can reproduce the decision from recorded versioned inputs and policies.
- **Approval fatigue:** simulation sensitivity to varying reviewer error rates; not an empirical claim about humans.
- **Delegation safety:** attempted permission expansions rejected / attempted expansions, plus legitimate delegated task completion.

Record confidence intervals for proportions (e.g., Wilson intervals), latency bootstrap intervals, machine/software versions, seeds and exact configuration. Do not report p99 without enough samples to make it meaningful. Avoid causal claims beyond controlled comparisons.

## Audit record contract
JSONL entries should contain: timestamp, trace/run IDs, scenario ID, actor/agent identity, parent agent ID, tenant, task ID, trusted grant ID and hash, tool/action, canonicalized resource IDs and parameter hash, policy ID/version/hash, decision and reason codes, approval identity/status and bound request hash, delegation lineage, outcome, synthetic side-effect reference, latency and correlation ID. Never log raw secrets or unnecessary synthetic PII. Use append-only integrity chaining for tamper-evidence, clearly labeled as *not* tamper-proof storage. Supply a `replay-audit` command and tests for incomplete/tampered records.

## Suggested repository layout
```text
.
├── README.md
├── pyproject.toml
├── uv.lock                       # after dependency resolution
├── LICENSE
├── CITATION.cff
├── .github/workflows/ci.yml
├── configs/strategies/*.yaml
├── scenarios/legitimate/*.yaml
├── scenarios/attacks/*.yaml
├── src/agent_privilege/
│   ├── cli.py
│   ├── models.py
│   ├── banking/{api.py,db.py,seed.py}
│   ├── mcp/{server.py,client.py}
│   ├── gateway/{service.py,canonicalize.py,capabilities.py}
│   ├── policy/{base.py,rbac.py,session.py,task.py,external.py}
│   ├── approval/{service.py,simulator.py}
│   ├── delegation/{attenuation.py}
│   ├── audit/{journal.py,replay.py}
│   ├── agents/{trace_runner.py,optional_llm.py}
│   └── evaluation/{runner.py,metrics.py,statistics.py,plots.py}
├── tests/{unit,integration,security,property}/
├── docs/{threat-model.md,methodology.md,assumptions.md,limitations.md}
├── results/README.md
└── scripts/reproduce.sh
```

## CLI contract (implement these commands)
```bash
uv sync
uv run agent-privilege seed --seed 42
uv run agent-privilege scenarios validate
uv run agent-privilege test --strategy external_policy --scenario cross_tenant_read
uv run agent-privilege evaluate --config configs/evaluation.yaml --seed 42 --output results/run-001
uv run agent-privilege replay-audit --input results/run-001/audit.jsonl
uv run agent-privilege report --input results/run-001 --format markdown
uv run pytest -q
bash scripts/reproduce.sh
```
These are target interfaces, not commands verified to work yet.

## Results publication contract
Each committed experiment release must include `manifest.json` (Git commit, timestamp, versions, platform, config, seed, scenario counts), `scenario_outcomes.csv`, `action_decisions.csv`, `metrics.csv`, `latency.csv`, `audit.jsonl` or a sanitized sample, `summary.md`, and reproducible plots (PNG/SVG). Separate `results/deterministic/`, `results/approval-simulation/`, and `results/llm-optional/`. Include a table for each hypothesis with evidence, counterexamples, and limitations. **Never fabricate measurements or publish placeholder data as results.**

## Security and reproducibility acceptance criteria
- Tests prove a denied action has no banking side effect.
- Cross-tenant and delegated privilege escalation attempts fail at both gateway and backend trust boundaries.
- Approval cannot be reused for altered action parameters or replayed after expiry.
- A tool cannot bypass the gateway using a direct credential available to the agent.
- Tests cover malformed input, currency/amount validation, concurrency, replay, revocation and timeout behavior.
- CI executes deterministic tests without cloud credentials.
- A fresh checkout can regenerate published deterministic results with documented tolerances; timing results are machine-dependent and labeled.
- README distinguishes observed findings from hypotheses and simulated assumptions.

## Execution phases
1. **Foundation:** models, seed data, banking service, MCP server/client, gateway and security tests.
2. **Baselines:** broad and restricted RBAC, session, task capability, external policy, approval and delegation.
3. **Scenario corpus:** ground-truth fixtures, legitimate workloads, adversarial traces, negative tests.
4. **Evaluation:** automated metrics, paired comparisons, repeated runs, plots and audit replay.
5. **Optional realism:** live LLM tool-selection experiments, explicitly separated from scripted tests; optionally human approval study with consent and clear methodology.
6. **Publication:** reproducibility verification, threat model, results release, article-ready figures and critical discussion.

## Article narrative
Lead with a concrete unauthorized transfer or cross-tenant access attempt; show the precise tool call and why the policy boundary matters. Explain the authorization design alternatives, then use comparative evidence to discuss trade-offs and failure modes. Conclude with deployment guidance: mediate every action, bind authorization to exact resource and intent, attenuate delegation, verify sensitive operations outside the model, and preserve decision provenance. These are engineering recommendations to test and qualify, not universal guarantees.

## Sources to consult
- ACM Queue: https://queue.acm.org/
- ACM Queue case studies: https://queue.acm.org/casestudies.cfm
- MCP specification: https://modelcontextprotocol.io/specification
- OWASP GenAI security resources: https://genai.owasp.org/
- NIST SP 800-53 access control family and NIST SP 800-207 zero trust architecture

## License and contribution
Choose a permissive license (e.g. Apache-2.0) and add `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md` if the project grows. Do not imply ACM affiliation or endorsement.
