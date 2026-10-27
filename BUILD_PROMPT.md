# Implementation prompt for coding agent

Build the GitHub-ready Python repository specified in the accompanying README.md. Read it fully before coding. The target is reproducible experimental evidence for a practitioner-focused ACM Queue article about least privilege for AI agents, not a toy chatbot demo and not a claim of novel security guarantees.

## Non-negotiable requirements
1. Python 3.12+, typed code, `uv`, `pytest`, `ruff`, Pydantic, FastAPI for synthetic banking API, SQLite or in-memory database, official Python MCP SDK for at least one real MCP server/client. Pin dependencies and document tested versions.
2. No external banking systems, real customer information, cloud credentials, or paid model API required. A deterministic seeded agent action-trace runner is the default. Real LLM integration is optional and results must be reported separately.
3. Implement a genuine authorization gateway on the tool invocation path, a separate policy decision module, real backend-side enforcement of trusted authorization assertions, denial without side effects, and fail-closed behavior. Agents must not have direct tool credentials that bypass controls.
4. Compare broad RBAC, carefully restricted RBAC, session-scoped permissions, task-bound capability grants, external per-action policy, policy plus approval, and delegated permission attenuation. Define exact policies in version-controlled config; keep experimental conditions comparable.
5. Implement scenario fixtures with independently specified ground truth for legitimate actions and adversarial attempts, including prompt-injection-bearing untrusted content, cross-tenant access, unauthorized transfers, approval replay, scope escalation, and delegation. Do not label a scripted malicious action as an LLM attack success.
6. Build a rigorous evaluator producing raw per-action outcomes, security metrics, false-positive rates, legitimate task completion, latency distributions, audit replay accuracy, policy maintenance proxies, and approval-simulator sensitivity. Report sample sizes, uncertainty, machine details, and limitations. Do not invent numbers.
7. Implement canonical request hashing, expiry/replay protection, parameter-bound approval, scoped delegation, immutable-by-convention audit JSONL with hash chaining, and a deterministic replay verifier. Clearly document limits of the security model.
8. Generate publishable charts, CSVs, manifests, and Markdown findings using measured data only. Include a one-command reproducibility script and offline CI.

## Work sequence
- First inspect README.md and write `docs/implementation-plan.md` with assumptions, architecture, threat model, trust boundaries, precise metric definitions, and a phased task checklist. Resolve ambiguous semantics explicitly in documentation rather than silently choosing.
- Implement foundation and security invariants with unit/integration tests before adding the evaluator.
- Implement all seven strategies and an explicit scenario/strategy applicability matrix.
- Add the adversarial and legitimate fixtures, ground-truth validators, and a paired benchmark runner.
- Add audit replay, reports, plots, reproducibility metadata, and GitHub Actions.
- Execute tests and full experiment. Debug failures; never modify scenario ground truth merely to make a policy look better.
- Produce `docs/findings.md` with measured observations, negative findings, sensitivity analysis, confounders, limitations, and which hypotheses are supported or not supported.
- Finish by providing a file tree, exact working commands, tests passed/failed, actual experiment totals, generated result paths, and known remaining gaps.

## Engineering quality gates
Use strong input validation, deterministic seed resets, concurrency-safe transfers, idempotency keys, stable canonical serialization, explicit principal/tenant/resource bindings, time injection for expiry tests, and separation of policy decisions from tool execution. Test malicious direct-to-backend calls, tampered grants, malformed records, approval parameter changes, missing audit fields, and delegated scope expansion. Include both allow and deny paths and measure false positives, not only attack blocking. Never describe simulated approval behavior as measured human behavior.

## Editorial quality gates
Keep README concise at the top with a quickstart, architecture figure, research questions, comparison matrix and links to detailed docs. Prefer evidence over marketing. Use precise terms: unauthorized execution, not generic 'attack success'; scripted adversarial traces, not demonstrated LLM exploitation. Include at least one counterexample where the strongest policy harms legitimate completion, and quantify the latency/security trade-off. State that local deterministic experiments do not establish real-world prompt-injection susceptibility. Explain exactly what is mocked, what is implemented, and what is optional.

Start by implementing Phase 1. Do not stop after generating a skeleton; deliver running code and tests. If a tool or package is unavailable, document the limitation and preserve a working offline path without pretending it was tested.
