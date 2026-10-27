# Findings (release `results/run-001`, seed 42)

Every number below is copied from the generated files in `results/run-001/` (`summary.md`, `deterministic/metrics.csv`,
`paired_comparisons.csv`, `maintenance.csv`, `performance/*.csv`, `approval-simulation/sweep.csv`). Read
[limitations.md](limitations.md) first: **scripted traces, one author, 35 templates (156 correlated instances), local timing.**
Percent (k/n) [95% Wilson CI]; CIs are optimistic because instances within a template are near-duplicates.
Terminology: *unauthorized execution* of a *scripted adversarial proposal*; this is **not** evidence about LLM susceptibility.

## Headline (primary condition, common scenarios; 104 unauthorized / 104 authorized actions per strategy)
| strategy | unauthorized executed | authorized not executed | legit task completion |
|---|---|---|---|
| broad_role | 76.9% (80/104) [68.0, 84.0] | 0.0% (0/104) | 100% (52/52) |
| restricted_role | 34.6% (36/104) [26.2, 44.2] | 3.8% (4/104) | 92.3% (48/52) |
| session_scope | 26.9% (28/104) [19.3, 36.2] | 3.8% (4/104) | 92.3% (48/52) |
| task_capability | 11.5% (12/104) [6.7, 19.1] | 0.0% (0/104) | 100% |
| external_policy | 11.5% (12/104) [6.7, 19.1] | 0.0% (0/104) | 100% |
| policy_plus_approval | 7.7% (8/104) [3.9, 14.4] | 0.0% (0/104) (15.4% = 16/104 escalated, all approved by the scripted reviewer) | 100% |
| delegated_attenuation | 7.7% (8/104) [3.9, 14.4] | 0.0% (0/104) | 100% |
| (ctl) direct_no_gateway | 76.9% (80/104) | 0.0% | 100% |
Figures: `figures/unauthorized_execution_rate.png`, `uer_by_category.png`, `security_vs_usability.png`.
Seed stability: 0 of 2260 action outcomes changed under seeds 1 and 2. A second run reproduced all deterministic CSVs byte-for-byte.

## Hypotheses
| H | Verdict | Evidence | Counterexamples / caveats |
|---|---|---|---|
| **H1** broad roles permit more unauthorized actions than contextual task-scoped grants | **Supported on this corpus** | 76.9% vs 11.5% (task_capability, external_policy); paired: broad vs restricted 44 vs 0 discordant (p=1.1e-13); restricted vs external_policy 28 vs 4 (p=1.9e-05). Gap concentrates in categories where static roles lack a mechanism: expiry, revocation, forged authority, multi-step payee abuse, confused deputy (`uer_by_category`). | The *carefully restricted* role is not a straw man: it blocks cross-tenant, cross-customer, read-only-task transfers and injection to other tenants (0%), but is 34.6% overall and costs 4 false denials (L08, a legitimate 1500.00 payment over its static 1000.00 cap). **task_capability and external_policy are indistinguishable here (0 discordant pairs)**; the corpus cannot separate them. **All intent-based strategies execute 100% of the in-policy residual cases (A21 inflated amount, A22 payee swap)**: scoping cannot see the gap between the user's request and the envelope. Percentages reflect scenario mix. |
| **H2** external policy reduces unauthorized execution but adds measurable latency and maintenance effort | **Partly supported; maintenance part not tested** | Reduction: see H1. Latency (local): gateway decision p50 2 us (timer resolution 1 us; direct = 0); allow-path end-to-end p50: external_policy 655 us [655, 656] vs direct 657 us [656, 658] vs broad_role 656 us, i.e. no distinguishable end-to-end overhead against ~650 us of MCP+SQLite+HMAC work. Gateway-denied calls are cheap (p50 12 us vs ~655 us) because the backend is never called. policy+approval escalation path p50 698 us [695, 702] (n=60). Real stdio-subprocess MCP read: 984 us [983, 986] (n=200). | In-process policy only: **a remote policy engine adds network RTT, which is not measured.** Maintenance proxy (`maintenance.csv`): for 3 change requests, restricted_role needed 1/2/1 config lines and session_scope 12/4/2; intent-based strategies needed **0 policy edits for CR1/CR2** because limits/task types live in per-task intent (**authoring cost not measured**) and CR3 (disable create_payee globally) was **not config-expressible** for them. Config edits had regression flips: CR2 on restricted_role fixed 4 false denials (L08) but let 4 in-policy-inflated transfers (A21) through (4 fixes / 4 regressions); CR3 fixed 4 attacks and broke 4 legitimate payee setups. Engineer time not measured. |
| **H3** approval can reduce dangerous actions, but fatigue increases false approvals | **Reduction: supported only for an idealised reviewer; fatigue: assumed, not tested** | policy_plus_approval 7.7% (8/104) vs external_policy 11.5% (12/104): the only difference is the A21 inflated-amount case (4 instances) blocked by the scripted reviewer; paired p=0.12 (not significant). With a **rubber-stamp** reviewer the benefit disappears: 11.5% (12/104). With an **always-reject** reviewer 15.4% (16/104) of authorized actions are not executed. Approval cannot override policy denial (tests). | A22 (payee swap, 300.00 < 500.00 threshold) is never escalated, so approval never sees it. Fatigue simulation (`sweep.csv`, synthetic): with 5% malicious escalations, base error 1% and slope 0.002/approval, malicious approvals rise from 5.8% (50 approvals/shift) to 19.8% (200) to 44.7% (1000), versus a flat ~1% with no fatigue slope; this follows from the assumed model and is **not evidence about human reviewers**. |
| **H4** delegation with attenuation prevents privilege expansion vs naive forwarding | **Supported (with a nuance)** | Expansion requests rejected: delegated_attenuation 12/12 [75.7, 100] vs 0/12 for every other strategy. Child unauthorized-execution rate in delegation scenarios: attenuation 0/16 vs forwarding (delegated_naive/external_policy) 4/16 vs broad_role and direct 16/16. Legitimate delegation completion 8/8 for all (no usability cost in this corpus). | For intent-based strategies forwarding never exceeded the *parent's* authority (expansion requests were ignored, not honoured); its harm is **over-privilege relative to the child's need** (A16: child delegated read-only, parent could pay -> forwarding executes the transfer). Paired external_policy vs attenuation: 4 vs 0 discordant, p=0.125 on 104 shared pairs. Only one over-privilege template exists. |
| **H5** structured audit improves deterministic reconstruction | **Supported as an existence proof; weak as a comparison** | Replay reproduced 2048/2048 recorded decisions (decision + reasons) with a valid hash chain. Tests detect field edits, deleted records, dropped fields, garbage lines, a changed decision with recomputed chain (caught by replay, not by the chain) and policy-config drift. | Replay re-runs the same policy code, so it cannot reveal a wrong policy. No unstructured-log comparison was run, so "improves" is **not measured comparatively**. Journal is tamper-evident, not tamper-proof. |

## Other measured observations
- **Defense in depth is narrow.** Layered condition (backend binds principal tenant and, for external policy, the amount): broad_role 76.9% -> 63.5% (66/104); direct 76.9% -> 67.3% (70/104). Backend blocks only tenant-crossing/malformed/over-limit; in-tenant abuse is untouched. Strong strategies are unchanged (gateway already blocks).
- **Fail-open vs fail-closed (policy outage, targeted):** fail-open executed 4/4 unauthorized proposals; fail-closed 0/4 but denied 4/4 authorized reads (availability cost, L10).
- **Ground-truth cross-check:** backend end-state diverges from the authorized-only oracle in exactly the runs with an executed unauthorized state change (e.g. external_policy 12/132 = A16, A21, A22; delegated_attenuation 8/132 = A21, A22).
- **Policy cost is small relative to transport:** CPU ~407-425 us/call for gateway strategies (depends on each workload's allow/deny mix; broad_role 589 us because its workload executes every call), 1.5-1.9 KB audit/call, peak traced memory 1.7-2.9 MB (`resources.csv`).
- p99 reported only where n >= 1000 (`latency_summary.csv`); approval-path and stdio samples report p50/p95 only.

## What this does not show
That real LLMs follow injected instructions at any rate; that approval helps real reviewers; that remote policy engines are cheap; that the
percentages generalise beyond this corpus; anything about engineer effort.
