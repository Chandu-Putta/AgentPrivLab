# Limitations (read before citing any number)

1. **Scripted traces, not LLMs.** Results measure enforcement against fixed proposals. They do not estimate how often a deployed model is
   tricked by prompt injection, nor how often it emits any given call. The optional LLM adapter is an unimplemented interface; no LLM experiment was run.
2. **Scenario authorship.** One author wrote strategies, scenarios and ground truth. Strategies get only attacks the author imagined; the corpus
   largely encodes which mechanism each strategy lacks. UER percentages depend on scenario mix and are **not prevalence estimates**.
3. **Small, correlated sample.** 35 templates -> 156 instances (account/tenant permutations). Instances are near-duplicates, so Wilson intervals
   treat correlated trials as independent and are **optimistic**; effective sample size is closer to the template count. Paired McNemar p-values share this problem.
4. **Non-adaptive adversary.** A malicious step proceeds even if earlier steps were blocked; no adaptive attacker.
5. **Simulated approval.** Reviewer models are synthetic. The fatigue curve is the assumed model, not evidence about people.
6. **Local timing only.** In-process policy and in-memory MCP transport (plus a 200-call stdio-subprocess sample). No network hop to a remote policy engine,
   no enterprise IAM, no TLS, no contention. Decision timer resolution is 1 us. CPU/call depends on the allow/deny mix of each strategy's workload.
7. **Maintenance is a proxy.** Config lines and regression flips for three change requests; per-task intent authoring effort (where intent-based strategies
   move the cost) and engineer time were **not measured**.
8. **Replay is partly tautological** for logic bugs: it re-runs the same policy code on the recorded inputs. It detects tampering and drift, not wrong policies.
9. **Backend backstop is narrow** (tenant/account/limit/replay). It cannot catch in-tenant semantic abuse.
10. Identity authentication, key management/rotation, and real revocation distribution are simulated or absent.
11. Single machine, Python 3.12.15, one platform; no cross-platform runs. SQLite single connection serialises transfers; this is not a scalability test.
