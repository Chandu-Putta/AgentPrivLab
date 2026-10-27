# Assumptions and design decisions

| # | Decision | Reason / consequence |
|---|---|---|
| 1 | Policies are pure functions of a recorded `inputs` dict; the gateway gathers clock, grant verification, session/intent state, resource owners, approval validity. | Enables independent audit replay. Cost: crypto checks happen in the PEP, so replay trusts the recorded verification result. |
| 2 | `delegate_task` is a gateway-native control-plane tool, not exposed on the MCP server. | Delegation mints authority; it must not be a backend operation. |
| 3 | Delegation: child intent = intersection(parent, request, ceiling); any request exceeding the parent is denied (not clipped); omitted dimensions mean none. | Explicit least-privilege semantics; avoids silent clipping hiding attacks. |
| 4 | Credential forwarding (control) gives the child the parent's full authority, ignoring requested scopes. | Models the common shortcut. It never exceeds the parent, but exceeds the child's need. |
| 5 | Approval can only upgrade ESCALATE to ALLOW; it never overrides DENY; approvals are bound to the canonical request hash, expire (300 s) and are single use. | Spec: approval is not a substitute for policy. |
| 6 | Reviewer behaviour is scripted/idealised, rubber-stamp or always-reject; fatigue is a parametric simulation. | Sensitivity analysis only. |
| 7 | `primary` gives the backend the resource's own tenant so the backend cannot mask policy differences; `layered` adds principal-tenant and limit binding. | Isolates policy effect, then shows defense in depth. |
| 8 | Money: `Decimal`/string, floats rejected; amounts are integer cents; <=2 dp; currencies USD/EUR; idempotency key mandatory; one atomic `BEGIN IMMEDIATE` transaction per transfer. | Spec requirements. Idempotent replay with different params is a conflict. |
| 9 | Expiry uses integer milliseconds from an injected clock (canonical form forbids floats). | Deterministic tests. |
| 10 | Policy-engine outage is injected per action; applies only to strategies with an external engine (in-process static roles/sessions/grants have no remote dependency). | Documented in scenario `applies_to`. |
| 11 | Backend call timeout 5 s -> `backend_timeout`, no blind retry (use the idempotency key); outcome of the call is unknown. | Fail closed. |
| 12 | `direct_no_gateway` is an allow-all control with a broad service credential (no audit, no policy). | Unmediated baseline. Equals `broad_role` on policy outcomes by construction; differs in audit/latency only. |
| 13 | The audit journal stores `policy_inputs` (redacting contact values) so decisions can be replayed. | Minimises PII; params are hashed separately. |
| 14 | Argparse CLI instead of Typer. | Fewer dependencies. |
