# Threat model and trust boundaries

```
 untrusted content (memos, docs, tool output) ──► agent (scripted trace / optional LLM)   [UNTRUSTED PROPOSER]
                                                     │ tool-call proposal (+ opaque grant token / approval id)
 ══════════════════════════ trust boundary 1 (agent ↔ gateway) ══════════════════════════
                         gateway (PEP): identity lookup → inputs → pure policy (PDP) → approval → audit
                                                     │ short-lived HMAC assertion bound to request hash (+ tenant/accounts/nonce/limit)
 ══════════════════════════ trust boundary 2 (gateway ↔ tool server) ═══════════════════
                         MCP banking server → banking service (verifies assertion independently) → SQLite
```
## Assets
Synthetic account balances, transaction history, statement exports, payee lists, contact data; integrity of the audit journal.

## Adversaries modelled (as scripted proposals only)
- A1 prompt-injected or manipulated agent proposing arbitrary tool calls with arbitrary parameters.
- A2 agent that edits its own grant token, replays/modifies/expires approvals, or reuses stale/revoked authority.
- A3 compromised or over-scoped child agent in a delegation chain.
- A4 confused deputy: a service identity with broad rights steered to another customer's data.
- A5 failing infrastructure: policy engine outage (fail-closed vs fail-open), backend timeout.
- A6 audit tamperer who edits, deletes, or (with chain recomputation) rewrites decisions in the journal.

## Trust assumptions (what each strategy relies on; also in `configs/strategies/*.yaml`)
- Caller identity (`agent_id`) is authenticated by the transport. Not implemented here (the gateway looks the id up in a registry).
- The **task intent** is supplied by a trusted party (the user/orchestrator), never derived from model output or content.
- Gateway process holds the assertion and grant keys; the agent package holds none (`tests/security/test_boundaries.py` checks this statically).
- The backend independently verifies assertions (signature, tool, request hash, expiry, single-use nonce, account list, tenant, amount cap).
  It cannot re-evaluate full policy (no task intent), so it is a **backstop for tenant/account/limit claims**, not a second policy engine.
- Clocks are trustworthy (injected `FakeClock` in tests).

## Out of scope / not defended
Compromised gateway or key theft; side channels; DoS; real network/IAM; correct human review (simulated only); semantic
attacks inside the intent envelope (A21/A22 show these pass every intent-based policy); audit rewrite by an attacker who also
holds the ability to re-anchor the chain (journal is **tamper-evident, not tamper-proof**; anchor the head hash externally).
