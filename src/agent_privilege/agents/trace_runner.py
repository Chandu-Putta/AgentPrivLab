"""Seeded, deterministic agent action-trace runner.

This is NOT an LLM. It replays scripted tool-call proposals (benign or malicious) against a
gateway. A malicious proposal measures whether *enforcement* blocks it; it says nothing about
how likely a real LLM is to emit that proposal.
"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field

from ..evaluation.env import Env
from ..evaluation.oracle import oracle_state
from ..policy.registry import Strategy
from ..scenarios import Instance

logging.getLogger("mcp").setLevel(logging.WARNING)


@dataclass
class ActionRow:
    instance_id: str
    scenario_id: str
    category: str
    kind: str
    severity: str
    strategy: str
    step: str
    agent: str
    tool: str
    origin: str
    expected: str
    decision: str
    outcome: str
    executed: bool
    blocked_by: str
    reasons: str
    expansion: bool
    amplified: bool
    decision_us: int
    total_us: int
    approval_id: str | None = None


@dataclass
class InstanceResult:
    rows: list[ActionRow] = field(default_factory=list)
    state_divergence: bool = False


def _tamper(token: str) -> str:
    body, mac = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["max_amount_cents"] = 10**9
    claims["destinations"] = sorted(set(claims["destinations"]) | {"acct_a3", "acct_b3"})
    nb = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    return nb.decode().rstrip("=") + "." + mac


async def run_instance(env: Env, strategy: Strategy, inst: Instance, *, run_id: str,
                       backend_defense: bool, reviewer_mode: str,
                       check_state: bool = True) -> InstanceResult:
    sc = inst.scenario
    env.seed_value = inst.seed
    env.reset()
    trace = f"{inst.instance_id}|{strategy.name}"
    gw = env.gateway(strategy, trace_id=trace, scenario_id=sc.id, run_id=run_id,
                     backend_defense=backend_defense, reviewer_mode=reviewer_mode)
    actor = sc.actor
    intent = {**sc.trusted_context["intent"]}
    tokens: dict[str, str | None] = {actor["agent_id"]: gw.start_task(actor, intent, trace)}
    approvals: dict[str, str | None] = {}
    out = InstanceResult()
    for a in sc.actions:
        if a.advance_clock_s:
            env.clock.advance(a.advance_clock_s)
        if a.type == "event":
            if a.event == "revoke_task":
                gw.revoke_task(trace)
            continue
        agent = a.agent or actor["agent_id"]
        params = json.loads(json.dumps(a.params))
        no_idem = isinstance(params, dict) and bool(params.pop("_no_idem", False))
        if a.tool == "transfer_funds" and isinstance(params, dict) and "idempotency_key" not in params \
                and not no_idem:
            params["idempotency_key"] = f"{trace}-{a.id}"
        tok = tokens.get(agent)
        if a.grant_mode == "none":
            tok = None
        elif a.grant_mode == "tampered" and tok:
            tok = _tamper(tok)
        appr = approvals.get(a.approval_from) if a.approval_from else None
        if a.type == "request_approval":
            r = await gw.request_approval(agent, a.tool, params, a.reviewer or "approve")
            approvals[a.id] = r.approval_id
            continue
        r = await gw.invoke(agent, a.tool, params, grant_token=tok, approval_id=appr,
                            scripted_reviewer=a.reviewer or "approve", fault=a.fault)
        approvals[a.id] = r.approval_id
        if a.tool == "delegate_task" and r.executed:
            tokens[params["child_agent_id"]] = r.extra.get("child_token")
        out.rows.append(ActionRow(
            instance_id=inst.instance_id, scenario_id=sc.id, category=sc.category, kind=sc.kind,
            severity=sc.severity if sc.expected_authorization[a.id] == "unauthorized" else "none",
            strategy=strategy.name, step=a.id, agent=agent, tool=str(a.tool), origin=a.origin,
            expected=sc.expected_authorization[a.id], decision=r.decision, outcome=r.outcome,
            executed=r.executed, blocked_by=r.blocked_by, reasons="|".join(r.reasons),
            expansion=a.expansion, amplified=bool(r.extra.get("amplified_dims")),
            decision_us=r.decision_us, total_us=r.total_us, approval_id=r.approval_id))
    if check_state:
        got = env.db.snapshot()
        out.state_divergence = got != oracle_state(env, inst, trace)
    return out
