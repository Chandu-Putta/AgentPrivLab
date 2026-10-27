"""Authorization gateway: the reference monitor on the tool-invocation path.

Responsibilities (enforcement point, PEP): authenticate the calling agent identity (assumed
provided by the transport), gather facts into a recorded `inputs` dict, call the pure policy
decision point, run the approval workflow, mint a short-lived signed backend assertion, call
the MCP tool server, and append a hash-chained audit record. Default deny on any error.
"""
from __future__ import annotations

import asyncio
import copy
import time
from dataclasses import dataclass, field
from typing import Any

from ..approval.service import ApprovalService
from ..approval.simulator import reviewer_decision
from ..audit.journal import AuditJournal
from ..banking.db import Database
from ..banking.service import parse_amount, sign_assertion
from ..clock import Clock
from ..delegation.attenuation import amplification, attenuate
from ..mcp_layer.client import McpBankingClient
from ..models import Decision
from ..policy.base import TOOL_PARAMS, gateway_precheck
from ..policy.registry import Strategy
from .canonicalize import canonical_json, request_hash, sha256_hex
from .capabilities import grant_hash, sign_grant, verify_grant


@dataclass
class AgentCtx:
    agent_id: str
    tenant: str
    customer_id: str
    on_behalf_of: str | None
    service: bool
    parent: str | None
    depth: int
    task_id: str
    task_type: str
    intent: dict[str, Any]
    lineage: list[str]
    role: str | None = None
    session: dict[str, Any] | None = None
    token: str | None = None
    grant_id: str | None = None
    revoked: bool = False


@dataclass
class InvokeResult:
    decision: str
    reasons: list[str]
    executed: bool
    outcome: str
    blocked_by: str  # none | gateway | backend | reviewer
    result: Any = None
    approval_id: str | None = None
    decision_us: int = 0
    total_us: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


def _norm_params(tool: str, params: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(params)


class Gateway:
    def __init__(self, strategy: Strategy, db: Database, client: McpBankingClient, clock: Clock,
                 journal: AuditJournal, *, assertion_key: bytes, grant_key: bytes, run_id: str,
                 trace_id: str, scenario_id: str, backend_defense: bool = False,
                 reviewer_mode: str = "scripted", backend_timeout_s: float = 5.0) -> None:
        self.backend_timeout_s = backend_timeout_s
        self.s, self.db, self.client, self.clock, self.journal = strategy, db, client, clock, journal
        self.akey, self.gkey = assertion_key, grant_key
        self.run_id, self.trace_id, self.scenario_id = run_id, trace_id, scenario_id
        self.backend_defense, self.reviewer_mode = backend_defense, reviewer_mode
        ttl = (strategy.approval or {}).get("ttl_s", 300)
        self.approvals = ApprovalService(clock, ttl)
        self.ctxs: dict[str, AgentCtx] = {}
        self.task_spent: dict[str, int] = {}
        self.revoked_grants: set[str] = set()
        self._n = 0
        self._grant_n = 0

    # ---- helpers ---------------------------------------------------------
    def now_ms(self) -> int:
        return int(self.clock.now() * 1000)

    def _dir(self, account_id: str) -> dict[str, Any]:
        with self.db.lock:
            r = self.db.conn.execute("SELECT tenant,customer_id FROM accounts WHERE id=?",
                                     (account_id,)).fetchone()
        if r is None:
            return {"account_id": account_id, "exists": False, "tenant": None, "customer_id": None}
        return {"account_id": account_id, "exists": True, "tenant": r["tenant"],
                "customer_id": r["customer_id"]}

    def _accounts_of(self, scope: str, tenant: str, customer: str) -> list[str]:
        q, a = (("SELECT id FROM accounts WHERE tenant=? ORDER BY id", (tenant,)) if scope == "tenant"
                else ("SELECT id FROM accounts WHERE customer_id=? ORDER BY id", (customer,)))
        with self.db.lock:
            return [r["id"] for r in self.db.conn.execute(q, a)]

    # ---- trusted onboarding ------------------------------------------------
    def normalize_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        it = dict(intent)
        mc = parse_amount(it.get("max_amount", "0.01")) if it.get("max_amount") else 0
        it["max_amount_cents"] = mc
        it["max_total_cents"] = parse_amount(it["max_total"]) if it.get("max_total") else mc
        it.setdefault("currency", "USD")
        it["tools"] = sorted(it.get("tools", []))
        it["accounts"] = sorted(it.get("accounts", []))
        it["destinations"] = sorted(it.get("destinations", []))
        it["exp_ms"] = self.now_ms() + int(it.get("valid_for_s", 1800)) * 1000
        it.pop("max_amount", None); it.pop("max_total", None)
        return it

    def start_task(self, actor: dict[str, Any], intent: dict[str, Any], task_id: str) -> str | None:
        """Trusted call by the human/orchestrator side. Returns the agent's grant token (or None)."""
        ctx = AgentCtx(agent_id=actor["agent_id"], tenant=actor["tenant"],
                       customer_id=actor["customer_id"], on_behalf_of=actor.get("on_behalf_of"),
                       service=bool(actor.get("service", False)), parent=None, depth=0,
                       task_id=task_id, task_type=intent["task_type"],
                       intent=self.normalize_intent(intent), lineage=[actor["agent_id"]])
        self._issue_material(ctx)
        self.ctxs[ctx.agent_id] = ctx
        return ctx.token

    def _issue_material(self, ctx: AgentCtx) -> None:
        k, cfg = self.s.kind, self.s.config
        if k == "restricted_role":
            ctx.role = cfg["task_type_roles"].get(ctx.task_type)
        elif k == "session_scope":
            t = cfg["session_templates"].get(ctx.task_type)
            if t:
                ctx.session = {
                    "tools": sorted(t["tools"]),
                    "accounts": self._accounts_of(t["scope"], ctx.tenant, ctx.customer_id),
                    "exp_ms": self.now_ms() + t["ttl_s"] * 1000,
                    "max_amount_cents": t["max_amount_cents"], "budget_cents": t["budget_cents"],
                    "destination_scope": t["destination_scope"], "closed": False}
        elif k == "task_capability":
            self._grant_n += 1
            it = ctx.intent
            claims = {"grant_id": f"{self.trace_id}-g{self._grant_n}", "principal": ctx.agent_id,
                      "tenant": ctx.tenant, "tools": it["tools"], "accounts": it["accounts"],
                      "destinations": it["destinations"], "max_amount_cents": it["max_amount_cents"],
                      "currency": it["currency"], "exp_ms": it["exp_ms"], "depth": ctx.depth,
                      "max_depth": self.s.max_depth, "task_id": ctx.task_id}
            ctx.grant_id, ctx.token = claims["grant_id"], sign_grant(self.gkey, claims)

    def revoke_task(self, task_id: str) -> None:
        for c in self.ctxs.values():
            if c.task_id == task_id:
                c.revoked = True
                if c.session:
                    c.session["closed"] = True
                if c.grant_id:
                    self.revoked_grants.add(c.grant_id)

    # ---- inputs ------------------------------------------------------------
    def _resources(self, tool: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        if tool == "transfer_funds":
            ids = [params.get("source_id"), params.get("destination_id")]
        else:
            ids = [params.get("account_id")]
        return [self._dir(str(i)) for i in ids if isinstance(i, str)]

    def _inputs(self, ctx: AgentCtx | None, agent_id: str, tool: str, params: dict[str, Any],
                token: str | None, approval: dict | None) -> dict[str, Any]:
        shown = params
        if tool == "update_contact" and isinstance(params.get("contact"), dict):
            shown = {**params, "contact": {k: "<redacted>" for k in params["contact"]}}
        inp: dict[str, Any] = {"registered": ctx is not None, "tool": tool, "params": shown,
                               "agent_id": agent_id, "now_ms": self.now_ms()}
        if ctx is None:
            return inp
        inp.update({"tenant": ctx.tenant, "customer_id": ctx.customer_id,
                    "on_behalf_of": ctx.on_behalf_of, "service": ctx.service,
                    "parent_agent_id": ctx.parent, "depth": ctx.depth, "task_type": ctx.task_type,
                    "resources": self._resources(tool, params) if isinstance(params, dict) else [],
                    "state": {"spent_cents": self.task_spent.get(ctx.task_id, 0)},
                    "role": ctx.role, "session": ctx.session, "intent": None, "grant": None,
                    "approval": approval})
        if self.s.kind == "external":
            inp["intent"] = {**ctx.intent, "revoked": ctx.revoked}
        if self.s.kind == "task_capability":
            inp["grant"] = verify_grant(self.gkey, token, principal=ctx.agent_id, tenant=ctx.tenant,
                                        now_ms=self.now_ms(), revoked=self.revoked_grants)
        if tool == "delegate_task" and isinstance(params.get("requested_scopes"), dict):
            child = str(params.get("child_agent_id"))
            inp["delegation"] = {
                "mode": self.s.delegation_mode, "child_exists": child in self.ctxs,
                "amplified_dims": amplification(ctx.intent, params["requested_scopes"])}
        return inp

    # ---- audit --------------------------------------------------------------
    def _audit(self, ctx: AgentCtx | None, agent_id: str, tool: str, params: Any, inputs: dict,
               rh: str | None, decision: str, reasons: list[str], pid: str, pver: str,
               approval: dict | None, outcome: str, side_effect: str | None, total_us: int,
               token: str | None, policy_hash: str | None = None) -> None:
        self._n += 1
        res = [r["account_id"] for r in inputs.get("resources", [])]
        self.journal.append(
            ts=self.now_ms(), run_id=self.run_id, trace_id=self.trace_id,
            scenario_id=self.scenario_id, agent_id=agent_id,
            parent_agent_id=ctx.parent if ctx else None, tenant=ctx.tenant if ctx else None,
            task_id=ctx.task_id if ctx else None,
            grant_id=ctx.grant_id if ctx else None,
            grant_hash=grant_hash(token) if token else None, tool=tool, resource_ids=res,
            params_hash=sha256_hex(canonical_json(inputs.get("params", {}))), request_hash=rh,
            policy_id=pid, policy_version=pver, policy_hash=policy_hash or self.s.policy_hash,
            policy_inputs=inputs, decision=decision, reasons=reasons,
            approval_id=(approval or {}).get("approval_id"),
            approval_status=(approval or {}).get("status"),
            approval_bound_hash=(approval or {}).get("bound_hash"),
            delegation_lineage=list(ctx.lineage) if ctx else [], outcome=outcome,
            side_effect_ref=side_effect, latency_us=total_us,
            correlation_id=f"{self.trace_id}:{self._n}")

    # ---- backend call -------------------------------------------------------
    async def _call_backend(self, ctx: AgentCtx | None, tool: str, params: dict[str, Any], rh: str,
                            resources: list[dict]) -> dict[str, Any]:
        self._n += 1
        ids = [r["account_id"] for r in resources]
        tenant = (ctx.tenant if (ctx and self.backend_defense)
                  else next((r["tenant"] for r in resources if r["exists"]), "none"))
        claims: dict[str, Any] = {
            "tool": tool, "request_hash": rh, "exp_ms": self.now_ms() + 30_000, "accounts": ids,
            "tenant": tenant, "nonce": f"{self.run_id}/{self.trace_id}/{self._n}",
            "allow_cross_tenant_destination": not self.backend_defense}
        if self.backend_defense and ctx and self.s.kind == "external":
            claims["max_amount_cents"] = ctx.intent["max_amount_cents"]
        mcp_params = dict(params)
        if tool == "transfer_funds" and "amount" in params:
            mcp_params["amount"] = str(params["amount"])
        try:
            return await asyncio.wait_for(
                self.client.call(tool, mcp_params, rh, sign_assertion(self.akey, claims)),
                self.backend_timeout_s)
        except TimeoutError:  # outcome unknown: report failure, never retry blindly (use idempotency key)
            return {"ok": False, "error": "backend_timeout"}
        except Exception as e:  # MCP validation / transport error: fail closed
            return {"ok": False, "error": f"mcp_error:{type(e).__name__}"}

    # ---- public API ----------------------------------------------------------
    async def request_approval(self, agent_id: str, tool: str, params: dict[str, Any],
                               scripted: str | None = "approve") -> InvokeResult:
        """Agent asks for approval of an exact action without executing it."""
        return await self.invoke(agent_id, tool, params, scripted_reviewer=scripted, dry_approval=True)

    async def invoke(self, agent_id: str, tool: str, params: dict[str, Any], *,
                     grant_token: str | None = None, approval_id: str | None = None,
                     scripted_reviewer: str | None = None, fault: str | None = None,
                     dry_approval: bool = False) -> InvokeResult:
        t0 = time.perf_counter_ns()
        ctx = self.ctxs.get(agent_id)
        try:
            rh_params = copy.deepcopy(params)
            canonical_json(rh_params)
            canonical_ok = True
        except Exception:
            rh_params, canonical_ok = {"_non_canonical": True}, False
        if self.s.bypass_gateway:
            return await self._direct(ctx, tool, rh_params, t0)
        rh = None
        if ctx is not None and canonical_ok and isinstance(tool, str):
            rh = request_hash(tool, rh_params, ctx.tenant, ctx.agent_id)
        appr = (self.approvals.validate(approval_id, rh or "")
                if (self.s.approval and approval_id) else None)
        inputs = self._inputs(ctx, agent_id, tool, rh_params, grant_token, appr)
        t_dec = time.perf_counter_ns()
        pre = gateway_precheck(inputs)
        if pre is not None:
            res, pid, pver, phash = pre, "gateway", "1", None
        else:
            res, pid, pver, phash = None, self.s.policy.policy_id, self.s.policy.version, None
            if fault == "policy_unavailable" and self.s.kind == "external":
                from ..models import PolicyResult
                allow_ = self.s.fail_mode == "open"
                res = PolicyResult(decision=Decision.ALLOW if allow_ else Decision.DENY,
                                   reasons=("policy_unavailable",) + (("fail_open",) if allow_ else ()),
                                   policy_id=pid, policy_version=pver)
            else:
                try:
                    res = self.s.policy.evaluate(inputs)
                except Exception as e:  # fail closed on any policy error
                    from ..models import PolicyResult
                    res = PolicyResult(decision=Decision.DENY, reasons=("policy_error", type(e).__name__),
                                       policy_id=pid, policy_version=pver)
        decision_us = (time.perf_counter_ns() - t_dec) // 1000
        reasons = list(res.reasons)

        def done(executed: bool, outcome: str, blocked: str, result: Any = None,
                 apr: dict | None = None, side: str | None = None, extra: dict | None = None):
            total = (time.perf_counter_ns() - t0) // 1000
            self._audit(ctx, agent_id, tool if isinstance(tool, str) else "?", rh_params, inputs, rh,
                        res.decision.value, reasons, res.policy_id, res.policy_version, apr, outcome,
                        side, total, grant_token, phash)
            return InvokeResult(res.decision.value, reasons, executed, outcome, blocked, result,
                                (apr or {}).get("approval_id"), decision_us, total, extra or {})

        if res.decision == Decision.DENY:
            return done(False, "denied", "gateway")
        apr_rec: dict | None = None
        if res.decision == Decision.ESCALATE:
            if not self.s.approval:
                return done(False, "denied_escalation_unavailable", "gateway")
            ok = reviewer_decision(self.reviewer_mode, scripted_reviewer)
            a = self.approvals.record(rh or "", "reviewer-sim", ok)
            apr_rec = {"approval_id": a.approval_id, "status": a.status, "bound_hash": a.request_hash}
            if not ok:
                return done(False, "approval_rejected", "reviewer", apr=apr_rec)
            if dry_approval:
                return done(False, "approval_issued", "none", apr=apr_rec)
            # re-evaluate with the now-valid approval (policy remains the authority)
            inputs2 = self._inputs(ctx, agent_id, tool, rh_params, grant_token,
                                   self.approvals.validate(a.approval_id, rh or ""))
            res2 = self.s.policy.evaluate(inputs2)
            if res2.decision != Decision.ALLOW:
                reasons = list(res2.reasons)
                return done(False, "denied_after_approval", "gateway", apr=apr_rec)
            self.approvals.consume(a.approval_id)
        elif appr and appr["valid"]:
            self.approvals.consume(approval_id)  # type: ignore[arg-type]
            apr_rec = {"approval_id": approval_id, "status": "approved", "bound_hash": appr["bound_hash"]}
        elif dry_approval:
            return done(False, "approval_not_required", "none")
        # ---- allowed: execute -------------------------------------------------
        if tool == "delegate_task":
            return self._do_delegate(ctx, params, done, apr_rec)
        out = await self._call_backend(ctx, tool, rh_params, rh or "", inputs["resources"])
        if not out.get("ok"):
            return done(False, f"backend_error:{out.get('error')}", "backend", apr=apr_rec)
        side = None
        if tool == "transfer_funds":
            self.task_spent[ctx.task_id] = self.task_spent.get(ctx.task_id, 0) + parse_amount(params["amount"])
            side = f"transfer:{params['idempotency_key']}"
        elif tool in ("update_contact", "create_payee", "export_statement"):
            side = f"{tool}:{rh[:12]}"
        return done(True, "approved_executed" if res.decision == Decision.ESCALATE else "executed",
                    "none", out["result"], apr_rec, side)

    def _do_delegate(self, ctx: AgentCtx, params: dict[str, Any], done, apr_rec):
        req = params["requested_scopes"]
        amp = amplification(ctx.intent, req)
        mode = self.s.delegation_mode
        child_intent = attenuate(ctx.intent, req) if mode == "attenuate" else copy.deepcopy(ctx.intent)
        cid = params["child_agent_id"]
        child = AgentCtx(agent_id=cid, tenant=ctx.tenant, customer_id=ctx.customer_id,
                         on_behalf_of=ctx.on_behalf_of, service=ctx.service, parent=ctx.agent_id,
                         depth=ctx.depth + 1, task_id=ctx.task_id, task_type=ctx.task_type,
                         intent=child_intent, lineage=ctx.lineage + [cid])
        self._issue_material(child)
        child.revoked = ctx.revoked
        self.ctxs[cid] = child
        return done(True, "delegated", "none", {"child_agent_id": cid, "token": child.token}, apr_rec,
                    f"delegate:{cid}", {"amplified_dims": amp, "child_token": child.token})

    async def _direct(self, ctx: AgentCtx | None, tool: str, params: dict, t0: int) -> InvokeResult:
        """Control: no gateway. The agent's own broad credential reaches the tool server."""
        if tool == "delegate_task":  # no gateway: the child simply reuses the same credential
            return InvokeResult("allow", ["no_enforcement"], True, "delegated", "none",
                                extra={"amplified_dims": amplification(ctx.intent, params["requested_scopes"])
                                       if ctx and isinstance(params.get("requested_scopes"), dict) else []})
        if not isinstance(params, dict):
            return InvokeResult("allow", ["no_enforcement"], False, "unsupported", "backend")
        try:
            res = self._resources(tool, params)
            rh = request_hash(tool, params, "svc", "svc")
            out = await self._call_backend(None, tool, params, rh, res)
        except Exception as e:  # malformed input reaching the tool server directly
            out = {"ok": False, "error": f"client_error:{type(e).__name__}"}
        total = (time.perf_counter_ns() - t0) // 1000
        if out.get("ok"):
            if tool == "transfer_funds":
                pass
            return InvokeResult("allow", ["no_enforcement"], True, "executed", "none", out["result"],
                                total_us=total)
        return InvokeResult("allow", ["no_enforcement"], False, f"backend_error:{out.get('error')}",
                            "backend", total_us=total)


TOOLS = tuple(TOOL_PARAMS)
