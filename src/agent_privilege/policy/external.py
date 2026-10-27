"""External per-call contextual policy engine. Evaluated independently of the agent at every
tool call against the *trusted* task intent (not tokens), live state and org rules.
With `approval` configured it returns ESCALATE for in-policy high-impact actions; it never
lets approval override a DENY."""
from __future__ import annotations

from typing import Any

from ..models import PolicyResult
from .base import allow, amount_cents, deny, escalate


class ExternalPolicy:
    def __init__(self, config: dict[str, Any]) -> None:
        self.policy_id, self.version = config["id"], str(config["version"])
        self.rules = config["rules"]
        self.approval = config.get("approval") or {}
        self.max_depth = int(config.get("delegation", {}).get("max_depth", 2))

    def _needs_approval(self, i: dict[str, Any]) -> bool:
        a = self.approval
        if not a:
            return False
        if i["tool"] == "export_statement" and a.get("export_statement_always"):
            return True
        if i["tool"] == "transfer_funds":
            c = amount_cents(i)
            return c is not None and c > int(a.get("transfer_above_cents", 10**15))
        return False

    def evaluate(self, i: dict[str, Any]) -> PolicyResult:
        P, V = self.policy_id, self.version
        it = i.get("intent")
        if not it:
            return deny(P, V, "no_task_intent")
        if it["revoked"]:
            return deny(P, V, "task_revoked")
        if i["now_ms"] > it["exp_ms"]:
            return deny(P, V, "task_expired")
        t, p = i["tool"], i["params"]
        if t not in it["tools"]:
            return deny(P, V, "tool_not_in_task")
        eff = i.get("on_behalf_of") or i["customer_id"]
        for r in i["resources"]:
            if not r["exists"]:
                return deny(P, V, "unknown_resource")
            if self.rules.get("tenant_isolation", True) and r["tenant"] != i["tenant"]:
                return deny(P, V, "cross_tenant")
        if t == "delegate_task":
            if i["depth"] + 1 > self.max_depth:
                return deny(P, V, "delegation_depth_exceeded")
            d = i["delegation"]
            if d["mode"] == "attenuate" and d["amplified_dims"]:
                return deny(P, V, "delegation_amplification", *d["amplified_dims"])
            return allow(P, V, "policy_allows")
        if t == "transfer_funds":
            if p["source_id"] not in it["accounts"]:
                return deny(P, V, "source_not_in_task")
            if self.rules.get("ownership", True) and i["resources"][0]["customer_id"] != eff:
                return deny(P, V, "not_owner")
            if p["destination_id"] not in it["destinations"]:
                return deny(P, V, "destination_not_in_task")
            a = amount_cents(i)
            if a is None:
                return deny(P, V, "invalid_amount")
            if a > it["max_amount_cents"]:
                return deny(P, V, "over_task_limit")
            if i["state"]["spent_cents"] + a > it["max_total_cents"]:
                return deny(P, V, "over_task_total")
            if p["currency"] != it["currency"]:
                return deny(P, V, "currency_not_in_task")
        elif t == "create_payee":
            if p["account_id"] not in it["accounts"] or p["payee_id"] not in it["destinations"]:
                return deny(P, V, "payee_not_in_task")
        else:
            if p["account_id"] not in it["accounts"]:
                return deny(P, V, "account_not_in_task")
            if self.rules.get("ownership", True) and i["resources"][0]["customer_id"] != eff:
                return deny(P, V, "not_owner")
        if self._needs_approval(i):
            ap = i.get("approval")
            if ap and ap["presented"]:
                if ap["valid"]:
                    return allow(P, V, "approved")
                return deny(P, V, "approval_invalid", ap["reason"])
            return escalate(P, V, "approval_required")
        return allow(P, V, "policy_allows")
