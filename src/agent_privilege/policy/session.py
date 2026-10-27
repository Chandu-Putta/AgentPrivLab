"""Session-scoped permissions: tool set, account set, expiry, per-call cap and a total budget
fixed when the session opens (from a per-task-type template), closed on revocation."""
from __future__ import annotations

from typing import Any

from ..models import PolicyResult
from .base import allow, amount_cents, deny


class SessionScope:
    def __init__(self, config: dict[str, Any]) -> None:
        self.policy_id, self.version = config["id"], str(config["version"])
        self.templates = config["session_templates"]

    def evaluate(self, i: dict[str, Any]) -> PolicyResult:
        P, V = self.policy_id, self.version
        s = i.get("session")
        if not s:
            return deny(P, V, "no_session")
        if s["closed"]:
            return deny(P, V, "session_closed")
        if i["now_ms"] > s["exp_ms"]:
            return deny(P, V, "session_expired")
        if i["tool"] not in s["tools"]:
            return deny(P, V, "tool_not_in_session")
        for r in i["resources"]:
            if not r["exists"]:
                return deny(P, V, "unknown_resource")
            if r["tenant"] != i["tenant"]:
                return deny(P, V, "cross_tenant")
            if r["account_id"] not in s["accounts"] and not (
                    i["tool"] == "transfer_funds" and r["account_id"] == i["params"]["destination_id"]
                    and s["destination_scope"] == "tenant"):
                return deny(P, V, "account_not_in_session")
        if i["tool"] == "transfer_funds":
            a = amount_cents(i)
            if a is None:
                return deny(P, V, "invalid_amount")
            if a > s["max_amount_cents"]:
                return deny(P, V, "over_session_limit")
            if i["state"]["spent_cents"] + a > s["budget_cents"]:
                return deny(P, V, "session_budget_exhausted")
        return allow(P, V, "session_allows")
