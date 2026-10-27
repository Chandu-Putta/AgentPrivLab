"""Task-bound capability grant checks. Signature/expiry/revocation/principal binding were
verified by the gateway into inputs['grant']; this checks claims against the exact action."""
from __future__ import annotations

from typing import Any

from ..models import PolicyResult
from .base import allow, amount_cents, deny


class TaskCapability:
    def __init__(self, config: dict[str, Any]) -> None:
        self.policy_id, self.version = config["id"], str(config["version"])

    def evaluate(self, i: dict[str, Any]) -> PolicyResult:
        P, V = self.policy_id, self.version
        g = i.get("grant")
        if not g or not g["valid"]:
            return deny(P, V, "grant_invalid", (g or {}).get("reason", "no_grant"))
        c = g["claims"]
        if i["tool"] not in c["tools"]:
            return deny(P, V, "tool_not_in_grant")
        if c["tenant"] != i["tenant"]:
            return deny(P, V, "tenant_mismatch")
        for r in i["resources"]:
            if not r["exists"]:
                return deny(P, V, "unknown_resource")
            if r["tenant"] != c["tenant"]:
                return deny(P, V, "cross_tenant")
        p = i["params"]
        t = i["tool"]
        if t == "delegate_task":
            if c["depth"] + 1 > c["max_depth"]:
                return deny(P, V, "delegation_depth_exceeded")
            return allow(P, V, "grant_allows")
        if t == "transfer_funds":
            if p["source_id"] not in c["accounts"]:
                return deny(P, V, "source_not_in_grant")
            if p["destination_id"] not in c["destinations"]:
                return deny(P, V, "destination_not_in_grant")
            a = amount_cents(i)
            if a is None:
                return deny(P, V, "invalid_amount")
            if a > c["max_amount_cents"]:
                return deny(P, V, "over_grant_limit")
            if p["currency"] != c["currency"]:
                return deny(P, V, "currency_not_in_grant")
        elif t == "create_payee":
            if p["account_id"] not in c["accounts"] or p["payee_id"] not in c["destinations"]:
                return deny(P, V, "payee_not_in_grant")
        else:
            if p["account_id"] not in c["accounts"]:
                return deny(P, V, "account_not_in_grant")
        return allow(P, V, "grant_allows")
