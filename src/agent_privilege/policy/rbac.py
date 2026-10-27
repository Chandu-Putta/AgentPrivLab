"""Static role baselines: `broad_role` (intentionally permissive) and `restricted_role`
(hand-written least-privilege static roles). Neither sees task intent, expiry or revocation."""
from __future__ import annotations

from typing import Any

from ..models import PolicyResult
from .base import allow, amount_cents, deny


class BroadRole:
    """One fixed 'agent_full' role: every tool, every account, every tenant, no limits.
    Models a service-wide integration role granted so the agent 'just works'."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.policy_id, self.version = config["id"], str(config["version"])
        self.tools = set(config["role"]["tools"])

    def evaluate(self, i: dict[str, Any]) -> PolicyResult:
        if i["tool"] not in self.tools:
            return deny(self.policy_id, self.version, "tool_not_in_role")
        return allow(self.policy_id, self.version, "broad_role_allows")


class RestrictedRole:
    """Per-task-type static roles. Knows tenant, customer ownership and a fixed amount cap,
    but cannot bind to a specific payee, task amount, expiry or revocation."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.policy_id, self.version = config["id"], str(config["version"])
        self.roles = config["roles"]
        self.map = config["task_type_roles"]

    def evaluate(self, i: dict[str, Any]) -> PolicyResult:
        P, V = self.policy_id, self.version
        role = self.roles.get(i.get("role") or "")
        if role is None:
            return deny(P, V, "no_role_for_task_type")
        if i["tool"] not in role["tools"]:
            return deny(P, V, "tool_not_in_role")
        scope = role["scope"]
        for r in i["resources"]:
            if not r["exists"]:
                return deny(P, V, "unknown_resource")
            if r["tenant"] != i["tenant"]:
                return deny(P, V, "cross_tenant")
        p = i["params"]
        if i["tool"] == "delegate_task":
            return allow(P, V, "role_allows_delegation")
        if i["tool"] == "transfer_funds":
            src, dst = i["resources"][0], i["resources"][1]
            if scope == "own_customer" and src["customer_id"] != i["customer_id"]:
                return deny(P, V, "not_owner")
            if dst["tenant"] != i["tenant"]:
                return deny(P, V, "cross_tenant_destination")
            a = amount_cents(i)
            if a is None:
                return deny(P, V, "invalid_amount")
            if a > role["max_amount_cents"]:
                return deny(P, V, "over_role_limit")
            return allow(P, V, "role_allows")
        for r in i["resources"]:
            if scope == "own_customer" and r["customer_id"] != i["customer_id"]:
                return deny(P, V, "not_owner")
        _ = p
        return allow(P, V, "role_allows")
