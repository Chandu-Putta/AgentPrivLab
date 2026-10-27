"""Policy decision points are PURE functions of a recorded `inputs` dict + config.

All dynamic facts (clock, grant verification result, session state, resource owners,
approval validity, spend so far) are gathered by the gateway (the enforcement point) and
placed in `inputs`. That is what lets `replay-audit` reproduce decisions independently.
"""
from __future__ import annotations

from typing import Any, Protocol

from ..banking.service import BackendError, parse_amount
from ..gateway.canonicalize import canonical_json, sha256_hex
from ..models import Decision, PolicyResult

TOOL_PARAMS: dict[str, dict[str, tuple[type, ...]]] = {
    "get_account": {"account_id": (str,)},
    "list_transactions": {"account_id": (str,)},
    "export_statement": {"account_id": (str,)},
    "update_contact": {"account_id": (str,), "contact": (dict,)},
    "create_payee": {"account_id": (str,), "payee_id": (str,)},
    "transfer_funds": {"source_id": (str,), "destination_id": (str,), "amount": (str, int),
                       "currency": (str,), "idempotency_key": (str,)},
    "delegate_task": {"child_agent_id": (str,), "requested_scopes": (dict,)},
}


class Policy(Protocol):
    policy_id: str
    version: str

    def evaluate(self, inputs: dict[str, Any]) -> PolicyResult: ...


def config_hash(config: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(config))


def deny(pid: str, ver: str, *reasons: str) -> PolicyResult:
    return PolicyResult(decision=Decision.DENY, reasons=tuple(reasons), policy_id=pid,
                        policy_version=ver)


def allow(pid: str, ver: str, *reasons: str) -> PolicyResult:
    return PolicyResult(decision=Decision.ALLOW, reasons=tuple(reasons or ("ok",)), policy_id=pid,
                        policy_version=ver)


def escalate(pid: str, ver: str, *reasons: str) -> PolicyResult:
    return PolicyResult(decision=Decision.ESCALATE, reasons=tuple(reasons), policy_id=pid,
                        policy_version=ver)


def gateway_precheck(inputs: dict[str, Any]) -> PolicyResult | None:
    """Structural checks done by the gateway before any policy. Pure, replayable."""
    if not inputs.get("registered", False):
        return deny("gateway", "1", "unknown_principal")
    tool, params = inputs.get("tool"), inputs.get("params")
    schema = TOOL_PARAMS.get(tool) if isinstance(tool, str) else None
    if schema is None:
        return deny("gateway", "1", "malformed_request", "unknown_tool")
    if not isinstance(params, dict) or set(params) != set(schema):
        return deny("gateway", "1", "malformed_request", "bad_param_keys")
    for k, types in schema.items():
        v = params[k]
        if isinstance(v, bool) or not isinstance(v, types):
            return deny("gateway", "1", "malformed_request", f"bad_type:{k}")
    if tool == "delegate_task" and inputs.get("delegation", {}).get("child_exists"):
        return deny("gateway", "1", "child_exists")
    return None


def amount_cents(inputs: dict[str, Any]) -> int | None:
    try:
        return parse_amount(inputs["params"].get("amount"))
    except BackendError:
        return None


def mentioned_accounts(params: dict[str, Any]) -> list[str]:
    return [str(params[k]) for k in ("account_id", "source_id", "destination_id") if k in params]
