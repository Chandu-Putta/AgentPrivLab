"""Shared typed models."""
from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Tool(StrEnum):
    GET_ACCOUNT = "get_account"
    LIST_TRANSACTIONS = "list_transactions"
    TRANSFER_FUNDS = "transfer_funds"
    UPDATE_CONTACT = "update_contact"
    CREATE_PAYEE = "create_payee"
    EXPORT_STATEMENT = "export_statement"
    DELEGATE_TASK = "delegate_task"


READ_TOOLS = {Tool.GET_ACCOUNT, Tool.LIST_TRANSACTIONS}
HIGH_IMPACT_TOOLS = {Tool.TRANSFER_FUNDS, Tool.EXPORT_STATEMENT, Tool.CREATE_PAYEE}


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"  # requires approval


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Principal(Frozen):
    """Authenticated caller identity as established by trusted context (never by content)."""

    agent_id: str
    tenant: str
    customer_id: str
    parent_agent_id: str | None = None
    roles: tuple[str, ...] = ()


class ToolRequest(Frozen):
    """What the agent asks for. Nothing here is trusted as authorization."""

    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    task_id: str = ""
    # Opaque tokens the agent presents; validated by the gateway, never trusted.
    grant_token: str | None = None
    approval_id: str | None = None
    idempotency_key: str | None = None


class PolicyResult(Frozen):
    decision: Decision
    reasons: tuple[str, ...]
    policy_id: str
    policy_version: str = "1"


class Money(Frozen):
    amount: Decimal
    currency: str
