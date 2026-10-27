"""Real MCP banking tool server (official SDK, FastMCP).

Each tool takes the business parameters plus `request_hash` and `assertion`, which are
supplied only by the gateway. The agent holds no assertion key and no MCP session.
Run standalone over stdio:  python -m agent_privilege.mcp_layer.server
"""
from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..banking.db import Database
from ..banking.seed import seed
from ..banking.service import BackendError, BankingService


def build_server(service: BankingService) -> FastMCP:
    mcp = FastMCP("banking")

    def run(tool: str, params: dict[str, Any], request_hash: str, assertion: str) -> str:
        try:
            return json.dumps({"ok": True, "result": service.call(tool, params, request_hash, assertion)})
        except BackendError as e:
            return json.dumps({"ok": False, "error": e.code})

    @mcp.tool()
    def get_account(account_id: str, request_hash: str, assertion: str) -> str:
        return run("get_account", {"account_id": account_id}, request_hash, assertion)

    @mcp.tool()
    def list_transactions(account_id: str, request_hash: str, assertion: str) -> str:
        return run("list_transactions", {"account_id": account_id}, request_hash, assertion)

    @mcp.tool()
    def export_statement(account_id: str, request_hash: str, assertion: str) -> str:
        return run("export_statement", {"account_id": account_id}, request_hash, assertion)

    @mcp.tool()
    def update_contact(account_id: str, contact: dict[str, str], request_hash: str,
                       assertion: str) -> str:
        return run("update_contact", {"account_id": account_id, "contact": contact},
                   request_hash, assertion)

    @mcp.tool()
    def create_payee(account_id: str, payee_id: str, request_hash: str, assertion: str) -> str:
        return run("create_payee", {"account_id": account_id, "payee_id": payee_id},
                   request_hash, assertion)

    @mcp.tool()
    def transfer_funds(source_id: str, destination_id: str, amount: str, currency: str,
                       idempotency_key: str, request_hash: str, assertion: str) -> str:
        return run("transfer_funds", {"source_id": source_id, "destination_id": destination_id,
                   "amount": amount, "currency": currency, "idempotency_key": idempotency_key},
                   request_hash, assertion)

    return mcp


def main() -> None:  # stdio entrypoint
    db = Database(os.environ.get("AGENTPRIV_DB", ":memory:"))
    seed(db, int(os.environ.get("AGENTPRIV_SEED", "42")))
    key = os.environ["AGENTPRIV_ASSERTION_KEY"].encode()
    build_server(BankingService(db, key)).run("stdio")


if __name__ == "__main__":
    main()
