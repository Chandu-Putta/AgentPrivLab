"""Real MCP over a stdio subprocess (official SDK), end to end through the gateway."""
import asyncio
import os

from agent_privilege.audit.journal import AuditJournal
from agent_privilege.clock import SystemClock
from agent_privilege.evaluation.env import ASSERTION_KEY, CONFIG_DIR, Env
from agent_privilege.mcp_layer.client import McpBankingClient
from agent_privilege.policy.registry import load_strategy
from tests.conftest import ACTOR_A1, intent


def test_stdio_server_end_to_end():
    async def go():
        env = Env(42, AuditJournal(), clock=SystemClock())
        env.reset()
        c = McpBankingClient()
        await c.connect_stdio({**os.environ, "AGENTPRIV_ASSERTION_KEY": ASSERTION_KEY.decode()})
        env.client = c
        try:
            assert await c.list_tools() == ["create_payee", "export_statement", "get_account",
                                            "list_transactions", "transfer_funds", "update_contact"]
            # direct call with no/forged assertion is refused by the separate server process
            assert (await c.call("get_account", {"account_id": "acct_a1"}, "h", "x"))["ok"] is False
            gw = env.gateway(load_strategy("external_policy", CONFIG_DIR), backend_defense=True)
            gw.start_task(ACTOR_A1, intent(), "T")
            ok = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})
            assert ok.executed and ok.result["id"] == "acct_a1"
            bad = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_b1"})
            assert not bad.executed and bad.blocked_by == "gateway"
            xfer = await gw.invoke("agent_a1", "transfer_funds", {
                "source_id": "acct_a1", "destination_id": "acct_a2", "amount": "10.00", "currency": "USD",
                "idempotency_key": "stdio-1"})
            assert xfer.executed
            # the subprocess's own database changed (gateway-local DB did not): real process boundary
            after = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})
            assert after.result["balance_cents"] == ok.result["balance_cents"] - 1000
        finally:
            await c.close()
    asyncio.run(asyncio.wait_for(go(), 60))
