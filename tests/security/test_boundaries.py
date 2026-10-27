import asyncio
import re
from pathlib import Path

from tests.conftest import ACTOR_A1, intent, run_env
from tests.security.test_invariants import xfer

PKG = Path(__file__).resolve().parents[2] / "src" / "agent_privilege"


def test_agent_code_holds_no_keys_or_signing_helpers():
    """The agent-side package must not import credentials that bypass the gateway."""
    for f in (PKG / "agents").glob("*.py"):
        src = f.read_text()
        assert not re.search(r"ASSERTION_KEY|GRANT_KEY|sign_assertion|sign_grant|BankingService|McpBankingClient", src), f


def test_backend_timeout_fails_closed_without_side_effect(strat):
    class Slow:
        async def call(self, *a, **k):
            await asyncio.sleep(1)
            return {"ok": True, "result": {}}

    async def go(env):
        gw = env.gateway(strat("external_policy"))
        gw.client, gw.backend_timeout_s = Slow(), 0.05
        gw.start_task(ACTOR_A1, intent(), "T")
        before = env.db.snapshot()
        r = await gw.invoke("agent_a1", "transfer_funds", xfer())
        assert not r.executed and "backend_timeout" in r.outcome and env.db.snapshot() == before
    run_env(go)


def test_every_invocation_is_audited_including_denials(strat):
    async def go(env):
        gw = env.gateway(strat("external_policy"))
        gw.start_task(ACTOR_A1, intent(), "T")
        await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})
        await gw.invoke("agent_a1", "get_account", {"account_id": "acct_b1"})
        await gw.invoke("ghost", "get_account", {"account_id": "acct_a1"})
        assert [r["decision"] for r in env.journal.records] == ["allow", "deny", "deny"]
    run_env(go)


def test_untrusted_content_is_not_an_input_to_policy(strat):
    """Policy inputs contain no free text from tools/documents; only structured trusted facts."""
    async def go(env):
        gw = env.gateway(strat("external_policy"))
        gw.start_task(ACTOR_A1, intent(), "T")
        r = await gw.invoke("agent_a1", "list_transactions", {"account_id": "acct_a1"})
        assert r.executed and any("IGNORE PREVIOUS" in t["memo"] for t in r.result)
        assert "IGNORE" not in str(env.journal.records[-1]["policy_inputs"])
    run_env(go)
