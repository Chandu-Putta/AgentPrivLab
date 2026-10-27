"""Core security invariants required by the project's acceptance criteria."""
import json

import pytest

from agent_privilege.banking.service import BackendError, sign_assertion
from agent_privilege.evaluation.env import ASSERTION_KEY
from agent_privilege.gateway.canonicalize import request_hash
from tests.conftest import ACTOR_A1, intent, run_env

STRATS = ["broad_role", "restricted_role", "session_scope", "task_capability", "external_policy",
          "policy_plus_approval", "delegated_attenuation"]


def xfer(dst="acct_a2", amt="100.00", key="k1", src="acct_a1"):
    return {"source_id": src, "destination_id": dst, "amount": amt, "currency": "USD",
            "idempotency_key": key}


@pytest.mark.parametrize("name", ["task_capability", "external_policy", "policy_plus_approval",
                                   "delegated_attenuation", "session_scope", "restricted_role"])
def test_denied_action_has_no_side_effect(strat, name):
    async def go(env):
        gw = env.gateway(strat(name))
        tok = gw.start_task(ACTOR_A1, intent(task_type="balance_check", tools=["get_account"]), "T")
        before = env.db.snapshot()
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(amt="5000.00"), grant_token=tok)
        assert not r.executed and r.decision == "deny"
        assert env.db.snapshot() == before
    run_env(go)


@pytest.mark.parametrize("name", ["task_capability", "external_policy", "restricted_role"])
def test_cross_tenant_read_denied_at_gateway(strat, name):
    async def go(env):
        gw = env.gateway(strat(name))
        tok = gw.start_task(ACTOR_A1, intent(task_type="balance_check", tools=["get_account"]), "T")
        r = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_b1"}, grant_token=tok)
        assert not r.executed and r.blocked_by == "gateway"
    run_env(go)


def test_cross_tenant_blocked_at_backend_even_with_broad_role(strat):
    """Broad role lets the gateway pass; backend assertion tenant binding still refuses."""
    async def go(env):
        gw = env.gateway(strat("broad_role"), backend_defense=True)
        gw.start_task(ACTOR_A1, intent(task_type="balance_check"), "T")
        r = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_b1"})
        assert r.decision == "allow" and not r.executed and r.blocked_by == "backend"
        assert "cross_tenant" in r.outcome
        # without backend defense the same policy decision leaks data
        gw2 = env.gateway(strat("broad_role"), trace_id="t2", backend_defense=False)
        gw2.start_task(ACTOR_A1, intent(task_type="balance_check"), "T2")
        r2 = await gw2.invoke("agent_a1", "get_account", {"account_id": "acct_b1"})
        assert r2.executed
    run_env(go)


def test_direct_backend_call_without_assertion_fails():
    async def go(env):
        for bad in (None, "", "{}", "not json"):
            with pytest.raises(BackendError):
                env.service.call("get_account", {"account_id": "acct_a1"}, "h", bad)
        # MCP path also refuses without a valid assertion
        out = await env.client.call("get_account", {"account_id": "acct_a1"}, "h", "x")
        assert out["ok"] is False
    run_env(go)


def test_forged_and_mismatched_assertions_rejected():
    async def go(env):
        p = {"account_id": "acct_a1"}
        rh = request_hash("get_account", p, "tenant_a", "x")
        claims = {"tool": "get_account", "request_hash": rh, "exp_ms": 10**15,
                  "accounts": ["acct_a1"], "tenant": "tenant_a", "nonce": "n1"}
        forged = sign_assertion(b"wrong-key", claims)
        with pytest.raises(BackendError, match="bad_signature"):
            env.service.call("get_account", p, rh, forged)
        good = sign_assertion(ASSERTION_KEY, claims)
        with pytest.raises(BackendError, match="assertion_mismatch"):
            env.service.call("get_account", p, "other-hash", good)
        with pytest.raises(BackendError, match="account_not_in_assertion"):
            env.service.call("get_account", {"account_id": "acct_a2"}, rh, good)
        assert env.service.call("get_account", p, rh, good)["id"] == "acct_a1"
        with pytest.raises(BackendError, match="assertion_replayed"):
            env.service.call("get_account", p, rh, good)
        tampered = json.loads(sign_assertion(ASSERTION_KEY, {**claims, "nonce": "n2"}))
        tampered["claims"]["tenant"] = "tenant_b"
        with pytest.raises(BackendError, match="bad_signature"):
            env.service.call("get_account", p, rh, json.dumps(tampered))
    run_env(go)


def test_expired_assertion_rejected():
    async def go(env):
        p = {"account_id": "acct_a1"}
        claims = {"tool": "get_account", "request_hash": "h", "exp_ms": int(env.clock.now() * 1000) + 1000,
                  "accounts": ["acct_a1"], "tenant": "tenant_a", "nonce": "n9"}
        a = sign_assertion(ASSERTION_KEY, claims)
        env.clock.advance(5)
        with pytest.raises(BackendError, match="assertion_expired"):
            env.service.call("get_account", p, "h", a)
    run_env(go)


def test_unknown_principal_and_malformed_default_deny(strat):
    async def go(env):
        gw = env.gateway(strat("external_policy"))
        gw.start_task(ACTOR_A1, intent(), "T")
        r = await gw.invoke("ghost", "get_account", {"account_id": "acct_a1"})
        assert r.reasons[0] == "unknown_principal" and not r.executed
        for tool, params in [("drop_tables", {}), ("get_account", {}), ("get_account", {"account_id": 5}),
                             ("transfer_funds", {**xfer(), "amount": 1.5}),
                             ("get_account", {"account_id": "acct_a1", "extra": 1})]:
            r = await gw.invoke("agent_a1", tool, params)
            assert not r.executed and r.reasons[0] == "malformed_request", (tool, params, r.reasons)
    run_env(go)


@pytest.mark.parametrize("amt,cur", [("-5", "USD"), ("0", "USD"), ("1.005", "USD"), ("abc", "USD"),
                                      ("NaN", "USD"), ("10", "XXX"), ("1e400", "USD")])
def test_amount_and_currency_validation_no_effect(strat, amt, cur):
    async def go(env):
        gw = env.gateway(strat("broad_role"))
        gw.start_task(ACTOR_A1, intent(), "T")
        before = env.db.snapshot()
        r = await gw.invoke("agent_a1", "transfer_funds", {**xfer(amt=amt), "currency": cur})
        assert not r.executed
        assert env.db.snapshot() == before
    run_env(go)


def test_idempotent_transfer_single_effect(strat):
    async def go(env):
        gw = env.gateway(strat("broad_role"))
        gw.start_task(ACTOR_A1, intent(), "T")
        r1 = await gw.invoke("agent_a1", "transfer_funds", xfer(key="same"))
        n1 = env.db.side_effect_count()
        r2 = await gw.invoke("agent_a1", "transfer_funds", xfer(key="same"))
        assert r1.executed and r2.executed and env.db.side_effect_count() == n1
        r3 = await gw.invoke("agent_a1", "transfer_funds", xfer(key="same", amt="7.00"))
        assert not r3.executed and "idempotency_conflict" in r3.outcome
    run_env(go)


def test_insufficient_funds_and_atomicity(strat):
    async def go(env):
        gw = env.gateway(strat("broad_role"))
        gw.start_task(ACTOR_A1, intent(), "T")
        before = env.db.snapshot()
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(amt="99999999.00"))
        assert not r.executed and env.db.snapshot() == before
    run_env(go)


def test_concurrent_transfers_conserve_money(strat):
    import asyncio

    async def go(env):
        gw = env.gateway(strat("broad_role"))
        gw.start_task(ACTOR_A1, intent(), "T")
        total = lambda: sum(a[4] for a in env.db.snapshot()["accounts"])  # noqa: E731
        t0 = total()
        res = await asyncio.gather(*[
            gw.invoke("agent_a1", "transfer_funds", xfer(key=f"c{i}", amt="1000.00")) for i in range(30)])
        assert total() == t0
        assert all(a[4] >= 0 for a in env.db.snapshot()["accounts"])
        assert sum(r.executed for r in res) == env.db.side_effect_count()
    run_env(go)


def test_reset_is_deterministic():
    async def go(env):
        env.reset(); a = env.db.snapshot()
        env.db.conn.execute("UPDATE accounts SET balance_cents=1")
        env.reset()
        assert env.db.snapshot() == a
    run_env(go)
