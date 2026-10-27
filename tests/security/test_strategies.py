import threading

from tests.conftest import ACTOR_A1, intent, run_env
from tests.security.test_invariants import xfer


def mk(strat, env, name, **it):
    gw = env.gateway(strat(name))
    tok = gw.start_task(ACTOR_A1, intent(**it), "T")
    return gw, tok


def test_tampered_grant_rejected(strat):
    async def go(env):
        gw, tok = mk(strat, env, "task_capability")
        body, mac = tok.split(".")
        bad = body[:-2] + ("AA" if not body.endswith("AA") else "BB") + "." + mac
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(), grant_token=bad)
        assert not r.executed and "grant_invalid" in r.reasons
        ok = await gw.invoke("agent_a1", "transfer_funds", xfer(), grant_token=tok)
        assert ok.executed
        r = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})
        assert "no_grant" in r.reasons
    run_env(go)


def test_grant_expiry_and_revocation(strat):
    async def go(env):
        gw, tok = mk(strat, env, "task_capability")
        gw.revoke_task("T")
        r = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"}, grant_token=tok)
        assert "grant_revoked" in r.reasons and not r.executed
        gw2 = env.gateway(strat("task_capability"), trace_id="x")
        tok2 = gw2.start_task(ACTOR_A1, intent(), "T2")
        env.clock.advance(3600)
        r = await gw2.invoke("agent_a1", "get_account", {"account_id": "acct_a1"}, grant_token=tok2)
        assert "grant_expired" in r.reasons
    run_env(go)


def test_grant_bound_to_principal_and_limits(strat):
    async def go(env):
        gw, tok = mk(strat, env, "task_capability")
        gw.ctxs["other"] = gw.ctxs["agent_a1"].__class__(**{**gw.ctxs["agent_a1"].__dict__, "agent_id": "other"})
        r = await gw.invoke("other", "get_account", {"account_id": "acct_a1"}, grant_token=tok)
        assert not r.executed and "principal_mismatch" in r.reasons
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(amt="200.01"), grant_token=tok)
        assert "over_grant_limit" in r.reasons
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(dst="acct_a3"), grant_token=tok)
        assert "destination_not_in_grant" in r.reasons
    run_env(go)


def test_external_policy_runtime_revocation_and_expiry(strat):
    async def go(env):
        gw, _ = mk(strat, env, "external_policy")
        assert (await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})).executed
        gw.revoke_task("T")
        r = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})
        assert "task_revoked" in r.reasons
        gw2 = env.gateway(strat("external_policy"), trace_id="y")
        gw2.start_task(ACTOR_A1, intent(), "T3")
        env.clock.advance(7200)
        assert "task_expired" in (await gw2.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})).reasons
    run_env(go)


def test_approval_binds_exact_params_expiry_and_single_use(strat):
    async def go(env):
        it = dict(max_amount="2000.00", max_total="5000.00")
        gw, _ = mk(strat, env, "policy_plus_approval", **it)
        big = xfer(amt="800.00", key="a1")
        pre = await gw.request_approval("agent_a1", "transfer_funds", big, "approve")
        assert pre.outcome == "approval_issued"
        # modified parameters after approval
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(amt="950.00", key="a1"), approval_id=pre.approval_id)
        assert not r.executed and "approval_hash_mismatch" in r.reasons
        # exact params with the approval succeed once...
        r = await gw.invoke("agent_a1", "transfer_funds", big, approval_id=pre.approval_id)
        assert r.executed
        # ...replay fails
        r = await gw.invoke("agent_a1", "transfer_funds", big, approval_id=pre.approval_id)
        assert not r.executed and "approval_used" in r.reasons
        # expiry
        pre2 = await gw.request_approval("agent_a1", "transfer_funds", xfer(amt="700.00", key="b"), "approve")
        env.clock.advance(301)
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(amt="700.00", key="b"), approval_id=pre2.approval_id)
        assert "approval_expired" in r.reasons and not r.executed
    run_env(go)


def test_approval_cannot_override_policy_denial(strat):
    async def go(env):
        gw, _ = mk(strat, env, "policy_plus_approval")  # task max is 200
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(amt="900.00"), scripted_reviewer="approve")
        assert r.decision == "deny" and not r.executed
        pre = await gw.request_approval("agent_a1", "transfer_funds", xfer(amt="900.00"), "approve")
        assert pre.outcome == "denied"
        # rubber-stamp reviewer does not help either
        gw2 = env.gateway(strat("policy_plus_approval"), trace_id="z", reviewer_mode="rubber_stamp")
        gw2.start_task(ACTOR_A1, intent(), "T9")
        assert not (await gw2.invoke("agent_a1", "transfer_funds", xfer(amt="900.00"))).executed
    run_env(go)


def test_rejected_approval_blocks_in_policy_action(strat):
    async def go(env):
        gw, _ = mk(strat, env, "policy_plus_approval", max_amount="2000.00")
        r = await gw.invoke("agent_a1", "transfer_funds", xfer(amt="800.00"), scripted_reviewer="reject")
        assert r.outcome == "approval_rejected" and not r.executed
    run_env(go)


def deleg(child="kid", **scopes):
    return {"child_agent_id": child, "requested_scopes": scopes}


def test_delegation_attenuation_denies_amplification(strat):
    async def go(env):
        gw, _ = mk(strat, env, "delegated_attenuation", tools=["get_account", "delegate_task"],
                   accounts=["acct_a1"], destinations=[])
        r = await gw.invoke("agent_a1", "delegate_task",
                            deleg(tools=["get_account", "transfer_funds"], accounts=["acct_a1"]))
        assert not r.executed and "delegation_amplification" in r.reasons and "tools" in r.reasons
        r = await gw.invoke("agent_a1", "delegate_task", deleg(tools=["get_account"], accounts=["acct_a2"]))
        assert "accounts" in r.reasons
        r = await gw.invoke("agent_a1", "delegate_task",
                            deleg(tools=["get_account"], accounts=["acct_a1"], max_amount="500.00"))
        assert "max_amount" in r.reasons
        ok = await gw.invoke("agent_a1", "delegate_task", deleg(tools=["get_account"], accounts=["acct_a1"]))
        assert ok.executed
        assert (await gw.invoke("kid", "get_account", {"account_id": "acct_a1"})).executed
        assert not (await gw.invoke("kid", "list_transactions", {"account_id": "acct_a1"})).executed
    run_env(go)


def test_delegation_forwarding_overprivileges_child(strat):
    async def go(env):
        gw, _ = mk(strat, env, "delegated_naive", tools=["get_account", "transfer_funds", "delegate_task"],
                   accounts=["acct_a1"], destinations=["acct_a2"])
        ok = await gw.invoke("agent_a1", "delegate_task", deleg(tools=["get_account"], accounts=["acct_a1"]))
        assert ok.executed
        # child only needed read, but forwarding gave it transfer rights too
        assert (await gw.invoke("kid", "transfer_funds", xfer())).executed
    run_env(go)


def test_delegation_depth_limit_and_duplicate_child(strat):
    async def go(env):
        gw, _ = mk(strat, env, "delegated_attenuation", tools=["get_account", "delegate_task"],
                   accounts=["acct_a1"])
        s = dict(tools=["get_account", "delegate_task"], accounts=["acct_a1"])
        assert (await gw.invoke("agent_a1", "delegate_task", deleg("k1", **s))).executed
        assert (await gw.invoke("k1", "delegate_task", deleg("k2", **s))).executed
        r = await gw.invoke("k2", "delegate_task", deleg("k3", **s))
        assert "delegation_depth_exceeded" in r.reasons
        r = await gw.invoke("agent_a1", "delegate_task", deleg("k1", **s))
        assert "child_exists" in r.reasons
    run_env(go)


def test_confused_deputy_service_identity(strat):
    svc = {"agent_id": "svc", "tenant": "tenant_a", "customer_id": "svc_batch", "on_behalf_of": "cust_a1",
           "service": True}
    async def go(env):
        it = intent(task_type="batch_report", tools=["get_account"], accounts=["acct_a1"])
        for name, blocked in [("external_policy", True), ("task_capability", True), ("restricted_role", False)]:
            gw = env.gateway(strat(name), trace_id=name)
            tok = gw.start_task(svc, it, "T-" + name)
            r = await gw.invoke("svc", "get_account", {"account_id": "acct_a3"}, grant_token=tok)
            assert (not r.executed) == blocked, name
    run_env(go)


def test_fail_closed_and_fail_open(strat):
    async def go(env):
        for name, executed in [("external_policy", False), ("external_policy_failopen", True)]:
            gw = env.gateway(strat(name), trace_id=name)
            gw.start_task(ACTOR_A1, intent(), "T" + name)
            r = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_b1"}, fault="policy_unavailable")
            assert r.executed == executed and "policy_unavailable" in r.reasons
    run_env(go)


def test_policy_exception_fails_closed(strat):
    async def go(env):
        s = strat("external_policy")
        def boom(_): raise RuntimeError("x")
        s.policy.evaluate = boom
        gw = env.gateway(s)
        gw.start_task(ACTOR_A1, intent(), "T")
        r = await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})
        assert not r.executed and "policy_error" in r.reasons
    run_env(go)


def test_threaded_transfers_serialised_by_backend():
    """True thread concurrency directly against the backend (valid assertions)."""
    from agent_privilege.banking.service import BackendError, sign_assertion
    from agent_privilege.evaluation.env import ASSERTION_KEY
    async def go(env):
        errs, oks = [], []
        def worker(i):
            p = {"source_id": "acct_a1", "destination_id": "acct_a2", "amount": "5000.00",
                 "currency": "USD", "idempotency_key": f"th{i}"}
            c = {"tool": "transfer_funds", "request_hash": f"h{i}", "exp_ms": 10**15,
                 "accounts": ["acct_a1", "acct_a2"], "tenant": "tenant_a", "nonce": f"n{i}"}
            try: oks.append(env.service.call("transfer_funds", p, f"h{i}", sign_assertion(ASSERTION_KEY, c)))
            except BackendError as e: errs.append(e.code)
        total0 = sum(a[4] for a in env.db.snapshot()["accounts"])
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
        [t.start() for t in ts]; [t.join() for t in ts]
        snap = env.db.snapshot()["accounts"]
        assert sum(a[4] for a in snap) == total0 and all(a[4] >= 0 for a in snap)
        assert len(oks) + len(errs) == 40 and set(errs) <= {"insufficient_funds"}
    run_env(go)
