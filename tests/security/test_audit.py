import json

from agent_privilege.audit.journal import AuditJournal
from agent_privilege.audit.replay import replay_lines
from agent_privilege.gateway.canonicalize import canonical_json
from agent_privilege.policy.registry import ALL_STRATEGIES
from tests.conftest import ACTOR_A1, intent, run_env
from tests.security.test_invariants import xfer


def make_log(strat):
    async def go(env):
        snaps = {}
        for n in ("external_policy", "policy_plus_approval"):
            s = strat(n)
            snaps[n] = s.config
            gw = env.gateway(s, trace_id=n)
            gw.start_task(ACTOR_A1, intent(max_amount="2000.00"), "T" + n)
            await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"})
            await gw.invoke("agent_a1", "get_account", {"account_id": "acct_b1"})
            await gw.invoke("agent_a1", "transfer_funds", xfer(amt="800.00"))
            await gw.invoke("agent_a1", "nope", {})
            await gw.invoke("agent_a1", "get_account", {"account_id": "acct_a1"}, fault="policy_unavailable")
        lines = [json.dumps(r, sort_keys=True) for r in env.journal.records]
        return lines, snaps
    return run_env(go)


def rechain(recs):
    prev, out = "0" * 64, []
    for i, r in enumerate(recs):
        r = {k: v for k, v in r.items() if k != "hash"}
        r["seq"], r["prev_hash"] = i, prev
        r["hash"] = AuditJournal.entry_hash(prev, r)
        prev = r["hash"]
        out.append(json.dumps(r, sort_keys=True))
    return out


def test_clean_log_fully_reproducible(strat):
    lines, snaps = make_log(strat)
    rep = replay_lines(lines, snaps)
    assert rep.ok and rep.total == 10 and rep.reconstructability == 1.0


def test_tampering_detected(strat):
    lines, snaps = make_log(strat)
    recs = [json.loads(x) for x in lines]
    # 1. edit a field without rechaining
    t = [json.loads(x) for x in lines]; t[1]["tenant"] = "tenant_b"
    assert replay_lines([json.dumps(x) for x in t], snaps).chain_breaks
    # 2. delete a record
    assert replay_lines(lines[:2] + lines[3:], snaps).chain_breaks
    # 3. incomplete record
    t = [json.loads(x) for x in lines]; del t[2]["policy_inputs"]
    assert replay_lines([json.dumps(x) for x in t], snaps).incomplete == [2]
    # 4. garbage line
    assert replay_lines(lines[:1] + ["{not json"] + lines[2:], snaps).unparseable == [1]
    # 5. attacker flips a DENY to ALLOW and recomputes the whole chain: chain valid, replay catches it
    t = [json.loads(x) for x in lines]
    i = next(k for k, r in enumerate(t) if r["decision"] == "deny" and r["policy_id"] != "gateway")
    t[i]["decision"] = "allow"
    rep = replay_lines(rechain(t), snaps)
    assert not rep.chain_breaks and rep.mismatches and rep.mismatches[0][0] == i
    # 6. policy config changed after the fact: hash mismatch
    snaps2 = {k: {**v, "description": "edited"} for k, v in snaps.items()}
    assert replay_lines(lines, snaps2).mismatches
    assert recs


def test_no_raw_contact_values_in_audit(strat):
    async def go(env):
        gw = env.gateway(strat("external_policy"))
        gw.start_task(ACTOR_A1, intent(task_type="profile_update", tools=["update_contact"]), "T")
        await gw.invoke("agent_a1", "update_contact",
                        {"account_id": "acct_a1", "contact": {"email": "secret@example.invalid"}})
        assert "secret@example.invalid" not in canonical_json(env.journal.records)
    run_env(go)


def test_all_strategies_configs_load(strat):
    for n in ALL_STRATEGIES:
        assert strat(n).policy_hash
