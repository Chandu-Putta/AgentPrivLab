from copy import deepcopy
from pathlib import Path

import pytest

from agent_privilege.scenarios import Scenario, applicable, load_instances, load_templates

ROOT = Path(__file__).resolve().parents[2]
SCEN = ROOT / "scenarios"


def test_corpus_loads_and_covers_required_categories():
    inst = load_instances(SCEN)
    cats = {i.scenario.category for i in inst}
    for need in ("cross_tenant", "cross_customer", "prompt_injection", "forged_authority", "multi_step_attack",
                 "expired_authorization", "revoked_authorization", "approval_replay", "approval_param_tamper",
                 "approval_expiry", "delegation_escalation", "confused_deputy", "benign_blocked", "fail_open",
                 "service_failure", "amount_escalation", "unauthorized_transfer", "legitimate_read"):
        assert need in cats, need
    assert any(i.scenario.kind == "legitimate" for i in inst)
    ids = [i.instance_id for i in inst]
    assert len(ids) == len(set(ids))
    for t in load_templates(SCEN):
        for key in ("id", "category", "task", "tenant", "actor", "trusted_context", "untrusted_content",
                    "actions", "expected_authorization", "expected_side_effects", "severity", "seed", "rationale"):
            assert key in t or key == "untrusted_content", (t["id"], key)


def test_applicability_matrix():
    inst = {i.scenario.id: i for i in load_instances(SCEN)}
    assert applicable(inst["A19_tampered_grant"], "task_capability")
    assert not applicable(inst["A19_tampered_grant"], "external_policy")
    assert applicable(inst["A10_approval_replay"], "policy_plus_approval")
    assert not applicable(inst["A10_approval_replay"], "broad_role")
    assert applicable(inst["A01_cross_tenant_read"], "direct_no_gateway")


def _tmpl(name):
    return next(t for t in load_templates(SCEN) if t["id"].startswith(name))


def test_validator_rejects_bad_fixtures():
    t = deepcopy(_tmpl("A01"))
    t["expected_authorization"] = {}
    with pytest.raises(ValueError):
        Scenario.model_validate(t)
    t = deepcopy(_tmpl("L02"))
    t["expected_authorization"]["s1"] = "unauthorized"
    with pytest.raises(ValueError):
        Scenario.model_validate(t)  # legitimate scenario with unauthorized action
    t = deepcopy(_tmpl("A04"))
    t["expected_side_effects"] = ["s2"]  # s2 is unauthorized
    with pytest.raises(ValueError):
        Scenario.model_validate(t)
    t = deepcopy(_tmpl("L02"))
    t["actions"].append(deepcopy(t["actions"][0]))
    with pytest.raises(ValueError):
        Scenario.model_validate(t)
    t = deepcopy(_tmpl("L02"))
    t["bogus_field"] = 1
    with pytest.raises(ValueError):
        Scenario.model_validate(t)


# ---- independent ground-truth consistency lint (NOT used to score strategies) ----
SKIP_RULE = {"in_policy_residual", "expired_authorization", "revoked_authorization", "fail_open",
             "delegation_escalation", "delegation_overprivilege", "legitimate_delegation", "approval_replay",
             "approval_param_tamper", "approval_expiry", "grant_tamper", "confused_deputy", "service_failure",
             "legitimate_service", "malformed_input"}


def _rule_allows(intent, a, tenant_letter):
    p, t = a.params, a.tool
    if t not in intent["tools"]:
        return False
    if t == "transfer_funds":
        from agent_privilege.banking.service import parse_amount
        return (p["source_id"] in intent["accounts"] and p["destination_id"] in intent["destinations"]
                and parse_amount(p["amount"]) <= parse_amount(intent["max_amount"]))
    if t == "create_payee":
        return p["account_id"] in intent["accounts"] and p["payee_id"] in intent["destinations"]
    return p["account_id"] in intent["accounts"]


def test_ground_truth_agrees_with_written_rule_where_rule_applies():
    for inst in load_instances(SCEN):
        sc = inst.scenario
        if sc.category in SKIP_RULE:
            continue
        for a in sc.actions:
            if a.type != "tool_call" or a.agent or not a.measured:
                continue
            allowed = _rule_allows(sc.trusted_context["intent"], a, sc.tenant[-1])
            if sc.expected_authorization[a.id] == "authorized":
                assert allowed, (inst.instance_id, a.id)
            else:
                assert not allowed, (inst.instance_id, a.id)
