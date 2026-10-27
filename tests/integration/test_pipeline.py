import json
import shutil
from pathlib import Path

from agent_privilege.cli import main
from agent_privilege.evaluation.runner import run_matrix
from agent_privilege.scenarios import load_instances

ROOT = Path(__file__).resolve().parents[2]


def strip(rows):
    return [{k: v for k, v in r.items() if k not in ("decision_us", "total_us")} for r in rows]


def test_runner_is_deterministic_and_paired():
    inst = [i for i in load_instances(ROOT / "scenarios") if i.scenario.id[:3] in ("L02", "A01", "A04", "A21")]
    a, oa = run_matrix(ROOT / "scenarios", ["restricted_role", "external_policy"], instances=inst)
    b, ob = run_matrix(ROOT / "scenarios", ["restricted_role", "external_policy"], instances=inst)
    assert strip(a) == strip(b) and oa == ob
    assert {r["strategy"] for r in a} == {"restricted_role", "external_policy"}


def test_external_policy_matches_ground_truth_on_in_policy_scenarios():
    inst = [i for i in load_instances(ROOT / "scenarios") if i.scenario.category not in
            ("in_policy_residual", "delegation_overprivilege", "service_failure")]
    rows, outs = run_matrix(ROOT / "scenarios", ["external_policy"], instances=inst)
    wrong = [(r["instance_id"], r["step"]) for r in rows
             if r["executed"] != (r["expected"] == "authorized") and not r["expansion"]]
    assert not wrong, wrong[:5]
    # oracle cross-check: backend end state equals the ground-truth-only end state
    assert not [o for o in outs if o["state_divergence"]]


def test_denied_attacks_leave_no_state_divergence_for_attenuation():
    inst = [i for i in load_instances(ROOT / "scenarios") if i.scenario.kind != "legitimate"
            and i.scenario.category != "in_policy_residual"]
    _, outs = run_matrix(ROOT / "scenarios", ["delegated_attenuation"], instances=inst)
    assert not [o for o in outs if o["state_divergence"]]


def test_full_pipeline_cli_and_tamper_detection(tmp_path):
    out = tmp_path / "run"
    cfg = ROOT / "configs" / "evaluation.yaml"
    assert main(["evaluate", "--config", str(cfg), "--seed", "42", "--output", str(out), "--skip-performance"]) == 0
    for f in ("manifest.json", "summary.md", "deterministic/action_decisions.csv", "deterministic/scenario_outcomes.csv",
              "deterministic/metrics.csv", "deterministic/audit.jsonl", "deterministic/maintenance.csv",
              "approval-simulation/sweep.csv", "figures/unauthorized_execution_rate.png"):
        assert (out / f).exists(), f
    assert json.loads((out / "manifest.json").read_text())["seed"] == 42
    audit = out / "deterministic" / "audit.jsonl"
    assert main(["replay-audit", "--input", str(audit)]) == 0
    # tamper with one decision in place -> replay must fail
    lines = audit.read_text().splitlines()
    rec = json.loads(lines[5]); rec["decision"] = "allow" if rec["decision"] == "deny" else "deny"
    lines[5] = json.dumps(rec, sort_keys=True)
    bad = tmp_path / "bad.jsonl"
    bad.write_text("\n".join(lines) + "\n")
    shutil.copytree(out / "deterministic" / "policy_snapshots", tmp_path / "policy_snapshots")
    assert main(["replay-audit", "--input", str(bad)]) == 1
    assert main(["report", "--input", str(out), "--format", "none"]) == 0
