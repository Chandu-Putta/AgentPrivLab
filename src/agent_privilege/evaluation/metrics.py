"""Metric computation from raw per-action rows (list of dicts). Definitions are the ones
pre-registered in docs/methodology.md."""
from __future__ import annotations

import collections
from typing import Any

from ..policy.registry import ALL_STRATEGIES, CORE_STRATEGIES
from .statistics import exact_mcnemar, wilson

APPROVED_OK = {"executed", "approved_executed", "delegated"}


def rate(k: int, n: int) -> dict[str, Any]:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n if n else float("nan")), "ci_lo": lo, "ci_hi": hi}


def split_rows(rows: list[dict], common_ids: set[str]) -> dict[str, list[dict]]:
    """Group rows: 'common' (scenarios applicable to all strategies) vs 'targeted'."""
    return {"common": [r for r in rows if r["scenario_id"] in common_ids],
            "targeted": [r for r in rows if r["scenario_id"] not in common_ids]}


def common_scenario_ids(instances) -> set[str]:
    return {i.scenario.id for i in instances if i.scenario.applies_to == "all"}


def _is_unauth(r: dict) -> bool:
    return r["expected"] == "unauthorized" and not r["expansion"]


def security_metrics(rows: list[dict]) -> list[dict[str, Any]]:
    """Per strategy: unauthorized execution rate (expansion requests reported separately)."""
    out = []
    for s in ALL_STRATEGIES:
        rs = [r for r in rows if r["strategy"] == s and _is_unauth(r)]
        if not rs:
            continue
        ex = sum(r["executed"] for r in rs)
        row = {"strategy": s, "metric": "unauthorized_execution_rate", **rate(ex, len(rs))}
        out.append(row)
        out.append({"strategy": s, "metric": "attack_blocking_rate",
                    **rate(len(rs) - ex, len(rs))})
        for sev in ("critical", "high", "medium", "low"):
            sr = [r for r in rs if r["severity"] == sev]
            if sr:
                out.append({"strategy": s, "metric": f"unauthorized_execution_rate[{sev}]",
                            **rate(sum(r["executed"] for r in sr), len(sr))})
        layers = collections.Counter(r["blocked_by"] for r in rs if not r["executed"])
        for layer, n in sorted(layers.items()):
            out.append({"strategy": s, "metric": f"blocked_by[{layer}]", **rate(n, len(rs))})
    return out


def by_category(rows: list[dict]) -> list[dict[str, Any]]:
    out = []
    for s in ALL_STRATEGIES:
        cats = sorted({r["category"] for r in rows if r["strategy"] == s and _is_unauth(r)})
        for c in cats:
            rs = [r for r in rows if r["strategy"] == s and _is_unauth(r) and r["category"] == c]
            out.append({"strategy": s, "metric": f"uer_by_category[{c}]",
                        **rate(sum(r["executed"] for r in rs), len(rs))})
    return out


def usability_metrics(rows: list[dict]) -> list[dict[str, Any]]:
    """False positives (deny vs escalation) and per-call success on authorized actions."""
    out = []
    for s in ALL_STRATEGIES:
        rs = [r for r in rows if r["strategy"] == s and r["expected"] == "authorized"]
        if not rs:
            continue
        n = len(rs)
        deny = sum(1 for r in rs if not r["executed"] and r["decision"] == "deny")
        esc_ok = sum(1 for r in rs if r["outcome"] == "approved_executed")
        esc_rej = sum(1 for r in rs if r["outcome"] in ("approval_rejected", "denied_escalation_unavailable"))
        backend = sum(1 for r in rs if not r["executed"] and r["decision"] == "allow")
        out += [{"strategy": s, "metric": "false_positive_deny_rate", **rate(deny, n)},
                {"strategy": s, "metric": "escalation_rate_completed", **rate(esc_ok, n)},
                {"strategy": s, "metric": "escalation_rate_rejected", **rate(esc_rej, n)},
                {"strategy": s, "metric": "authorized_backend_failure_rate", **rate(backend, n)},
                {"strategy": s, "metric": "per_call_success_rate",
                 **rate(sum(r["executed"] for r in rs), n)}]
    return out


def task_completion(rows: list[dict]) -> list[dict[str, Any]]:
    """Legitimate-scenario instances completed = every authorized action executed."""
    out = []
    for s in ALL_STRATEGIES:
        inst: dict[str, list[dict]] = collections.defaultdict(list)
        for r in rows:
            if r["strategy"] == s and r["kind"] == "legitimate":
                inst[r["instance_id"]].append(r)
        if not inst:
            continue
        done = sum(all(x["executed"] for x in v) for v in inst.values())
        out.append({"strategy": s, "metric": "legitimate_task_completion", **rate(done, len(inst))})
        multi = [v for v in inst.values() if len(v) > 1]
        if multi:
            out.append({"strategy": s, "metric": "multistep_task_completion",
                        **rate(sum(all(x["executed"] for x in v) for v in multi), len(multi))})
    return out


def delegation_metrics(rows: list[dict]) -> list[dict[str, Any]]:
    out = []
    for s in ALL_STRATEGIES:
        exp = [r for r in rows if r["strategy"] == s and r["expansion"]]
        if exp:
            rej = sum(1 for r in exp if not r["executed"])
            out.append({"strategy": s, "metric": "delegation_expansion_rejected", **rate(rej, len(exp))})
        child = [r for r in rows if r["strategy"] == s and r["category"].startswith("delegation")
                 and _is_unauth(r)]
        if child:
            out.append({"strategy": s, "metric": "delegation_unauthorized_execution_rate",
                        **rate(sum(r["executed"] for r in child), len(child))})
        leg = [r for r in rows if r["strategy"] == s and r["category"] == "legitimate_delegation"]
        if leg:
            out.append({"strategy": s, "metric": "legitimate_delegation_completion",
                        **rate(sum(r["executed"] for r in leg), len(leg))})
    return out


def state_metrics(outcomes: list[dict]) -> list[dict[str, Any]]:
    out = []
    for s in ALL_STRATEGIES:
        o = [x for x in outcomes if x["strategy"] == s]
        if o:
            out.append({"strategy": s, "metric": "oracle_state_divergence_rate",
                        **rate(sum(x["state_divergence"] for x in o), len(o))})
    return out


def paired(rows: list[dict], a: str, b: str, scenario_filter=None) -> dict[str, Any]:
    """Paired comparison on unauthorized proposals that both strategies saw."""
    key = lambda r: (r["instance_id"], r["step"])  # noqa: E731
    ra = {key(r): r["executed"] for r in rows if r["strategy"] == a and _is_unauth(r)
          and (scenario_filter is None or scenario_filter(r))}
    rb = {key(r): r["executed"] for r in rows if r["strategy"] == b and _is_unauth(r)
          and (scenario_filter is None or scenario_filter(r))}
    shared = ra.keys() & rb.keys()
    only_a = sum(1 for k in shared if ra[k] and not rb[k])
    only_b = sum(1 for k in shared if rb[k] and not ra[k])
    return {"a": a, "b": b, "n_pairs": len(shared), "a_exec": sum(ra[k] for k in shared),
            "b_exec": sum(rb[k] for k in shared), "a_only": only_a, "b_only": only_b,
            "mcnemar_p": exact_mcnemar(only_a, only_b)}


PAIRS = [("broad_role", "restricted_role"), ("restricted_role", "task_capability"),
         ("restricted_role", "external_policy"), ("session_scope", "external_policy"),
         ("task_capability", "external_policy"), ("external_policy", "policy_plus_approval"),
         ("external_policy", "delegated_attenuation"), ("delegated_naive", "delegated_attenuation")]


def all_paired(rows: list[dict]) -> list[dict[str, Any]]:
    return [paired(rows, a, b) for a, b in PAIRS]


def all_metrics(rows: list[dict], outcomes: list[dict]) -> list[dict[str, Any]]:
    return (security_metrics(rows) + by_category(rows) + usability_metrics(rows) +
            task_completion(rows) + delegation_metrics(rows) + state_metrics(outcomes))


__all__ = ["all_metrics", "all_paired", "CORE_STRATEGIES", "split_rows", "common_scenario_ids",
           "APPROVED_OK"]
