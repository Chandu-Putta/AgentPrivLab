"""Policy-maintenance PROXIES for predefined change requests. These count configuration lines
changed and regression flips; they do NOT measure engineer time (never claimed)."""
from __future__ import annotations

import copy
import difflib
from pathlib import Path
from typing import Any

import yaml

from ..policy.registry import CORE_STRATEGIES, load_config
from .metrics import common_scenario_ids
from .runner import run_matrix


def _leaves(x: Any) -> int:
    if isinstance(x, dict):
        return sum(_leaves(v) for v in x.values())
    if isinstance(x, list):
        return sum(_leaves(v) for v in x)
    return 1


POLICY_KEYS = {"broad_role": ["role"], "restricted_role": ["roles", "task_type_roles"],
               "session_scope": ["session_templates"], "task_capability": [],
               "external_policy": ["rules", "approval"], "policy_plus_approval": ["rules", "approval"],
               "delegated_attenuation": ["rules", "delegation"]}


def rules_count(name: str, cfg: dict[str, Any]) -> int:
    return sum(_leaves(cfg.get(k)) for k in POLICY_KEYS[name] if cfg.get(k) is not None)


def cr1(name: str, cfg: dict) -> str:
    """CR1: support a new task type 'invoice_batch' that may read and transfer."""
    if name == "restricted_role":
        cfg["task_type_roles"]["invoice_batch"] = "payer"
    elif name == "session_scope":
        cfg["session_templates"]["invoice_batch"] = copy.deepcopy(cfg["session_templates"]["pay_invoice"])
    else:
        return "no_policy_change_needed"  # authority comes from per-task intent / generic claims
    return "config_edit"


def cr2(name: str, cfg: dict) -> str:
    """CR2: raise the transfer limit available to payers from 1000.00 to 2000.00."""
    if name == "restricted_role":
        cfg["roles"]["payer"]["max_amount_cents"] = 200000
    elif name == "session_scope":
        for t in cfg["session_templates"].values():
            if t["max_amount_cents"] == 100000:
                t["max_amount_cents"] = 200000
    else:
        return "no_policy_change_needed"  # limit is carried by each task's intent
    return "config_edit"


def cr3(name: str, cfg: dict) -> str:
    """CR3: organisation disables create_payee for agents everywhere."""
    if name == "broad_role":
        cfg["role"]["tools"].remove("create_payee")
    elif name == "restricted_role":
        cfg["roles"]["payer"]["tools"].remove("create_payee")
    elif name == "session_scope":
        for t in cfg["session_templates"].values():
            if "create_payee" in t["tools"]:
                t["tools"].remove("create_payee")
    else:
        return "not_config_expressible"  # needs a new rule (code) or per-task intents
    return "config_edit"


CRS = {"CR1_new_task_type": cr1, "CR2_raise_transfer_cap": cr2, "CR3_disable_create_payee": cr3}


def _correct(r: dict) -> bool:
    return r["executed"] == (r["expected"] == "authorized")


def run_maintenance(scenarios_dir: Path, config_dir: Path, instances, seed: int) -> list[dict[str, Any]]:
    ids = common_scenario_ids(instances)
    inst = [i for i in instances if i.scenario.id in ids]
    base_rows, _ = run_matrix(scenarios_dir, CORE_STRATEGIES, seed=seed, instances=inst)
    base = {(r["strategy"], r["instance_id"], r["step"]): _correct(r) for r in base_rows}
    out = []
    for name in CORE_STRATEGIES:
        cfg0 = load_config(name, config_dir)
        out.append({"strategy": name, "change_request": "baseline", "rules_count": rules_count(name, cfg0),
                    "config_lines": len(yaml.safe_dump(cfg0).splitlines()), "change_mode": "baseline",
                    "config_lines_changed": 0, "regressions": 0, "fixes": 0,
                    "engineer_time": "not_measured"})
        for crn, fn in CRS.items():
            cfg = copy.deepcopy(cfg0)
            mode = fn(name, cfg)
            row = {"strategy": name, "change_request": crn, "rules_count": rules_count(name, cfg),
                   "config_lines": len(yaml.safe_dump(cfg).splitlines()), "change_mode": mode,
                   "config_lines_changed": 0, "regressions": 0, "fixes": 0, "engineer_time": "not_measured"}
            if mode == "config_edit":
                d = difflib.unified_diff(yaml.safe_dump(cfg0).splitlines(), yaml.safe_dump(cfg).splitlines(),
                                         lineterm="", n=0)
                row["config_lines_changed"] = sum(1 for x in d if x[:1] in "+-" and x[:3] not in ("+++", "---"))
                rows, _ = run_matrix(scenarios_dir, [name], seed=seed, instances=inst, overrides={name: cfg})
                for r in rows:
                    was = base[(name, r["instance_id"], r["step"])]
                    now = _correct(r)
                    row["regressions"] += int(was and not now)
                    row["fixes"] += int(now and not was)
            out.append(row)
    return out
