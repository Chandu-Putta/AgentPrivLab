"""End-to-end `evaluate` and `report` implementations."""
from __future__ import annotations

import csv
import hashlib
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

import yaml

from ..audit.journal import AuditJournal
from ..audit.replay import replay_file
from ..policy.registry import ALL_STRATEGIES, load_config
from ..scenarios import load_instances
from . import metrics as M
from . import plots
from .approval_sim import run_sweep
from .latency import run_latency
from .maintenance import run_maintenance
from .runner import run_matrix

TIMING_COLS = {"decision_us", "total_us"}


def write_csv(path: Path, rows: list[dict[str, Any]], drop: set[str] = frozenset()) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    cols = [c for c in rows[0] if c not in drop]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open() as f:
        out = list(csv.DictReader(f))
    for r in out:
        for k, v in r.items():
            if v in ("True", "False"):
                r[k] = v == "True"
    return out


def _dir_hash(root: Path, pattern: str) -> str:
    h = hashlib.sha256()
    for p in sorted(root.glob(pattern)):
        h.update(p.name.encode()); h.update(p.read_bytes())
    return h.hexdigest()


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except Exception:
        return "uncommitted"


def evaluate(config_path: Path, seed: int, output: Path, *, skip_performance: bool = False) -> Path:
    cfg = yaml.safe_load(config_path.read_text())
    root = config_path.resolve().parent.parent
    sdir, cdir = root / cfg["scenarios"], root / cfg["strategy_configs"]
    instances = load_instances(sdir)
    for i in instances:
        i.seed = seed
    common = M.common_scenario_ids(instances)
    det = output / "deterministic"
    det.mkdir(parents=True, exist_ok=True)
    all_rows: list[dict] = []
    all_out: list[dict] = []
    for cname, c in cfg["conditions"].items():
        strategies = ALL_STRATEGIES if c["strategies"] == "all" else c["strategies"]
        journal = AuditJournal(det / "audit.jsonl") if cname == "primary" else AuditJournal()
        rows, outs = run_matrix(sdir, strategies, seed=seed, backend_defense=c["backend_defense"],
                                reviewer_mode=c["reviewer_mode"], run_id=f"{cname}-seed{seed}",
                                journal=journal, config_dir=cdir, instances=instances)
        for r in rows:
            r["condition"] = cname
            r["scope"] = "common" if r["scenario_id"] in common else "targeted"
        for o in outs:
            o["condition"] = cname
        all_rows += rows; all_out += outs
        print(f"[{cname}] {len(rows)} action rows, audit records: {len(journal.records)}", flush=True)
    write_csv(det / "action_decisions.csv", all_rows, drop=TIMING_COLS)
    write_csv(det / "scenario_outcomes.csv", all_out)

    # outcome stability across initial-state seeds (balances differ)
    stab = []
    base = {(r["instance_id"], r["strategy"], r["step"]): r["executed"] for r in all_rows if r["condition"] == "primary"}
    for s2 in cfg.get("stability_extra_seeds", []):
        ins2 = load_instances(sdir)
        for i in ins2:
            i.seed = s2
        rows2, _ = run_matrix(sdir, ALL_STRATEGIES, seed=s2, instances=ins2, config_dir=cdir)
        diff = sum(1 for r in rows2 if base.get((r["instance_id"], r["strategy"], r["step"])) != r["executed"])
        stab.append({"seed": s2, "compared_actions": len(rows2), "differing_outcomes": diff})
    write_csv(det / "seed_stability.csv", stab)

    snap = det / "policy_snapshots"
    snap.mkdir(exist_ok=True)
    for n in ALL_STRATEGIES:
        (snap / f"{n}.json").write_text(json.dumps(load_config(n, cdir), sort_keys=True, indent=1))
    rep = replay_file(det / "audit.jsonl", snap)
    (det / "replay_audit.json").write_text(json.dumps(rep.summary(), indent=1))
    print("[replay]", rep.summary(), flush=True)
    write_csv(det / "maintenance.csv", run_maintenance(sdir, cdir, instances, seed))

    sim = run_sweep(seed=seed, shifts=cfg["approval_sim"]["shifts"])
    write_csv(output / "approval-simulation" / "sweep.csv", sim)
    (output / "llm-optional").mkdir(exist_ok=True)
    (output / "llm-optional" / "README.md").write_text(
        "No real-LLM experiment was run for this release. Nothing here is a result.\n")
    if not skip_performance:
        lc = cfg["latency"]
        summ, raw, res = run_latency(calls=lc["calls"], warmup=lc["warmup"], repeats=lc["repeats"],
                                     stdio_calls=lc["stdio_calls"], approval_calls=lc["approval_calls"],
                                     n_boot=lc["bootstrap"], seed=seed)
        write_csv(output / "performance" / "latency.csv", raw)
        write_csv(output / "performance" / "latency_summary.csv", summ)
        write_csv(output / "performance" / "resources.csv", res)

    versions = {p: metadata.version(p) for p in ("mcp", "pydantic", "fastapi", "pyyaml", "numpy", "matplotlib")}
    manifest = {
        "git_commit": _git_commit(), "timestamp_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "seed": seed, "python": sys.version, "platform": platform.platform(), "machine": platform.machine(),
        "package_versions": versions, "evaluation_config": cfg,
        "scenario_templates": len({i.scenario.id for i in instances}), "scenario_instances": len(instances),
        "action_rows": len(all_rows), "scenario_sha256": _dir_hash(sdir / "attacks", "*.yaml") + _dir_hash(sdir / "legitimate", "*.yaml"),
        "strategy_config_sha256": _dir_hash(cdir, "*.yaml"),
        "performance_included": not skip_performance,
        "notes": "timing fields are machine-dependent; deterministic CSVs exclude timing columns",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    report(output)
    return output


def _fmt(m: dict | None) -> str:
    if not m:
        return "n/a"
    return f'{m["rate"]*100:.1f}% ({m["k"]}/{m["n"]}) [{m["ci_lo"]*100:.1f}, {m["ci_hi"]*100:.1f}]'


def report(output: Path) -> None:
    det = output / "deterministic"
    rows = read_csv(det / "action_decisions.csv")
    outs = read_csv(det / "scenario_outcomes.csv")
    for r in rows:
        r["expansion"] = r["expansion"] is True
    metrics_rows: list[dict] = []
    paired_rows: list[dict] = []
    for cond in sorted({r["condition"] for r in rows}):
        for scope in ("common", "targeted"):
            rs = [r for r in rows if r["condition"] == cond and r["scope"] == scope]
            os_ = [o for o in outs if o["condition"] == cond and
                   any(r["instance_id"] == o["instance_id"] for r in rs[:0])] or \
                  [o for o in outs if o["condition"] == cond]
            ms = M.all_metrics(rs, [o for o in os_ if o["scenario_id"] in {r["scenario_id"] for r in rs}])
            for m in ms:
                metrics_rows.append({"condition": cond, "scope": scope, **m})
            if cond == "primary" and scope == "common":
                paired_rows = M.all_paired(rs)
    write_csv(det / "metrics.csv", metrics_rows)
    write_csv(det / "paired_comparisons.csv", paired_rows)
    fig = output / "figures"
    plots.uer_by_strategy(metrics_rows, fig)
    plots.tradeoff(metrics_rows, fig)
    plots.category_heatmap(metrics_rows, fig)
    plots.reviewer_plot(metrics_rows, fig)
    sweep = output / "approval-simulation" / "sweep.csv"
    if sweep.exists():
        plots.approval_plot(read_csv(sweep), fig)
    ls = output / "performance" / "latency_summary.csv"
    if ls.exists():
        plots.latency_plot(read_csv(ls), fig)
    (output / "summary.md").write_text(_summary(output, metrics_rows, paired_rows))
    print(f"report written to {output}/summary.md")


def _summary(output: Path, metrics_rows: list[dict], paired_rows: list[dict]) -> str:
    def get(s, m, c="primary", sc="common"):
        return next((x for x in metrics_rows if (x["strategy"], x["metric"], x["condition"], x["scope"]) == (s, m, c, sc)), None)
    man = json.loads((output / "manifest.json").read_text())
    L = ["# Run summary (auto-generated from CSVs; do not edit)", "",
         f"- seed: {man['seed']}, scenarios: {man['scenario_templates']} templates / {man['scenario_instances']} instances, "
         f"action rows (all conditions): {man['action_rows']}",
         f"- python {man['python'].split()[0]}, mcp {man['package_versions']['mcp']}, platform {man['platform']}",
         "- LABELS: deterministic = scripted traces measuring *enforcement*, not LLM susceptibility; "
         "approval simulation = synthetic reviewer model; timing = this machine only.",
         "- CAVEAT: instances of one scenario template are near-duplicates (account/tenant permutations), so Wilson "
         "intervals treat correlated trials as independent and are optimistic. Percentages depend on the scenario "
         "mix and are not attack-prevalence estimates.", "",
         "## Security and usability (primary condition, common scenarios; % (k/n) [95% Wilson CI])", "",
         "| strategy | unauthorized exec | authorized not executed | legit task completion | delegation expansion rejected |",
         "|---|---|---|---|---|"]
    for s in ALL_STRATEGIES:
        u = get(s, "unauthorized_execution_rate")
        if not u:
            continue
        ps = get(s, "per_call_success_rate")
        notex = {"k": ps["n"] - ps["k"], "n": ps["n"], "rate": 1 - ps["rate"], "ci_lo": 1 - ps["ci_hi"], "ci_hi": 1 - ps["ci_lo"]} if ps else None
        L.append(f"| {s} | {_fmt(u)} | {_fmt(notex)} | {_fmt(get(s, 'legitimate_task_completion'))} | "
                 f"{_fmt(get(s, 'delegation_expansion_rejected'))} |")
    L += ["", "## Targeted scenarios (apply to a subset of strategies)", "",
          "| strategy | unauthorized exec (targeted) | authorized not executed (targeted) |", "|---|---|---|"]
    for s in ALL_STRATEGIES:
        u = get(s, "unauthorized_execution_rate", sc="targeted")
        if u:
            ps = get(s, "per_call_success_rate", sc="targeted")
            nx = {"k": ps["n"] - ps["k"], "n": ps["n"], "rate": 1 - ps["rate"], "ci_lo": 1 - ps["ci_hi"], "ci_hi": 1 - ps["ci_lo"]} if ps else None
            L.append(f"| {s} | {_fmt(u)} | {_fmt(nx)} |")
    L += ["", "## Layered condition (backend independently enforces tenant/account/limit claims)", "",
          "| strategy | unauthorized exec (gateway-only) | unauthorized exec (gateway + backend) |", "|---|---|---|"]
    for s in ALL_STRATEGIES:
        a, b = get(s, "unauthorized_execution_rate"), get(s, "unauthorized_execution_rate", "layered")
        if a and b:
            L.append(f"| {s} | {_fmt(a)} | {_fmt(b)} |")
    L += ["", "## Reviewer sensitivity for policy_plus_approval (common scenarios)", "",
          "| condition | unauthorized exec | authorized not executed |", "|---|---|---|"]
    for c in ("primary", "rubber_stamp", "always_reject"):
        u = get("policy_plus_approval", "unauthorized_execution_rate", c)
        ps = get("policy_plus_approval", "per_call_success_rate", c)
        nx = {"k": ps["n"] - ps["k"], "n": ps["n"], "rate": 1 - ps["rate"], "ci_lo": 1 - ps["ci_hi"], "ci_hi": 1 - ps["ci_lo"]} if ps else None
        L.append(f"| {c} | {_fmt(u)} | {_fmt(nx)} |")
    L += ["", "## Paired comparisons on shared unauthorized proposals (exact McNemar on discordant pairs)", "",
          "| A | B | pairs | A executed | B executed | A only | B only | p |", "|---|---|---|---|---|---|---|---|"]
    for p in paired_rows:
        L.append(f"| {p['a']} | {p['b']} | {p['n_pairs']} | {p['a_exec']} | {p['b_exec']} | {p['a_only']} | {p['b_only']} | {float(p['mcnemar_p']):.2g} |")
    det = output / "deterministic"
    L += ["", "## Audit replay", "", "```json", (det / "replay_audit.json").read_text(), "```", "",
          "## Seed stability (differing action outcomes vs primary seed)", ""]
    L += [f"- seed {r['seed']}: {r['differing_outcomes']} of {r['compared_actions']} differ" for r in read_csv(det / "seed_stability.csv")]
    L += ["", "Figures: `figures/`. Raw data: `deterministic/*.csv`, `performance/*.csv`, `approval-simulation/sweep.csv`."]
    return "\n".join(L) + "\n"
